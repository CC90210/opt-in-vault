import "server-only";

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const TOKEN_VERSION = "oiv2";
const HASH_VERSION = "oivh1";
const SECRET_MIN_BYTES = 32;
const RANDOM_BYTES = 32;
const TOKEN_PART_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const BINDING_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$/;
const KEY_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const MAX_TOKEN_CHARS = 1_024;

export const MAX_OPAQUE_TOKEN_KEY_VERSIONS = 8;

export type OpaqueTokenSecretRing =
  | ReadonlyMap<string, string>
  | Readonly<Record<string, string>>;

type TokenBinding = {
  purpose: string;
  tenantId: string;
  resourceId: string;
};

type CreateTokenOptions = TokenBinding & {
  signingSecret: string;
  signingKeyVersion: string;
  expiresAt: number;
  now?: number;
};

type VerifyTokenOptions = TokenBinding & {
  signingSecrets: OpaqueTokenSecretRing;
  now?: number;
};

function requireStrongSecret(name: string, value: string): void {
  if (Buffer.byteLength(value, "utf8") < SECRET_MIN_BYTES) {
    throw new Error(`${name} must be at least 32 bytes.`);
  }
}

function requireKeyVersion(value: string): void {
  if (!KEY_VERSION_PATTERN.test(value)) {
    throw new Error("Invalid opaque token key version.");
  }
}

function requireBinding(binding: TokenBinding): void {
  if (
    !BINDING_PATTERN.test(binding.purpose) ||
    !BINDING_PATTERN.test(binding.tenantId) ||
    !BINDING_PATTERN.test(binding.resourceId)
  ) {
    throw new Error("Invalid opaque token binding.");
  }
}

function requireNow(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("Opaque token time must be a non-negative safe integer.");
  }
  return value;
}

function secretEntries(ring: OpaqueTokenSecretRing): Array<readonly [string, string]> {
  const entries: Array<readonly [string, string]> =
    ring instanceof Map
      ? [...ring.entries()]
      : Object.entries(ring as Readonly<Record<string, string>>);
  if (entries.length === 0 || entries.length > MAX_OPAQUE_TOKEN_KEY_VERSIONS) {
    throw new Error("Opaque token secret ring has an invalid size.");
  }
  for (const [version, secret] of entries) {
    requireKeyVersion(version);
    requireStrongSecret("Opaque token secret", secret);
  }
  return entries;
}

function secretFromRing(ring: OpaqueTokenSecretRing, version: string): string | null {
  return secretEntries(ring).find(([candidate]) => candidate === version)?.[1] ?? null;
}

function tokenSignature(
  keyVersion: string,
  expiration: string,
  nonce: string,
  binding: TokenBinding,
  signingSecret: string,
): Buffer {
  const signedData = JSON.stringify([
    TOKEN_VERSION,
    keyVersion,
    expiration,
    nonce,
    binding.purpose,
    binding.tenantId,
    binding.resourceId,
  ]);
  return createHmac("sha256", signingSecret).update(signedData, "utf8").digest();
}

export function createOpaqueToken(options: CreateTokenOptions): string {
  requireStrongSecret("Token signing secret", options.signingSecret);
  requireKeyVersion(options.signingKeyVersion);
  requireBinding(options);
  const now = requireNow(options.now ?? Date.now());
  if (!Number.isSafeInteger(options.expiresAt) || options.expiresAt <= now) {
    throw new Error("Opaque token expiry must be in the future.");
  }

  const expiration = options.expiresAt.toString(36);
  const nonce = randomBytes(RANDOM_BYTES).toString("base64url");
  const signature = tokenSignature(
    options.signingKeyVersion,
    expiration,
    nonce,
    options,
    options.signingSecret,
  ).toString("base64url");
  return `${TOKEN_VERSION}.${options.signingKeyVersion}.${expiration}.${nonce}.${signature}`;
}

export function verifyOpaqueToken(token: string, options: VerifyTokenOptions): boolean {
  try {
    requireBinding(options);
    const now = requireNow(options.now ?? Date.now());
    if (token.length === 0 || token.length > MAX_TOKEN_CHARS) {
      return false;
    }
    const parts = token.split(".");
    if (
      parts.length !== 5 ||
      parts[0] !== TOKEN_VERSION ||
      !KEY_VERSION_PATTERN.test(parts[1]) ||
      !/^[0-9a-z]+$/.test(parts[2]) ||
      !TOKEN_PART_PATTERN.test(parts[3]) ||
      !TOKEN_PART_PATTERN.test(parts[4])
    ) {
      return false;
    }

    const expiresAt = Number.parseInt(parts[2], 36);
    if (
      !Number.isSafeInteger(expiresAt) ||
      expiresAt.toString(36) !== parts[2] ||
      now >= expiresAt
    ) {
      return false;
    }

    const signingSecret = secretFromRing(options.signingSecrets, parts[1]);
    if (!signingSecret) {
      return false;
    }
    const actual = Buffer.from(parts[4], "base64url");
    const expected = tokenSignature(parts[1], parts[2], parts[3], options, signingSecret);
    return (
      actual.length === expected.length &&
      actual.toString("base64url") === parts[4] &&
      timingSafeEqual(actual, expected)
    );
  } catch {
    return false;
  }
}

function validateTokenForHashing(token: string): void {
  if (typeof token !== "string" || token.length === 0 || token.length > MAX_TOKEN_CHARS) {
    throw new Error("Invalid opaque token.");
  }
}

function tokenHashDigest(token: string, pepper: string): string {
  return createHmac("sha256", pepper)
    .update(`opt-in-vault-token-hash-v1\u0000${token}`, "utf8")
    .digest("hex");
}

export function hashOpaqueToken(
  token: string,
  pepper: string,
  hashKeyVersion: string,
): string {
  requireStrongSecret("Token hash pepper", pepper);
  requireKeyVersion(hashKeyVersion);
  validateTokenForHashing(token);
  return `${HASH_VERSION}.${hashKeyVersion}.${tokenHashDigest(token, pepper)}`;
}

export function hashOpaqueTokenCandidates(
  token: string,
  peppers: OpaqueTokenSecretRing,
): string[] {
  validateTokenForHashing(token);
  return secretEntries(peppers).map(([version, pepper]) =>
    hashOpaqueToken(token, pepper, version),
  );
}

export function verifyOpaqueTokenHash(
  token: string,
  persistedHash: string,
  peppers: OpaqueTokenSecretRing,
): boolean {
  try {
    validateTokenForHashing(token);
    const parts = persistedHash.split(".");
    if (
      parts.length !== 3 ||
      parts[0] !== HASH_VERSION ||
      !KEY_VERSION_PATTERN.test(parts[1]) ||
      !HASH_PATTERN.test(parts[2])
    ) {
      return false;
    }
    const pepper = secretFromRing(peppers, parts[1]);
    if (!pepper) {
      return false;
    }
    const actual = Buffer.from(parts[2], "hex");
    const expected = Buffer.from(tokenHashDigest(token, pepper), "hex");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}
