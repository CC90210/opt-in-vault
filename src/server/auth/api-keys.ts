import "server-only";

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const API_KEY_MARKER = "oiv_sk_";
const API_KEY_SECRET_BYTES = 32;
const API_KEY_PREFIX_LENGTH = 18;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
export const MAX_API_KEY_HASH_VERSIONS = 8;

export type ApiKeyPepperRing =
  | ReadonlyMap<number, string>
  | Readonly<Record<number, string>>;

export type ApiKeyRecord = {
  id: string;
  tenantId: string;
  prefix: string;
  hash: string;
  hashKeyVersion: number;
  scopes: readonly string[];
  expiresAt: number | null;
  revokedAt: number | null;
};

export type ApiKeyPrincipal = {
  apiKeyId: string;
  tenantId: string;
  scopes: string[];
};

function requireStrongPepper(pepper: string): void {
  if (Buffer.byteLength(pepper, "utf8") < 32) {
    throw new Error("API key pepper must be at least 32 bytes.");
  }
}

function isApiKey(value: string): boolean {
  return /^oiv_sk_[A-Za-z0-9_-]{43}$/.test(value);
}

export function extractApiKeyLookupPrefix(rawKey: string): string | null {
  return isApiKey(rawKey) ? rawKey.slice(0, API_KEY_PREFIX_LENGTH) : null;
}

function isKeyVersion(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && value <= 2_147_483_647;
}

function selectPepper(peppers: ApiKeyPepperRing, version: number): string | null {
  if (!isKeyVersion(version)) {
    return null;
  }

  if (peppers instanceof Map) {
    if (peppers.size === 0 || peppers.size > MAX_API_KEY_HASH_VERSIONS) {
      return null;
    }
    for (const keyVersion of peppers.keys()) {
      if (!isKeyVersion(keyVersion)) {
        return null;
      }
    }
    return peppers.get(version) ?? null;
  }

  const pepperRecord = peppers as Readonly<Record<number, string>>;
  const versions = Object.keys(pepperRecord);
  if (versions.length === 0 || versions.length > MAX_API_KEY_HASH_VERSIONS) {
    return null;
  }
  if (versions.some((candidate) => !isKeyVersion(Number(candidate)))) {
    return null;
  }
  return Object.hasOwn(pepperRecord, version) ? pepperRecord[version] : null;
}

export function hashApiKey(rawKey: string, pepper: string): string {
  requireStrongPepper(pepper);
  if (!isApiKey(rawKey)) {
    throw new Error("Invalid API key format.");
  }

  return createHmac("sha256", pepper).update(rawKey, "utf8").digest("hex");
}

export function createApiKey(pepper: string, hashKeyVersion: number): {
  rawKey: string;
  prefix: string;
  hash: string;
  hashKeyVersion: number;
} {
  requireStrongPepper(pepper);
  if (!isKeyVersion(hashKeyVersion)) {
    throw new Error("API key hash version must be a positive integer.");
  }
  const rawKey = `${API_KEY_MARKER}${randomBytes(API_KEY_SECRET_BYTES).toString("base64url")}`;

  return {
    rawKey,
    prefix: rawKey.slice(0, API_KEY_PREFIX_LENGTH),
    hash: hashApiKey(rawKey, pepper),
    hashKeyVersion,
  };
}

export function verifyApiKey(
  rawKey: string,
  expectedHash: string,
  pepper: string,
): boolean {
  try {
    if (!SHA256_HEX_PATTERN.test(expectedHash)) {
      return false;
    }

    const actual = Buffer.from(hashApiKey(rawKey, pepper), "hex");
    const expected = Buffer.from(expectedHash, "hex");
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

export function authenticateApiKey(
  rawKey: string,
  record: ApiKeyRecord | null | undefined,
  peppers: ApiKeyPepperRing,
  options: { now?: number; requiredScope?: string } = {},
): ApiKeyPrincipal | null {
  if (!record || record.revokedAt !== null) {
    return null;
  }

  const now = options.now ?? Date.now();
  if (!Number.isSafeInteger(now) || now < 0) {
    return null;
  }
  if (
    record.expiresAt !== null &&
    (!Number.isSafeInteger(record.expiresAt) || record.expiresAt < 0 || now >= record.expiresAt)
  ) {
    return null;
  }

  const prefix = extractApiKeyLookupPrefix(rawKey);
  if (!prefix || prefix !== record.prefix) {
    return null;
  }

  if (options.requiredScope && !record.scopes.includes(options.requiredScope)) {
    return null;
  }

  const pepper = selectPepper(peppers, record.hashKeyVersion);
  if (!pepper || !verifyApiKey(rawKey, record.hash, pepper)) {
    return null;
  }

  return {
    apiKeyId: record.id,
    tenantId: record.tenantId,
    scopes: [...record.scopes],
  };
}
