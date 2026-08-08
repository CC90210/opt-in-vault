import "server-only";

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MAX_ENVELOPE_CHARS = 200_000;
export const MAX_SECRET_PLAINTEXT_BYTES = 149_000;
export const MAX_ENCRYPTION_KEY_VERSIONS = 8;
const KEY_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export type SecretAad = {
  tenantId: string;
  resourceType: string;
  resourceId: string;
  field: string;
  provider?: string;
  host?: string;
};

export type EncryptionKeyRing =
  | ReadonlyMap<string, Buffer>
  | Readonly<Record<string, Buffer>>;

type EncryptionEnvelope = {
  v: 1;
  kid: string;
  iv: string;
  tag: string;
  ciphertext: string;
};

function invalidKey(): never {
  throw new Error("Encryption key must be valid hex or base64 resolving to exactly 32 bytes.");
}

export function parseEncryptionKey(value: string): Buffer {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim()) {
    return invalidKey();
  }

  let key: Buffer;
  if (/^[a-fA-F0-9]{64}$/.test(value)) {
    key = Buffer.from(value, "hex");
  } else {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
      return invalidKey();
    }
    key = Buffer.from(value, "base64");
    if (key.toString("base64") !== value) {
      return invalidKey();
    }
  }

  if (key.length !== KEY_BYTES) {
    return invalidKey();
  }
  return Buffer.from(key);
}

function requireKey(key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) {
    invalidKey();
  }
}

function requireAadPart(name: string, value: string | undefined, required: boolean): string {
  if (value === undefined && !required) {
    return "";
  }
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 512 ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`Invalid encryption associated-data field: ${name}.`);
  }
  return value;
}

function encodeAad(aad: SecretAad, keyVersion: string): Buffer {
  const requiresConnectionBinding = aad.resourceType === "sending_inbox";
  const canonical = [
    "opt-in-vault-secret-v1",
    keyVersion,
    requireAadPart("tenantId", aad.tenantId, true),
    requireAadPart("resourceType", aad.resourceType, true),
    requireAadPart("resourceId", aad.resourceId, true),
    requireAadPart("field", aad.field, true),
    requireAadPart("provider", aad.provider, requiresConnectionBinding),
    requireAadPart("host", aad.host, requiresConnectionBinding).toLowerCase(),
  ];
  return Buffer.from(JSON.stringify(canonical), "utf8");
}

export function encryptSecret(
  plaintext: string,
  key: Buffer,
  aad: SecretAad,
  keyVersion = "1",
): string {
  requireKey(key);
  if (typeof plaintext !== "string" || plaintext.length === 0) {
    throw new Error("Secret plaintext must not be empty.");
  }
  if (Buffer.byteLength(plaintext, "utf8") > MAX_SECRET_PLAINTEXT_BYTES) {
    throw new Error("Secret plaintext is too large.");
  }
  if (!KEY_VERSION_PATTERN.test(keyVersion)) {
    throw new Error("Invalid encryption key version.");
  }

  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(encodeAad(aad, keyVersion));
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const envelope: EncryptionEnvelope = {
    v: 1,
    kid: keyVersion,
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
  };

  const serialized = JSON.stringify(envelope);
  if (serialized.length > MAX_ENVELOPE_CHARS) {
    throw new Error("Encrypted secret envelope is too large.");
  }
  return serialized;
}

function decodeEnvelope(value: string): EncryptionEnvelope {
  if (value.length === 0 || value.length > MAX_ENVELOPE_CHARS) {
    throw new Error("Invalid envelope.");
  }
  const raw: unknown = JSON.parse(value);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("Invalid envelope.");
  }

  const envelope = raw as Partial<EncryptionEnvelope>;
  if (
    Object.keys(envelope).length !== 5 ||
    envelope.v !== 1 ||
    typeof envelope.kid !== "string" ||
    !KEY_VERSION_PATTERN.test(envelope.kid) ||
    typeof envelope.iv !== "string" ||
    typeof envelope.tag !== "string" ||
    typeof envelope.ciphertext !== "string" ||
    !BASE64URL_PATTERN.test(envelope.iv) ||
    !BASE64URL_PATTERN.test(envelope.tag) ||
    !BASE64URL_PATTERN.test(envelope.ciphertext)
  ) {
    throw new Error("Invalid envelope.");
  }

  const iv = Buffer.from(envelope.iv, "base64url");
  const tag = Buffer.from(envelope.tag, "base64url");
  const ciphertext = Buffer.from(envelope.ciphertext, "base64url");
  if (
    iv.length !== IV_BYTES ||
    tag.length !== TAG_BYTES ||
    iv.toString("base64url") !== envelope.iv ||
    tag.toString("base64url") !== envelope.tag ||
    ciphertext.toString("base64url") !== envelope.ciphertext
  ) {
    throw new Error("Invalid envelope.");
  }

  return envelope as EncryptionEnvelope;
}

export function decryptSecret(
  serializedEnvelope: string,
  key: Buffer,
  aad: SecretAad,
): { plaintext: string; keyVersion: string } {
  requireKey(key);
  try {
    const envelope = decodeEnvelope(serializedEnvelope);
    return decryptEnvelope(envelope, key, aad);
  } catch {
    throw new Error("Secret could not be decrypted.");
  }
}

function decryptEnvelope(
  envelope: EncryptionEnvelope,
  key: Buffer,
  aad: SecretAad,
): { plaintext: string; keyVersion: string } {
  requireKey(key);
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(envelope.iv, "base64url"),
    { authTagLength: TAG_BYTES },
  );
  decipher.setAAD(encodeAad(aad, envelope.kid));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");

  return { plaintext, keyVersion: envelope.kid };
}

function keyFromRing(ring: EncryptionKeyRing, version: string): Buffer | null {
  const entries: Array<readonly [string, Buffer]> =
    ring instanceof Map
      ? [...ring.entries()]
      : Object.entries(ring as Readonly<Record<string, Buffer>>);
  if (entries.length === 0 || entries.length > MAX_ENCRYPTION_KEY_VERSIONS) {
    return null;
  }
  for (const [candidateVersion, candidateKey] of entries) {
    if (!KEY_VERSION_PATTERN.test(candidateVersion)) {
      return null;
    }
    try {
      requireKey(candidateKey);
    } catch {
      return null;
    }
  }
  const selected = entries.find(([candidateVersion]) => candidateVersion === version)?.[1];
  return selected ? Buffer.from(selected) : null;
}

export function decryptSecretWithKeyRing(
  serializedEnvelope: string,
  keys: EncryptionKeyRing,
  aad: SecretAad,
): { plaintext: string; keyVersion: string } {
  try {
    const envelope = decodeEnvelope(serializedEnvelope);
    const key = keyFromRing(keys, envelope.kid);
    if (!key) {
      throw new Error("Unknown encryption key version.");
    }
    return decryptEnvelope(envelope, key, aad);
  } catch {
    throw new Error("Secret could not be decrypted.");
  }
}
