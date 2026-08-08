import "server-only";

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

const SHA256_HEX = /^[a-f0-9]{64}$/;
const MIN_SECRET_BYTES = 32;

type JsonPrimitive = null | boolean | number | string;
export type CanonicalJsonValue =
  | JsonPrimitive
  | CanonicalJsonValue[]
  | { [key: string]: CanonicalJsonValue };

function canonicalValue(value: unknown, ancestors: Set<object>): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Canonical JSON numbers must be finite.");
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new Error("Canonical JSON integers must be safe integers.");
    }
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    throw new Error("Canonical evidence must contain only JSON values.");
  }
  if (ancestors.has(value)) throw new Error("Canonical JSON cannot contain cyclic values.");

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => canonicalValue(entry, ancestors)).join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("Canonical evidence must contain only plain JSON objects.");
    }
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalValue(record[key], ancestors)}`)
      .join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalizeJson(value: unknown): string {
  return canonicalValue(value, new Set());
}

export function hashCanonicalEvidence(canonicalPayload: string): string {
  return createHash("sha256").update(canonicalPayload, "utf8").digest("hex");
}

function requireSigningInputs(secret: string, keyVersion: number): void {
  if (Buffer.byteLength(secret, "utf8") < MIN_SECRET_BYTES) {
    throw new Error("Consent signature secret must be at least 32 bytes.");
  }
  if (!Number.isSafeInteger(keyVersion) || keyVersion < 1) {
    throw new Error("Consent signature key version must be a positive integer.");
  }
}

export function signCanonicalEvidence(
  canonicalPayload: string,
  secret: string,
  keyVersion: number,
): string {
  requireSigningInputs(secret, keyVersion);
  return createHmac("sha256", secret)
    .update(`opt-in-vault-consent-v1\n${keyVersion}\n`, "utf8")
    .update(canonicalPayload, "utf8")
    .digest("hex");
}

export function verifyCanonicalEvidence(
  canonicalPayload: string,
  expectedHash: string,
  expectedSignature: string,
  secret: string,
  keyVersion: number,
): boolean {
  try {
    if (!SHA256_HEX.test(expectedHash) || !SHA256_HEX.test(expectedSignature)) {
      return false;
    }
    const actualHash = Buffer.from(hashCanonicalEvidence(canonicalPayload), "hex");
    const storedHash = Buffer.from(expectedHash, "hex");
    const actualSignature = Buffer.from(
      signCanonicalEvidence(canonicalPayload, secret, keyVersion),
      "hex",
    );
    const storedSignature = Buffer.from(expectedSignature, "hex");
    return (
      timingSafeEqual(actualHash, storedHash) &&
      timingSafeEqual(actualSignature, storedSignature)
    );
  } catch {
    return false;
  }
}
