import "server-only";

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";

import { DNS_FRESHNESS_MS } from "@/server/dns/freshness";

const MAX_DNS_SNAPSHOT_BYTES = 2 * 1_024 * 1_024;
const MAX_DKIM_RECORD_BYTES = 4_096;
const MAX_DKIM_PUBLIC_KEY_BYTES = 8_192;
const MIN_RSA_MODULUS_BITS = 1_024;

export type LocalDkimDnsSnapshot = {
  domainLastDnsCheckAt: number | null;
  dnsCheckAt: number | null;
  dnsCheckStatus: string | null;
  dnsCheckDkimStatus: string | null;
  dnsCheckErrorCode: string | null;
  dnsCheckRecordsJson: string | null;
};

export class LocalDkimVerificationError extends Error {
  readonly code: string;

  constructor(code: string) {
    super("Local DKIM key verification failed");
    this.name = "LocalDkimVerificationError";
    this.code = code;
  }
}

function fail(code: string): never {
  throw new LocalDkimVerificationError(code);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readSingleDkimRecord(
  recordsJson: string,
  expected: { sendingDomain: string; dkimSelector: string },
): string {
  if (
    !recordsJson ||
    Buffer.byteLength(recordsJson, "utf8") > MAX_DNS_SNAPSHOT_BYTES
  ) {
    fail("local_dkim_dns_snapshot_invalid");
  }

  let document: unknown;
  try {
    document = JSON.parse(recordsJson);
  } catch {
    fail("local_dkim_dns_snapshot_invalid");
  }
  if (
    !isObject(document) ||
    !isObject(document.source) ||
    document.source.sendingDomain !== expected.sendingDomain ||
    document.source.dkimSelector !== expected.dkimSelector ||
    document.source.dkimMode !== "local" ||
    !isObject(document.records)
  ) {
    fail("local_dkim_dns_snapshot_invalid");
  }
  const dkim = document.records.dkim;
  if (
    !Array.isArray(dkim) ||
    dkim.length !== 1 ||
    typeof dkim[0] !== "string" ||
    !dkim[0] ||
    Buffer.byteLength(dkim[0], "utf8") > MAX_DKIM_RECORD_BYTES ||
    /[\r\n\u0000]/.test(dkim[0])
  ) {
    fail("local_dkim_dns_record_invalid");
  }
  return dkim[0];
}

function dkimTags(record: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const segment of record.split(";")) {
    const normalized = segment.trim();
    if (!normalized) continue;
    const separator = normalized.indexOf("=");
    if (separator <= 0) fail("local_dkim_dns_record_invalid");
    const name = normalized.slice(0, separator).trim().toLowerCase();
    const value = normalized.slice(separator + 1).trim();
    if (!/^[a-z][a-z0-9]*$/.test(name) || tags.has(name)) {
      fail("local_dkim_dns_record_invalid");
    }
    tags.set(name, value);
  }
  if (tags.get("v")?.toLowerCase() !== "dkim1") {
    fail("local_dkim_dns_record_invalid");
  }
  return tags;
}

function decodeCanonicalBase64(value: string): Buffer {
  if (!value || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    fail("local_dkim_dns_record_invalid");
  }
  const unpadded = value.replace(/=+$/, "");
  const padded = `${unpadded}${"=".repeat((4 - (unpadded.length % 4)) % 4)}`;
  const decoded = Buffer.from(padded, "base64");
  if (
    decoded.length === 0 ||
    decoded.length > MAX_DKIM_PUBLIC_KEY_BYTES ||
    decoded.toString("base64").replace(/=+$/, "") !== unpadded
  ) {
    fail("local_dkim_dns_record_invalid");
  }
  return decoded;
}

function requireRsaKey(key: KeyObject, code: string): KeyObject {
  if (
    key.asymmetricKeyType !== "rsa" ||
    (key.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_RSA_MODULUS_BITS
  ) {
    fail(code);
  }
  return key;
}

function normalizedDnsSpki(record: string): Buffer {
  const tags = dkimTags(record);
  if ((tags.get("k") ?? "rsa").toLowerCase() !== "rsa") {
    fail("local_dkim_public_key_unsupported");
  }
  const decoded = decodeCanonicalBase64(tags.get("p") ?? "");
  for (const type of ["spki", "pkcs1"] as const) {
    try {
      const key = requireRsaKey(
        createPublicKey({ key: decoded, format: "der", type }),
        "local_dkim_public_key_unsupported",
      );
      return key.export({ format: "der", type: "spki" }) as Buffer;
    } catch (error) {
      if (error instanceof LocalDkimVerificationError) throw error;
      // Try the other standard RSA DER wrapper.
    }
  }
  fail("local_dkim_dns_record_invalid");
}

function normalizedPrivateSpki(privateKey: string): Buffer {
  try {
    const key = requireRsaKey(
      createPrivateKey(privateKey),
      "local_dkim_private_key_unsupported",
    );
    return createPublicKey(key).export({ format: "der", type: "spki" }) as Buffer;
  } catch (error) {
    if (error instanceof LocalDkimVerificationError) throw error;
    fail("local_dkim_private_key_invalid");
  }
}

function assertFreshSnapshot(
  snapshot: LocalDkimDnsSnapshot,
  now: number,
): void {
  if (
    !Number.isSafeInteger(now) ||
    now < 0 ||
    !Number.isSafeInteger(snapshot.domainLastDnsCheckAt) ||
    !Number.isSafeInteger(snapshot.dnsCheckAt) ||
    snapshot.domainLastDnsCheckAt! < 0 ||
    snapshot.dnsCheckAt !== snapshot.domainLastDnsCheckAt ||
    snapshot.domainLastDnsCheckAt! > now
  ) {
    fail("local_dkim_dns_snapshot_invalid");
  }
  if (now - snapshot.domainLastDnsCheckAt! > DNS_FRESHNESS_MS) {
    fail("local_dkim_dns_stale");
  }
  if (
    !["healthy", "degraded"].includes(snapshot.dnsCheckStatus ?? "") ||
    snapshot.dnsCheckDkimStatus !== "present_local_key" ||
    snapshot.dnsCheckErrorCode !== null
  ) {
    fail("local_dkim_dns_unhealthy");
  }
}

export function assertLocalDkimKeyMatchesDns(input: {
  privateKey: string;
  sendingDomain: string;
  dkimSelector: string;
  snapshot: LocalDkimDnsSnapshot;
  now?: number;
}): void {
  const now = input.now ?? Date.now();
  assertFreshSnapshot(input.snapshot, now);
  const record = readSingleDkimRecord(
    input.snapshot.dnsCheckRecordsJson ?? "",
    {
      sendingDomain: input.sendingDomain,
      dkimSelector: input.dkimSelector,
    },
  );
  const dnsFingerprint = createHash("sha256")
    .update(normalizedDnsSpki(record))
    .digest();
  const privateFingerprint = createHash("sha256")
    .update(normalizedPrivateSpki(input.privateKey))
    .digest();
  if (!timingSafeEqual(dnsFingerprint, privateFingerprint)) {
    fail("local_dkim_key_mismatch");
  }
}
