import "server-only";

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import type { Client } from "@libsql/client";

const CODE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const SHARE_TOKEN_PATTERN = /^oiv_share_[A-Za-z0-9_-]{43}$/;
const HEX_SHA256_PATTERN = /^[a-f0-9]{64}$/;

const RESPONSE_HEADERS = {
  "cache-control": "no-store, max-age=0",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "x-robots-tag": "noindex, nofollow, noarchive",
};

export function hashCertificateShareToken(rawToken: string, pepper: string): string {
  if (!SHARE_TOKEN_PATTERN.test(rawToken)) {
    throw new Error("Invalid certificate share token.");
  }
  if (Buffer.byteLength(pepper, "utf8") < 32) {
    throw new Error("Certificate share-token pepper must be at least 32 bytes.");
  }
  return createHmac("sha256", pepper).update(rawToken, "utf8").digest("hex");
}

export function createCertificateShareToken(pepper: string): {
  rawToken: string;
  tokenHash: string;
} {
  const rawToken = `oiv_share_${randomBytes(32).toString("base64url")}`;
  return { rawToken, tokenHash: hashCertificateShareToken(rawToken, pepper) };
}

export type CertificateRecord = {
  code: string;
  tenantId: string;
  consentId: string;
  shareTokenHash: string | null;
  shareExpiresAt: number | null;
  revokedAt: number | null;
  retentionExpiresAt: number;
};

export function resolveVersionedConsentValue(options: {
  targetVersion: number;
  currentVersion: number;
  currentValue: string;
  serializedRing?: string;
  name: string;
}): string {
  const validVersion = (value: number) => Number.isSafeInteger(value) && value >= 1;
  if (!validVersion(options.targetVersion) || !validVersion(options.currentVersion)) {
    throw new Error(`${options.name} contains an invalid key version.`);
  }
  if (options.targetVersion === options.currentVersion) return options.currentValue;
  try {
    const parsed: unknown = JSON.parse(options.serializedRing ?? "");
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    const entries = Object.entries(parsed);
    if (entries.length === 0 || entries.length > 8) throw new Error();
    for (const [version, value] of entries) {
      if (
        !/^[1-9][0-9]*$/.test(version) ||
        !validVersion(Number(version)) ||
        typeof value !== "string" ||
        value.length === 0 ||
        value.length > 16_384
      ) {
        throw new Error();
      }
    }
    const selected = (parsed as Record<string, string>)[String(options.targetVersion)];
    if (selected) return selected;
  } catch {
    // The generic unavailable error below avoids exposing key-ring contents.
  }
  throw new Error(`${options.name} version ${options.targetVersion} is unavailable.`);
}

type TenantPrincipal = { tenantId: string };

type RouteContext = {
  params: Promise<{ code: string }>;
};

type CertificateDependencies = {
  findCertificate(code: string): Promise<CertificateRecord | null>;
  authorizeTenant(request: Request): Promise<TenantPrincipal | null>;
  hashShareToken(rawToken: string): string;
  render(record: CertificateRecord): Promise<Buffer>;
  markDownloaded(record: CertificateRecord): Promise<void>;
  now?: () => number;
};

function hiddenResponse(): Response {
  return Response.json(
    { error: "not_found" },
    { status: 404, headers: RESPONSE_HEADERS },
  );
}

function shareTokenMatches(
  record: CertificateRecord,
  rawToken: string | null,
  dependencies: CertificateDependencies,
  now: number,
): boolean {
  if (
    !rawToken ||
    !SHARE_TOKEN_PATTERN.test(rawToken) ||
    !record.shareTokenHash ||
    !HEX_SHA256_PATTERN.test(record.shareTokenHash) ||
    record.shareExpiresAt === null ||
    now >= record.shareExpiresAt ||
    record.revokedAt !== null
  ) {
    return false;
  }
  try {
    const actualHash = dependencies.hashShareToken(rawToken);
    if (!HEX_SHA256_PATTERN.test(actualHash)) return false;
    return timingSafeEqual(
      Buffer.from(actualHash, "hex"),
      Buffer.from(record.shareTokenHash, "hex"),
    );
  } catch {
    return false;
  }
}

export function createCertificateHandlers(dependencies: CertificateDependencies) {
  const now = dependencies.now ?? Date.now;
  return {
    async GET(request: Request, context: RouteContext): Promise<Response> {
      const { code } = await context.params;
      if (!CODE_PATTERN.test(code)) return hiddenResponse();

      try {
        const [record, principal] = await Promise.all([
          dependencies.findCertificate(code),
          dependencies.authorizeTenant(request),
        ]);
        if (!record) return hiddenResponse();
        const tenantAuthorized = principal?.tenantId === record.tenantId;
        if (
          !Number.isSafeInteger(record.retentionExpiresAt) ||
          now() >= record.retentionExpiresAt
        ) {
          return hiddenResponse();
        }
        const authorization = request.headers.get("authorization") ?? "";
        const shareMatch = /^Share (oiv_share_[A-Za-z0-9_-]{43})$/.exec(authorization);
        const shared = shareTokenMatches(
          record,
          shareMatch?.[1] ?? null,
          dependencies,
          now(),
        );
        if (!tenantAuthorized && !shared) return hiddenResponse();

        const pdf = await dependencies.render(record);
        if (!Buffer.isBuffer(pdf) || pdf.subarray(0, 5).toString("ascii") !== "%PDF-") {
          throw new Error("Certificate renderer did not return a PDF.");
        }
        await dependencies.markDownloaded(record);
        return new Response(new Uint8Array(pdf), {
          status: 200,
          headers: {
            ...RESPONSE_HEADERS,
            "content-type": "application/pdf",
            "content-disposition": `attachment; filename="${code}.pdf"`,
          },
        });
      } catch {
        return Response.json(
          { error: "certificate_unavailable" },
          { status: 503, headers: RESPONSE_HEADERS },
        );
      }
    },
  };
}

type StoredCertificateRecord = CertificateRecord & {
  captureSiteId: string;
  canonicalPayloadCiphertext: Buffer;
  payloadKeyVersion: number;
  payloadSha256: string;
  signatureHmac: string;
  signatureKeyVersion: number;
};

function bufferFromDatabase(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  throw new Error("Certificate evidence ciphertext is invalid.");
}

async function findStoredCertificate(
  client: Client,
  code: string,
): Promise<StoredCertificateRecord | null> {
  const result = await client.execute({
    sql: `SELECT certificate.id, certificate.tenant_id,
                 certificate.consent_log_id, certificate.share_token_hash,
                 certificate.share_expires_at, certificate.revoked_at,
                 log.capture_site_id, log.canonical_payload_ciphertext,
                 log.payload_key_version, log.payload_sha256,
                 log.signature_hmac, log.signature_key_version,
                 log.retention_expires_at
          FROM consent_certificates AS certificate
          JOIN consent_logs AS log
            ON log.tenant_id = certificate.tenant_id
           AND log.id = certificate.consent_log_id
          WHERE certificate.id = ?
          LIMIT 1`,
    args: [code],
  });
  const row = result.rows[0];
  if (!row) return null;
  if (!row.capture_site_id) throw new Error("Certificate has no capture-site binding.");
  return {
    code: String(row.id),
    tenantId: String(row.tenant_id),
    consentId: String(row.consent_log_id),
    shareTokenHash:
      row.share_token_hash == null ? null : String(row.share_token_hash),
    shareExpiresAt:
      row.share_expires_at == null ? null : Number(row.share_expires_at),
    revokedAt: row.revoked_at == null ? null : Number(row.revoked_at),
    retentionExpiresAt: Number(row.retention_expires_at),
    captureSiteId: String(row.capture_site_id),
    canonicalPayloadCiphertext: bufferFromDatabase(row.canonical_payload_ciphertext),
    payloadKeyVersion: Number(row.payload_key_version),
    payloadSha256: String(row.payload_sha256),
    signatureHmac: String(row.signature_hmac),
    signatureKeyVersion: Number(row.signature_key_version),
  };
}

function cookieValue(request: Request, name: string): string | null {
  const cookie = request.headers.get("cookie") ?? "";
  for (const part of cookie.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return null;
    }
  }
  return null;
}

async function authorizeProductionTenant(
  client: Client,
  request: Request,
): Promise<TenantPrincipal | null> {
  const sessionModule = await import("@/server/auth/session");
  const sessionToken = cookieValue(request, sessionModule.SESSION_COOKIE_NAME);
  const sessionSecret = process.env.SESSION_SECRET;
  if (sessionToken && sessionSecret) {
    const claims = sessionModule.verifySessionToken(sessionToken, sessionSecret);
    if (
      claims &&
      claims.scopes.some((scope) =>
        ["admin", "consent:read", "certificate:read"].includes(scope),
      )
    ) {
      return { tenantId: claims.tenantId };
    }
  }

  const authorization = request.headers.get("authorization") ?? "";
  const match = /^Bearer (oiv_sk_[A-Za-z0-9_-]{43})$/.exec(authorization);
  const pepper = process.env.API_KEY_PEPPER;
  if (!match || !pepper) return null;
  const rawKey = match[1];
  const result = await client.execute({
    sql: `SELECT id, tenant_id, prefix, key_hash, hash_key_version, scopes_json,
                 expires_at, revoked_at
          FROM tenant_api_keys
          WHERE prefix = ?
          LIMIT 1`,
    args: [rawKey.slice(0, 18)],
  });
  const row = result.rows[0];
  if (!row) return null;
  let scopes: string[];
  try {
    const parsed: unknown = JSON.parse(String(row.scopes_json));
    if (!Array.isArray(parsed) || !parsed.every((scope) => typeof scope === "string")) {
      return null;
    }
    scopes = parsed;
  } catch {
    return null;
  }
  const apiKeys = await import("@/server/auth/api-keys");
  const hashKeyVersion = Number(row.hash_key_version);
  const principal = apiKeys.authenticateApiKey(
    rawKey,
    {
      id: String(row.id),
      tenantId: String(row.tenant_id),
      prefix: String(row.prefix),
      hash: String(row.key_hash),
      hashKeyVersion,
      scopes,
      expiresAt: row.expires_at == null ? null : Number(row.expires_at),
      revokedAt: row.revoked_at == null ? null : Number(row.revoked_at),
    },
    { [hashKeyVersion]: pepper },
  );
  return principal &&
    principal.scopes.some((scope) =>
      ["admin", "consent:read", "certificate:read"].includes(scope),
    )
    ? { tenantId: principal.tenantId }
    : null;
}

function requiredPositiveVersion(name: string): number {
  const raw = process.env[name];
  if (!raw || !/^[1-9][0-9]*$/.test(raw)) throw new Error(`${name} is required.`);
  const version = Number(raw);
  if (!Number.isSafeInteger(version)) throw new Error(`${name} is invalid.`);
  return version;
}

async function productionDependencies(): Promise<CertificateDependencies> {
  const [{ getDatabase }, encryption, canonical, renderer] = await Promise.all([
    import("@/db/client"),
    import("@/server/security/encryption"),
    import("@/server/consent/canonicalize"),
    import("@/server/certificates/render"),
  ]);
  const database = await getDatabase();

  return {
    findCertificate: (code) => findStoredCertificate(database.client, code),
    authorizeTenant: (request) => authorizeProductionTenant(database.client, request),
    hashShareToken(rawToken) {
      const pepper = process.env.CERTIFICATE_SHARE_TOKEN_PEPPER;
      if (!pepper) {
        throw new Error("CERTIFICATE_SHARE_TOKEN_PEPPER is required.");
      }
      return hashCertificateShareToken(rawToken, pepper);
    },
    async render(record) {
      const stored = record as StoredCertificateRecord;
      const encryptionValue = process.env.CONSENT_ENCRYPTION_KEY;
      const signatureKey = process.env.CONSENT_SIGNATURE_KEY;
      if (!encryptionValue || !signatureKey) {
        throw new Error("Consent evidence keys are required.");
      }
      const payloadVersion = requiredPositiveVersion("CONSENT_PAYLOAD_KEY_VERSION");
      const signatureVersion = requiredPositiveVersion("CONSENT_SIGNATURE_KEY_VERSION");
      const selectedEncryptionValue = resolveVersionedConsentValue({
        targetVersion: stored.payloadKeyVersion,
        currentVersion: payloadVersion,
        currentValue: encryptionValue,
        serializedRing: process.env.CONSENT_ENCRYPTION_KEYS_JSON,
        name: "Consent encryption key",
      });
      const selectedSignatureKey = resolveVersionedConsentValue({
        targetVersion: stored.signatureKeyVersion,
        currentVersion: signatureVersion,
        currentValue: signatureKey,
        serializedRing: process.env.CONSENT_SIGNATURE_KEYS_JSON,
        name: "Consent signature key",
      });
      const decrypted = encryption.decryptSecret(
        stored.canonicalPayloadCiphertext.toString("utf8"),
        encryption.parseEncryptionKey(selectedEncryptionValue),
        {
          tenantId: stored.tenantId,
          resourceType: "consent_log",
          resourceId: stored.consentId,
          field: "canonical_payload",
          provider: stored.captureSiteId,
        },
      );
      if (decrypted.keyVersion !== String(stored.payloadKeyVersion)) {
        throw new Error("Consent evidence key version does not match its envelope.");
      }
      const evidence: unknown = JSON.parse(decrypted.plaintext);
      if (canonical.canonicalizeJson(evidence) !== decrypted.plaintext) {
        throw new Error("Consent evidence is not canonical JSON.");
      }
      const verified = canonical.verifyCanonicalEvidence(
        decrypted.plaintext,
        stored.payloadSha256,
        stored.signatureHmac,
        selectedSignatureKey,
        stored.signatureKeyVersion,
      );
      if (!verified || !evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
        throw new Error("Consent evidence verification failed.");
      }
      return renderer.renderEvidenceCertificate({
        certificateCode: stored.code,
        consentId: stored.consentId,
        payloadSha256: stored.payloadSha256,
        signatureHmac: stored.signatureHmac,
        signatureKeyVersion: stored.signatureKeyVersion,
        verified: true,
        evidence: evidence as Record<string, never>,
      });
    },
    async markDownloaded(record) {
      await database.client.execute({
        sql: `UPDATE consent_certificates
              SET download_count = download_count + 1, last_downloaded_at = ?
              WHERE id = ? AND tenant_id = ?`,
        args: [Date.now(), record.code, record.tenantId],
      });
    },
  };
}

export async function GET(request: Request, context: RouteContext): Promise<Response> {
  return createCertificateHandlers(await productionDependencies()).GET(request, context);
}
