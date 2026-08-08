import "server-only";

import { createHmac, randomUUID } from "node:crypto";
import { isIP } from "node:net";

import type { Client } from "@libsql/client";
import { z } from "zod";

import { decryptSecret, encryptSecret } from "@/server/security/encryption";
import { emailSchema, webUrlSchema } from "@/server/validation/primitives";

import {
  canonicalizeJson,
  hashCanonicalEvidence,
  signCanonicalEvidence,
  verifyCanonicalEvidence,
} from "./canonicalize";

const SITE_KEY_PATTERN = /^oiv_pk_[A-Za-z0-9_-]{43}$/;
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const ACTION_PATTERN = /^[a-z][a-z0-9_-]{1,63}$/;
const SOURCE_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;
const SECRET_MIN_BYTES = 32;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1_000;

const captureInputSchema = z
  .object({
    disclosure_version: z.string().min(1).max(128),
    affirmative_action: z.string().regex(ACTION_PATTERN),
    form_url: webUrlSchema,
    occurred_at: z.string().max(64).optional(),
    email: emailSchema.optional(),
    phone: z.string().trim().min(7).max(32).optional(),
  })
  .strict()
  .refine((value) => value.email !== undefined || value.phone !== undefined, {
    message: "At least one contact identifier is required.",
  });

export type ConsentCaptureInput = z.infer<typeof captureInputSchema>;

export type TrustedEdgeEvidence = {
  ip: string;
  source: string;
};

export type ConsentCaptureContext = {
  siteKey: string;
  origin: string;
  idempotencyKey: string;
  userAgent?: string;
  trustedEdge?: TrustedEdgeEvidence;
};

export type ConsentCaptureErrorCode =
  | "invalid_request"
  | "site_not_found"
  | "site_inactive"
  | "site_configuration_invalid"
  | "origin_not_allowed"
  | "form_url_mismatch"
  | "disclosure_mismatch"
  | "idempotency_conflict"
  | "evidence_verification_failed";

export class ConsentCaptureError extends Error {
  readonly code: ConsentCaptureErrorCode;

  constructor(code: ConsentCaptureErrorCode) {
    super(code);
    this.name = "ConsentCaptureError";
    this.code = code;
  }
}

export type CaptureSiteRecord = {
  id: string;
  tenantId: string;
  allowedOriginsJson: string;
  formUrlPattern: string | null;
  disclosureVersion: string;
  disclosureText: string;
  controller: string;
  purpose: string;
  channelsJson: string;
  status: string;
};

type StoredConsentEvidence = {
  consentId: string;
  certificateCode: string;
  tenantId: string;
  captureSiteId: string;
  canonicalPayloadCiphertext: Buffer;
  payloadKeyVersion: number;
  payloadSha256: string;
  signatureHmac: string;
  signatureKeyVersion: number;
  receivedAt: number;
  retentionExpiresAt: number;
};

type NewConsentEvidence = StoredConsentEvidence & {
  subjectIdentifierHash: string;
  controller: string;
  purpose: string;
  disclosureVersion: string;
  affirmativeAction: string;
  idempotencyKey: string;
  occurredAt: number;
};

export type ConsentRepository = {
  findCaptureSite(prefix: string, keyHash: string): Promise<CaptureSiteRecord | null>;
  persistOrGet(evidence: NewConsentEvidence): Promise<{
    evidence: StoredConsentEvidence;
    created: boolean;
  }>;
};

export type ConsentCaptureResult = {
  created: boolean;
  consentId: string;
  certificateCode: string;
  tenantId: string;
  captureSiteId: string;
  payloadSha256: string;
  signatureHmac: string;
  signatureKeyVersion: number;
  receivedAt: number;
  retentionExpiresAt: number;
};

type ConsentServiceOptions = {
  siteKeyPepper: string;
  subjectHashKey: string;
  signatureKey: string;
  signatureKeyVersion: number;
  payloadEncryptionKey: Buffer;
  payloadKeyVersion: number;
  retentionMs: number;
  signatureVerificationKeys?: Readonly<Record<number, string>>;
  payloadDecryptionKeys?: Readonly<Record<number, Buffer>>;
  now?: () => number;
  createId?: (kind: "consent" | "certificate") => string;
};

function requireStrongSecret(name: string, value: string): void {
  if (Buffer.byteLength(value, "utf8") < SECRET_MIN_BYTES) {
    throw new Error(`${name} must be at least 32 bytes.`);
  }
}

export function hashCaptureSiteKey(rawKey: string, pepper: string): string {
  requireStrongSecret("Capture-site key pepper", pepper);
  if (!SITE_KEY_PATTERN.test(rawKey)) throw new Error("Invalid capture-site key.");
  return createHmac("sha256", pepper).update(rawKey, "utf8").digest("hex");
}

function subjectHash(
  tenantId: string,
  subject: { email?: string; phone?: string },
  key: string,
): string {
  return createHmac("sha256", key)
    .update(canonicalizeJson({ tenant_id: tenantId, ...subject }), "utf8")
    .digest("hex");
}

function normalizePhone(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  if (!trimmed.startsWith("+")) throw new ConsentCaptureError("invalid_request");
  const normalized = `+${trimmed.slice(1).replace(/[\s().-]/g, "")}`;
  if (!/^\+[1-9][0-9]{6,14}$/.test(normalized)) {
    throw new ConsentCaptureError("invalid_request");
  }
  return normalized;
}

function exactAllowedOrigins(value: string): string[] {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > 100) throw new Error();
    const origins = parsed.map((entry) => {
      if (typeof entry !== "string" || entry.length > 512) throw new Error();
      const url = new URL(entry);
      if (url.origin !== entry || !["http:", "https:"].includes(url.protocol)) throw new Error();
      return entry;
    });
    if (new Set(origins).size !== origins.length) throw new Error();
    return origins;
  } catch {
    throw new ConsentCaptureError("site_configuration_invalid");
  }
}

function configuredChannels(value: string): string[] {
  try {
    const parsed: unknown = JSON.parse(value);
    if (
      !Array.isArray(parsed) ||
      parsed.length === 0 ||
      parsed.length > 10 ||
      !parsed.every((entry) => typeof entry === "string" && /^(email|sms)$/.test(entry))
    ) {
      throw new Error();
    }
    return [...parsed].sort();
  } catch {
    throw new ConsentCaptureError("site_configuration_invalid");
  }
}

function formUrlMatches(actual: string, pattern: string | null): boolean {
  if (!pattern || pattern.length > 2_048) return false;
  const wildcardCount = [...pattern].filter((character) => character === "*").length;
  if (wildcardCount === 0) return actual === pattern;
  if (wildcardCount !== 1 || !pattern.endsWith("*")) return false;
  const prefix = pattern.slice(0, -1);
  try {
    const actualUrl = new URL(actual);
    const prefixUrl = new URL(prefix);
    if (actualUrl.origin !== prefixUrl.origin || !actual.startsWith(prefix)) return false;
    return prefix.endsWith("/") || actualUrl.pathname === prefixUrl.pathname;
  } catch {
    return false;
  }
}

function requestTimestamp(value: string | undefined, now: number): number {
  if (value === undefined) return now;
  const parsed = Date.parse(value);
  if (!Number.isSafeInteger(parsed) || new Date(parsed).toISOString() !== value) {
    throw new ConsentCaptureError("invalid_request");
  }
  if (parsed > now + MAX_CLOCK_SKEW_MS) throw new ConsentCaptureError("invalid_request");
  return parsed;
}

function validateOptions(options: ConsentServiceOptions): void {
  requireStrongSecret("Capture-site key pepper", options.siteKeyPepper);
  requireStrongSecret("Subject hash key", options.subjectHashKey);
  requireStrongSecret("Consent signature key", options.signatureKey);
  if (!Buffer.isBuffer(options.payloadEncryptionKey) || options.payloadEncryptionKey.length !== 32) {
    throw new Error("Consent payload encryption key must be exactly 32 bytes.");
  }
  if (!Number.isSafeInteger(options.signatureKeyVersion) || options.signatureKeyVersion < 1) {
    throw new Error("Consent signature key version must be a positive integer.");
  }
  if (!Number.isSafeInteger(options.payloadKeyVersion) || options.payloadKeyVersion < 1) {
    throw new Error("Consent payload key version must be a positive integer.");
  }
  if (!Number.isSafeInteger(options.retentionMs) || options.retentionMs <= 0) {
    throw new Error("Consent retention must be an explicit positive duration.");
  }
}

function rowBuffer(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  throw new Error("Stored consent ciphertext is invalid.");
}

function mapStored(row: Record<string, unknown>): StoredConsentEvidence {
  if (
    !row.id ||
    !row.certificate_code ||
    !row.tenant_id ||
    !row.capture_site_id ||
    !row.payload_sha256 ||
    !row.signature_hmac
  ) {
    throw new Error("Stored consent evidence is incomplete.");
  }
  return {
    consentId: String(row.id),
    certificateCode: String(row.certificate_code),
    tenantId: String(row.tenant_id),
    captureSiteId: String(row.capture_site_id),
    canonicalPayloadCiphertext: rowBuffer(row.canonical_payload_ciphertext),
    payloadKeyVersion: Number(row.payload_key_version),
    payloadSha256: String(row.payload_sha256),
    signatureHmac: String(row.signature_hmac),
    signatureKeyVersion: Number(row.signature_key_version),
    receivedAt: Number(row.received_at),
    retentionExpiresAt: Number(row.retention_expires_at),
  };
}

async function findStored(
  executor: Pick<Client, "execute">,
  tenantId: string,
  idempotencyKey: string,
): Promise<StoredConsentEvidence | null> {
  const result = await executor.execute({
    sql: `SELECT log.id, log.tenant_id, log.capture_site_id,
                 log.canonical_payload_ciphertext, log.payload_key_version,
                 log.payload_sha256, log.signature_hmac, log.signature_key_version,
                 log.received_at, log.retention_expires_at,
                 certificate.id AS certificate_code
          FROM consent_logs AS log
          JOIN consent_certificates AS certificate
            ON certificate.tenant_id = log.tenant_id
           AND certificate.consent_log_id = log.id
          WHERE log.tenant_id = ? AND log.idempotency_key = ?
          LIMIT 1`,
    args: [tenantId, idempotencyKey],
  });
  const row = result.rows[0];
  return row ? mapStored(row as unknown as Record<string, unknown>) : null;
}

export function createLibsqlConsentRepository(client: Client): ConsentRepository {
  return {
    async findCaptureSite(prefix, keyHash) {
      const result = await client.execute({
        sql: `SELECT id, tenant_id, allowed_origins_json, form_url_pattern,
                     disclosure_version, disclosure_text, controller, purpose,
                     channels_json, status
              FROM capture_sites
              WHERE public_key_prefix = ? AND public_key_hash = ?
              LIMIT 1`,
        args: [prefix, keyHash],
      });
      const row = result.rows[0];
      if (!row) return null;
      return {
        id: String(row.id),
        tenantId: String(row.tenant_id),
        allowedOriginsJson: String(row.allowed_origins_json),
        formUrlPattern: row.form_url_pattern == null ? null : String(row.form_url_pattern),
        disclosureVersion: String(row.disclosure_version),
        disclosureText: String(row.disclosure_text),
        controller: String(row.controller),
        purpose: String(row.purpose),
        channelsJson: String(row.channels_json),
        status: String(row.status),
      };
    },

    async persistOrGet(evidence) {
      const results = await client.batch(
        [
          {
          sql: `INSERT OR IGNORE INTO consent_logs
            (id, tenant_id, capture_site_id, subject_identifier_hash,
             controller, purpose, disclosure_version, affirmative_action,
             canonical_payload_ciphertext, payload_key_version, payload_sha256,
             signature_hmac, signature_key_version, idempotency_key,
             occurred_at, retention_expires_at, received_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          args: [
            evidence.consentId,
            evidence.tenantId,
            evidence.captureSiteId,
            evidence.subjectIdentifierHash,
            evidence.controller,
            evidence.purpose,
            evidence.disclosureVersion,
            evidence.affirmativeAction,
            evidence.canonicalPayloadCiphertext,
            evidence.payloadKeyVersion,
            evidence.payloadSha256,
            evidence.signatureHmac,
            evidence.signatureKeyVersion,
            evidence.idempotencyKey,
            evidence.occurredAt,
            evidence.retentionExpiresAt,
            evidence.receivedAt,
          ],
          },
          {
            sql: `INSERT INTO consent_certificates
                    (id, tenant_id, consent_log_id)
                  SELECT ?, ?, ?
                  WHERE EXISTS (
                    SELECT 1 FROM consent_logs
                    WHERE id = ? AND tenant_id = ? AND idempotency_key = ?
                  )
                  ON CONFLICT DO NOTHING`,
            args: [
              evidence.certificateCode,
              evidence.tenantId,
              evidence.consentId,
              evidence.consentId,
              evidence.tenantId,
              evidence.idempotencyKey,
            ],
          },
        ],
        "write",
      );
      const stored = await findStored(client, evidence.tenantId, evidence.idempotencyKey);
      if (!stored) throw new Error("Consent evidence transaction did not persist a complete record.");
      return { evidence: stored, created: results[0].rowsAffected === 1 };
    },
  };
}

export function createConsentService(
  repository: ConsentRepository,
  options: ConsentServiceOptions,
) {
  validateOptions(options);
  const now = options.now ?? Date.now;
  const createId = options.createId ?? ((kind) => `${kind}_${randomUUID()}`);

  return {
    async capture(
      rawInput: unknown,
      context: ConsentCaptureContext,
    ): Promise<ConsentCaptureResult> {
      const parsed = captureInputSchema.safeParse(rawInput);
      if (!parsed.success) throw new ConsentCaptureError("invalid_request");
      if (
        !IDEMPOTENCY_PATTERN.test(context.idempotencyKey) ||
        typeof context.origin !== "string" ||
        context.origin.length > 512 ||
        (context.userAgent !== undefined &&
          (context.userAgent.length > 512 || /[\u0000-\u001f\u007f]/.test(context.userAgent)))
      ) {
        throw new ConsentCaptureError("invalid_request");
      }
      if (
        context.trustedEdge &&
        (!isIP(context.trustedEdge.ip) || !SOURCE_PATTERN.test(context.trustedEdge.source))
      ) {
        throw new ConsentCaptureError("invalid_request");
      }

      let keyHash: string;
      try {
        keyHash = hashCaptureSiteKey(context.siteKey, options.siteKeyPepper);
      } catch {
        throw new ConsentCaptureError("site_not_found");
      }
      const site = await repository.findCaptureSite(context.siteKey.slice(0, 18), keyHash);
      if (!site) throw new ConsentCaptureError("site_not_found");
      if (site.status !== "active") throw new ConsentCaptureError("site_inactive");
      if (!exactAllowedOrigins(site.allowedOriginsJson).includes(context.origin)) {
        throw new ConsentCaptureError("origin_not_allowed");
      }
      if (parsed.data.disclosure_version !== site.disclosureVersion) {
        throw new ConsentCaptureError("disclosure_mismatch");
      }
      if (!formUrlMatches(parsed.data.form_url, site.formUrlPattern)) {
        throw new ConsentCaptureError("form_url_mismatch");
      }

      const receivedAt = now();
      if (!Number.isSafeInteger(receivedAt) || receivedAt <= 0) {
        throw new Error("Consent service clock returned an invalid timestamp.");
      }
      const retentionExpiresAt = receivedAt + options.retentionMs;
      if (!Number.isSafeInteger(retentionExpiresAt) || retentionExpiresAt <= receivedAt) {
        throw new Error("Consent retention deadline is invalid.");
      }
      const occurredAt = requestTimestamp(parsed.data.occurred_at, receivedAt);
      const subject = {
        ...(parsed.data.email ? { email: parsed.data.email } : {}),
        ...(parsed.data.phone ? { phone: normalizePhone(parsed.data.phone) } : {}),
      };
      const subjectIdentifierHash = subjectHash(
        site.tenantId,
        subject,
        options.subjectHashKey,
      );
      const channels = configuredChannels(site.channelsJson);
      if (
        (channels.includes("email") && !subject.email) ||
        (channels.includes("sms") && !subject.phone)
      ) {
        throw new ConsentCaptureError("invalid_request");
      }
      const evidenceWithoutReceipt = {
        schema_version: 1,
        tenant_id: site.tenantId,
        capture_site_id: site.id,
        subject,
        subject_identifier_hash: subjectIdentifierHash,
        controller: site.controller,
        purpose: site.purpose,
        channels,
        disclosure: {
          version: site.disclosureVersion,
          text: site.disclosureText,
        },
        affirmative_action: parsed.data.affirmative_action,
        form_url: parsed.data.form_url,
        origin: context.origin,
        occurred_at: new Date(occurredAt).toISOString(),
        user_agent: context.userAgent ?? null,
        network: context.trustedEdge
          ? { trusted_ip: context.trustedEdge.ip, source: context.trustedEdge.source }
          : { trusted_ip: null, source: null },
      };
      const requestFingerprint = hashCanonicalEvidence(
        canonicalizeJson({
          ...evidenceWithoutReceipt,
          occurred_at: parsed.data.occurred_at ?? null,
        }),
      );
      const evidenceDocument = {
        ...evidenceWithoutReceipt,
        occurred_at_source: parsed.data.occurred_at ? "client" : "server_received",
        request_fingerprint: requestFingerprint,
        received_at: new Date(receivedAt).toISOString(),
        retention_expires_at: new Date(retentionExpiresAt).toISOString(),
      };
      const canonicalPayload = canonicalizeJson(evidenceDocument);
      const payloadSha256 = hashCanonicalEvidence(canonicalPayload);
      const signatureHmac = signCanonicalEvidence(
        canonicalPayload,
        options.signatureKey,
        options.signatureKeyVersion,
      );
      const consentId = createId("consent");
      const certificateCode = createId("certificate");
      const canonicalPayloadCiphertext = Buffer.from(
        encryptSecret(
          canonicalPayload,
          options.payloadEncryptionKey,
          {
            tenantId: site.tenantId,
            resourceType: "consent_log",
            resourceId: consentId,
            field: "canonical_payload",
            provider: site.id,
          },
          String(options.payloadKeyVersion),
        ),
        "utf8",
      );

      const persisted = await repository.persistOrGet({
        consentId,
        certificateCode,
        tenantId: site.tenantId,
        captureSiteId: site.id,
        subjectIdentifierHash,
        controller: site.controller,
        purpose: site.purpose,
        disclosureVersion: site.disclosureVersion,
        affirmativeAction: parsed.data.affirmative_action,
        canonicalPayloadCiphertext,
        payloadKeyVersion: options.payloadKeyVersion,
        payloadSha256,
        signatureHmac,
        signatureKeyVersion: options.signatureKeyVersion,
        idempotencyKey: context.idempotencyKey,
        occurredAt,
        retentionExpiresAt,
        receivedAt,
      });

      const stored = persisted.evidence;
      if (
        !Number.isSafeInteger(stored.retentionExpiresAt) ||
        receivedAt >= stored.retentionExpiresAt
      ) {
        throw new ConsentCaptureError("evidence_verification_failed");
      }
      const decryptionKey =
        stored.payloadKeyVersion === options.payloadKeyVersion
          ? options.payloadEncryptionKey
          : options.payloadDecryptionKeys?.[stored.payloadKeyVersion];
      const signatureKey =
        stored.signatureKeyVersion === options.signatureKeyVersion
          ? options.signatureKey
          : options.signatureVerificationKeys?.[stored.signatureKeyVersion];
      if (!decryptionKey || !signatureKey) {
        throw new ConsentCaptureError("evidence_verification_failed");
      }

      let storedCanonical: string;
      try {
        const decrypted = decryptSecret(
          stored.canonicalPayloadCiphertext.toString("utf8"),
          decryptionKey,
          {
            tenantId: stored.tenantId,
            resourceType: "consent_log",
            resourceId: stored.consentId,
            field: "canonical_payload",
            provider: stored.captureSiteId,
          },
        );
        if (decrypted.keyVersion !== String(stored.payloadKeyVersion)) throw new Error();
        storedCanonical = decrypted.plaintext;
        const decoded: unknown = JSON.parse(storedCanonical);
        if (canonicalizeJson(decoded) !== storedCanonical) throw new Error();
        if (
          !decoded ||
          typeof decoded !== "object" ||
          Array.isArray(decoded) ||
          (decoded as Record<string, unknown>).request_fingerprint !== requestFingerprint
        ) {
          throw new ConsentCaptureError("idempotency_conflict");
        }
      } catch (error) {
        if (error instanceof ConsentCaptureError) throw error;
        throw new ConsentCaptureError("evidence_verification_failed");
      }
      if (
        !verifyCanonicalEvidence(
          storedCanonical,
          stored.payloadSha256,
          stored.signatureHmac,
          signatureKey,
          stored.signatureKeyVersion,
        )
      ) {
        throw new ConsentCaptureError("evidence_verification_failed");
      }

      return {
        created: persisted.created,
        consentId: stored.consentId,
        certificateCode: stored.certificateCode,
        tenantId: stored.tenantId,
        captureSiteId: stored.captureSiteId,
        payloadSha256: stored.payloadSha256,
        signatureHmac: stored.signatureHmac,
        signatureKeyVersion: stored.signatureKeyVersion,
        receivedAt: stored.receivedAt,
        retentionExpiresAt: stored.retentionExpiresAt,
      };
    },
  };
}
