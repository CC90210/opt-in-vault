import "server-only";

import { createHmac, randomUUID } from "node:crypto";
import { isIP } from "node:net";

import type { Client } from "@libsql/client";
import { z } from "zod";

import { decryptSecret, encryptSecret } from "@/server/security/encryption";
import { isPublicIpAddress } from "@/server/security/network";
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
const RATE_LIMIT_HASH_PATTERN = /^[a-f0-9]{64}$/;
const RATE_LIMIT_SCOPE_CAPTURE = "public_consent_capture";
const RATE_LIMIT_SCOPE_SOURCE = "public_consent_source";
const RATE_LIMIT_SCOPE_REPLAY = "public_consent_replay";
const MIN_RATE_LIMIT_WINDOW_MS = 1_000;
const MAX_RATE_LIMIT_WINDOW_MS = 60 * 60 * 1_000;
const MAX_RATE_LIMIT_REQUESTS = 10_000;
const MAX_RATE_LIMIT_KEY_PART_LENGTH = 256;

/**
 * Fixed-window public ingress contract. Callers may tighten these values through
 * createConsentService options, within the validation bounds above.
 */
export const CONSENT_CAPTURE_RATE_LIMIT_DEFAULTS = Object.freeze({
  maxRequests: 120,
  sourceMaxRequests: 25,
  replayMaxRequests: 10,
  windowMs: 60_000,
});

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
  | "source_unavailable"
  | "rate_limited"
  | "idempotency_conflict"
  | "evidence_verification_failed";

export class ConsentCaptureError extends Error {
  readonly code: ConsentCaptureErrorCode;
  readonly retryAfterSeconds?: number;

  constructor(
    code: ConsentCaptureErrorCode,
    options: { retryAfterSeconds?: number } = {},
  ) {
    super(code);
    this.name = "ConsentCaptureError";
    this.code = code;
    this.retryAfterSeconds = options.retryAfterSeconds;
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

type CaptureRateLimitInput = {
  tenantId: string;
  idempotencyKey: string;
  captureBucketKeyHash: string;
  sourceBucketKeyHash: string;
  replayBucketKeyHash: string;
  windowStartedAt: number;
  expiresAt: number;
  maxRequests: number;
  sourceMaxRequests: number;
  replayMaxRequests: number;
};

type CaptureRateLimitDecision = {
  allowed: boolean;
  replay: boolean;
};

export type ConsentRepository = {
  findCaptureSite(prefix: string, keyHash: string): Promise<CaptureSiteRecord | null>;
  consumeCaptureRateLimit(
    input: CaptureRateLimitInput,
  ): Promise<CaptureRateLimitDecision>;
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
  captureRateLimit?: {
    maxRequests: number;
    sourceMaxRequests: number;
    replayMaxRequests: number;
    windowMs: number;
  };
  requireTrustedSource?: boolean;
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
  const rateLimit = options.captureRateLimit ?? CONSENT_CAPTURE_RATE_LIMIT_DEFAULTS;
  if (
    !Number.isSafeInteger(rateLimit.maxRequests) ||
    rateLimit.maxRequests < 1 ||
    rateLimit.maxRequests > MAX_RATE_LIMIT_REQUESTS
  ) {
    throw new Error("Consent capture rate-limit maximum is invalid.");
  }
  if (
    !Number.isSafeInteger(rateLimit.sourceMaxRequests) ||
    rateLimit.sourceMaxRequests < 1 ||
    rateLimit.sourceMaxRequests > MAX_RATE_LIMIT_REQUESTS
  ) {
    throw new Error("Consent source rate-limit maximum is invalid.");
  }
  if (
    !Number.isSafeInteger(rateLimit.replayMaxRequests) ||
    rateLimit.replayMaxRequests < 1 ||
    rateLimit.replayMaxRequests > MAX_RATE_LIMIT_REQUESTS
  ) {
    throw new Error("Consent replay rate-limit maximum is invalid.");
  }
  if (
    !Number.isSafeInteger(rateLimit.windowMs) ||
    rateLimit.windowMs < MIN_RATE_LIMIT_WINDOW_MS ||
    rateLimit.windowMs > MAX_RATE_LIMIT_WINDOW_MS
  ) {
    throw new Error("Consent capture rate-limit window is invalid.");
  }
}

function rateLimitKeyHash(
  kind: "capture" | "source" | "replay",
  tenantId: string,
  captureSiteId: string,
  keyMaterial: string,
  secret: string,
): string {
  for (const value of [tenantId, captureSiteId]) {
    if (
      value.length < 1 ||
      value.length > MAX_RATE_LIMIT_KEY_PART_LENGTH ||
      /[\u0000-\u001f\u007f]/.test(value)
    ) {
      throw new ConsentCaptureError("site_configuration_invalid");
    }
  }
  return createHmac("sha256", secret)
    .update(
      canonicalizeJson({
        version: 1,
        kind,
        tenant_id: tenantId,
        capture_site_id: captureSiteId,
        ...(kind === "source" ? { source_identity: keyMaterial } : {}),
        ...(kind === "replay" ? { idempotency_key: keyMaterial } : {}),
      }),
      "utf8",
    )
    .digest("hex");
}

function validateRateLimitInput(input: CaptureRateLimitInput): void {
  if (
    input.tenantId.length < 1 ||
    input.tenantId.length > MAX_RATE_LIMIT_KEY_PART_LENGTH ||
    !IDEMPOTENCY_PATTERN.test(input.idempotencyKey) ||
    !RATE_LIMIT_HASH_PATTERN.test(input.captureBucketKeyHash) ||
    !RATE_LIMIT_HASH_PATTERN.test(input.sourceBucketKeyHash) ||
    !RATE_LIMIT_HASH_PATTERN.test(input.replayBucketKeyHash) ||
    !Number.isSafeInteger(input.windowStartedAt) ||
    input.windowStartedAt < 0 ||
    !Number.isSafeInteger(input.expiresAt) ||
    input.expiresAt <= input.windowStartedAt ||
    input.expiresAt - input.windowStartedAt > MAX_RATE_LIMIT_WINDOW_MS ||
    !Number.isSafeInteger(input.maxRequests) ||
    input.maxRequests < 1 ||
    input.maxRequests > MAX_RATE_LIMIT_REQUESTS ||
    !Number.isSafeInteger(input.sourceMaxRequests) ||
    input.sourceMaxRequests < 1 ||
    input.sourceMaxRequests > MAX_RATE_LIMIT_REQUESTS ||
    !Number.isSafeInteger(input.replayMaxRequests) ||
    input.replayMaxRequests < 1 ||
    input.replayMaxRequests > MAX_RATE_LIMIT_REQUESTS
  ) {
    throw new Error("Consent capture rate-limit input is invalid.");
  }
}

function normalizedTrustedEdge(
  evidence: TrustedEdgeEvidence | undefined,
): TrustedEdgeEvidence | undefined {
  if (!evidence) return undefined;
  if (!SOURCE_PATTERN.test(evidence.source) || !isPublicIpAddress(evidence.ip)) {
    throw new ConsentCaptureError("invalid_request");
  }
  const family = isIP(evidence.ip);
  let ip: string;
  if (family === 4) {
    ip = evidence.ip
      .split(".")
      .map((part) => String(Number(part)))
      .join(".");
  } else {
    try {
      const hostname = new URL(`http://[${evidence.ip}]/`).hostname;
      ip = hostname.slice(1, -1).toLowerCase();
    } catch {
      throw new ConsentCaptureError("invalid_request");
    }
  }
  return { ip, source: evidence.source };
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
        sql: `SELECT site.id, site.tenant_id, site.allowed_origins_json,
                     site.form_url_pattern, site.disclosure_version,
                     site.disclosure_text, site.controller, site.purpose,
                     site.channels_json, site.status
              FROM capture_sites AS site
              JOIN tenants AS tenant ON tenant.id = site.tenant_id
              WHERE site.public_key_prefix = ? AND site.public_key_hash = ?
                AND tenant.status = 'active'
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

    async consumeCaptureRateLimit(input) {
      validateRateLimitInput(input);
      const result = await client.execute({
        sql: `WITH parameters (
                tenant_id, idempotency_key, window_started_at, expires_at,
                replay_id, source_id, capture_id,
                replay_scope, source_scope, capture_scope,
                replay_hash, source_hash, capture_hash,
                replay_max, source_max, capture_max
              ) AS (VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)),
              request_mode AS (
                SELECT parameters.*,
                       CASE WHEN EXISTS (
                         SELECT 1 FROM consent_logs
                         WHERE tenant_id = parameters.tenant_id
                           AND idempotency_key = parameters.idempotency_key
                       ) THEN 1 ELSE 0 END AS is_replay
                FROM parameters
              ),
              capacity AS (
                SELECT request_mode.*
                FROM request_mode
                WHERE (
                  is_replay = 1 AND COALESCE((
                    SELECT count FROM rate_limit_buckets
                    WHERE tenant_id = request_mode.tenant_id
                      AND scope = request_mode.replay_scope
                      AND bucket_key_hash = request_mode.replay_hash
                      AND window_started_at = request_mode.window_started_at
                  ), 0) < request_mode.replay_max
                  AND COALESCE((
                    SELECT count FROM rate_limit_buckets
                    WHERE tenant_id = request_mode.tenant_id
                      AND scope = request_mode.source_scope
                      AND bucket_key_hash = request_mode.source_hash
                      AND window_started_at = request_mode.window_started_at
                  ), 0) < request_mode.source_max
                ) OR (
                  is_replay = 0
                  AND COALESCE((
                    SELECT count FROM rate_limit_buckets
                    WHERE tenant_id = request_mode.tenant_id
                      AND scope = request_mode.source_scope
                      AND bucket_key_hash = request_mode.source_hash
                      AND window_started_at = request_mode.window_started_at
                  ), 0) < request_mode.source_max
                  AND COALESCE((
                    SELECT count FROM rate_limit_buckets
                    WHERE tenant_id = request_mode.tenant_id
                      AND scope = request_mode.capture_scope
                      AND bucket_key_hash = request_mode.capture_hash
                      AND window_started_at = request_mode.window_started_at
                  ), 0) < request_mode.capture_max
                )
              ),
              buckets (id, scope, bucket_key_hash) AS (
                SELECT replay_id, replay_scope, replay_hash
                FROM capacity WHERE is_replay = 1
                UNION ALL
                SELECT source_id, source_scope, source_hash
                FROM capacity
                UNION ALL
                SELECT capture_id, capture_scope, capture_hash
                FROM capacity WHERE is_replay = 0
              )
              INSERT INTO rate_limit_buckets
                (id, tenant_id, scope, bucket_key_hash,
                 window_started_at, count, expires_at)
              SELECT buckets.id, parameters.tenant_id, buckets.scope,
                     buckets.bucket_key_hash, parameters.window_started_at,
                     1, parameters.expires_at
              FROM buckets CROSS JOIN parameters
              WHERE true
              ON CONFLICT (tenant_id, scope, bucket_key_hash, window_started_at)
              DO UPDATE SET count = rate_limit_buckets.count + 1
              RETURNING scope, count`,
        args: [
          input.tenantId,
          input.idempotencyKey,
          input.windowStartedAt,
          input.expiresAt,
          `rate-limit-replay-${randomUUID()}`,
          `rate-limit-source-${randomUUID()}`,
          `rate-limit-capture-${randomUUID()}`,
          RATE_LIMIT_SCOPE_REPLAY,
          RATE_LIMIT_SCOPE_SOURCE,
          RATE_LIMIT_SCOPE_CAPTURE,
          input.replayBucketKeyHash,
          input.sourceBucketKeyHash,
          input.captureBucketKeyHash,
          input.replayMaxRequests,
          input.sourceMaxRequests,
          input.maxRequests,
        ],
      });
      if (result.rows.length === 0) {
        return { allowed: false, replay: false };
      }
      const counts = new Map(
        result.rows.map((row) => [String(row.scope), Number(row.count)]),
      );
      const replay = counts.has(RATE_LIMIT_SCOPE_REPLAY);
      const expected = replay
        ? [
            [RATE_LIMIT_SCOPE_REPLAY, input.replayMaxRequests] as const,
            [RATE_LIMIT_SCOPE_SOURCE, input.sourceMaxRequests] as const,
          ]
        : [
            [RATE_LIMIT_SCOPE_SOURCE, input.sourceMaxRequests] as const,
            [RATE_LIMIT_SCOPE_CAPTURE, input.maxRequests] as const,
          ];
      if (
        result.rows.length !== expected.length ||
        counts.size !== expected.length ||
        expected.some(([scope, limit]) => {
          const count = counts.get(scope);
          return (
            !Number.isSafeInteger(count) ||
            count === undefined ||
            count < 1 ||
            count > limit
          );
        })
      ) {
        throw new Error("Consent capture rate-limit result is invalid.");
      }
      return { allowed: true, replay };
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
  const captureRateLimit = {
    ...(options.captureRateLimit ?? CONSENT_CAPTURE_RATE_LIMIT_DEFAULTS),
  };
  const requireTrustedSource = options.requireTrustedSource ?? true;

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
      const trustedEdge = normalizedTrustedEdge(context.trustedEdge);
      if (requireTrustedSource && !trustedEdge) {
        throw new ConsentCaptureError("source_unavailable");
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
      const windowStartedAt =
        Math.floor(receivedAt / captureRateLimit.windowMs) * captureRateLimit.windowMs;
      const rateLimitExpiresAt = windowStartedAt + captureRateLimit.windowMs;
      if (!Number.isSafeInteger(rateLimitExpiresAt) || rateLimitExpiresAt <= receivedAt) {
        throw new Error("Consent capture rate-limit window is invalid.");
      }
      const rateLimit = await repository.consumeCaptureRateLimit({
        tenantId: site.tenantId,
        idempotencyKey: context.idempotencyKey,
        captureBucketKeyHash: rateLimitKeyHash(
          "capture",
          site.tenantId,
          site.id,
          "",
          options.siteKeyPepper,
        ),
        sourceBucketKeyHash: rateLimitKeyHash(
          "source",
          site.tenantId,
          site.id,
          trustedEdge
            ? `${trustedEdge.source}\n${trustedEdge.ip}`
            : "explicitly_unattributed",
          options.siteKeyPepper,
        ),
        replayBucketKeyHash: rateLimitKeyHash(
          "replay",
          site.tenantId,
          site.id,
          context.idempotencyKey,
          options.siteKeyPepper,
        ),
        windowStartedAt,
        expiresAt: rateLimitExpiresAt,
        maxRequests: captureRateLimit.maxRequests,
        sourceMaxRequests: trustedEdge
          ? captureRateLimit.sourceMaxRequests
          : captureRateLimit.maxRequests,
        replayMaxRequests: captureRateLimit.replayMaxRequests,
      });
      if (
        !rateLimit ||
        typeof rateLimit.allowed !== "boolean" ||
        typeof rateLimit.replay !== "boolean"
      ) {
        throw new Error("Consent capture rate-limit decision is invalid.");
      }
      if (!rateLimit.allowed) {
        throw new ConsentCaptureError("rate_limited", {
          retryAfterSeconds: Math.max(
            1,
            Math.ceil((rateLimitExpiresAt - receivedAt) / 1_000),
          ),
        });
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
        network: trustedEdge
          ? { trusted_ip: trustedEdge.ip, source: trustedEdge.source }
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
