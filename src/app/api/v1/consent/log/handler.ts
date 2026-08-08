import "server-only";

import type {
  ConsentCaptureContext,
  ConsentCaptureResult,
  ConsentCaptureErrorCode,
} from "@/server/consent/service";
import { ConsentCaptureError } from "@/server/consent/service";

const MAX_BODY_BYTES = 32 * 1_024;

const RESPONSE_HEADERS = {
  "cache-control": "no-store, max-age=0",
  "x-content-type-options": "nosniff",
  "x-robots-tag": "noindex, nofollow, noarchive",
};

type ConsentService = {
  capture(input: unknown, context: ConsentCaptureContext): Promise<ConsentCaptureResult>;
};

type TrustedEdgeResolver = {
  getClientIp(request: Request):
    | Promise<{ ip: string; source: string } | undefined>
    | { ip: string; source: string }
    | undefined;
};

function json(body: unknown, status: number, origin?: string): Response {
  return Response.json(body, {
    status,
    headers: {
      ...RESPONSE_HEADERS,
      ...(origin
        ? {
            "access-control-allow-origin": origin,
            vary: "Origin",
          }
        : {}),
    },
  });
}

function captureCredential(request: Request): string | null {
  const siteHeader = request.headers.get("x-optinvault-site-key")?.trim() || null;
  const authorization = request.headers.get("authorization")?.trim() || "";
  const match = /^Publishable ([^\s]+)$/.exec(authorization);
  const publishable = match?.[1] ?? null;
  if (siteHeader && publishable && siteHeader !== publishable) return null;
  return siteHeader ?? publishable;
}

const statusForError: Record<ConsentCaptureErrorCode, number> = {
  invalid_request: 400,
  site_not_found: 401,
  site_inactive: 403,
  site_configuration_invalid: 503,
  origin_not_allowed: 403,
  form_url_mismatch: 422,
  disclosure_mismatch: 422,
  idempotency_conflict: 409,
  evidence_verification_failed: 503,
};

export function createConsentLogHandlers(
  service: ConsentService,
  options: { trustedEdge?: TrustedEdgeResolver } = {},
) {
  return {
    async POST(request: Request): Promise<Response> {
      const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
      if (!contentType.startsWith("application/json")) {
        return json({ error: "invalid_request" }, 415);
      }
      const contentLength = Number(request.headers.get("content-length") ?? "0");
      if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
        return json({ error: "invalid_request" }, 413);
      }
      const siteKey = captureCredential(request);
      const origin = request.headers.get("origin") ?? "";
      const idempotencyKey = request.headers.get("idempotency-key") ?? "";
      if (!siteKey || !origin || !idempotencyKey) {
        return json({ error: "invalid_request" }, 400);
      }

      let body: unknown;
      try {
        const rawBody = await request.text();
        if (Buffer.byteLength(rawBody, "utf8") > MAX_BODY_BYTES) {
          return json({ error: "invalid_request" }, 413);
        }
        body = JSON.parse(rawBody) as unknown;
        if (
          body &&
          typeof body === "object" &&
          !Array.isArray(body) &&
          ("tenant_id" in body || "tenantId" in body)
        ) {
          return json({ error: "invalid_request" }, 400);
        }
      } catch {
        return json({ error: "invalid_request" }, 400);
      }

      try {
        const trustedEdge = options.trustedEdge
          ? await options.trustedEdge.getClientIp(request)
          : undefined;
        const result = await service.capture(body, {
          siteKey,
          origin,
          idempotencyKey,
          userAgent: request.headers.get("user-agent") ?? undefined,
          trustedEdge,
        });
        return json(
          {
            created: result.created,
            consent_id: result.consentId,
            certificate_code: result.certificateCode,
            payload_sha256: result.payloadSha256,
            signature_hmac: result.signatureHmac,
            signature_key_version: result.signatureKeyVersion,
            received_at: new Date(result.receivedAt).toISOString(),
            retention_expires_at: new Date(result.retentionExpiresAt).toISOString(),
          },
          result.created ? 201 : 200,
          origin,
        );
      } catch (error) {
        if (error instanceof ConsentCaptureError) {
          return json({ error: error.code }, statusForError[error.code]);
        }
        throw error;
      }
    },

    async OPTIONS(request: Request): Promise<Response> {
      const origin = request.headers.get("origin") ?? "";
      if (!origin) return new Response(null, { status: 400, headers: RESPONSE_HEADERS });
      return new Response(null, {
        status: 204,
        headers: {
          ...RESPONSE_HEADERS,
          "access-control-allow-origin": origin,
          "access-control-allow-methods": "POST, OPTIONS",
          "access-control-allow-headers":
            "Content-Type, Idempotency-Key, X-OptInVault-Site-Key, Authorization",
          "access-control-max-age": "600",
          vary: "Origin",
        },
      });
    },
  };
}

function positiveIntegerEnv(name: string): number {
  const raw = process.env[name];
  if (!raw || !/^[1-9][0-9]*$/.test(raw)) throw new Error(`${name} is required.`);
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${name} is invalid.`);
  return parsed;
}

async function productionHandlers() {
  const required = [
    "CAPTURE_SITE_KEY_PEPPER",
    "CONSENT_SUBJECT_HASH_KEY",
    "CONSENT_SIGNATURE_KEY",
    "CONSENT_ENCRYPTION_KEY",
  ] as const;
  for (const name of required) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  const [{ getDatabase }, consent, encryption] = await Promise.all([
    import("@/db/client"),
    import("@/server/consent/service"),
    import("@/server/security/encryption"),
  ]);
  const database = await getDatabase();
  const retentionDays = positiveIntegerEnv("CONSENT_RETENTION_DAYS");
  const service = consent.createConsentService(
    consent.createLibsqlConsentRepository(database.client),
    {
      siteKeyPepper: process.env.CAPTURE_SITE_KEY_PEPPER!,
      subjectHashKey: process.env.CONSENT_SUBJECT_HASH_KEY!,
      signatureKey: process.env.CONSENT_SIGNATURE_KEY!,
      signatureKeyVersion: positiveIntegerEnv("CONSENT_SIGNATURE_KEY_VERSION"),
      payloadEncryptionKey: encryption.parseEncryptionKey(
        process.env.CONSENT_ENCRYPTION_KEY!,
      ),
      payloadKeyVersion: positiveIntegerEnv("CONSENT_PAYLOAD_KEY_VERSION"),
      retentionMs: retentionDays * 24 * 60 * 60 * 1_000,
    },
  );
  return createConsentLogHandlers(service);
}

export async function POST(request: Request): Promise<Response> {
  return (await productionHandlers()).POST(request);
}

export async function OPTIONS(request: Request): Promise<Response> {
  return (await productionHandlers()).OPTIONS(request);
}
