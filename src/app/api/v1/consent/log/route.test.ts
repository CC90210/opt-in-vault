import { describe, expect, it, vi } from "vitest";

import { ConsentCaptureError, type ConsentCaptureResult } from "@/server/consent/service";

import {
  createConfiguredTrustedEdgeResolver,
  createConsentLogHandlers,
} from "./handler";

const SITE_KEY = `oiv_pk_${"b".repeat(43)}`;
const MAX_BODY_BYTES = 32 * 1_024;
const captureResult: ConsentCaptureResult = {
  created: true,
  consentId: "consent-1",
  certificateCode: "cert-1",
  tenantId: "tenant-from-site",
  captureSiteId: "site-1",
  payloadSha256: "a".repeat(64),
  signatureHmac: "b".repeat(64),
  signatureKeyVersion: 2,
  receivedAt: Date.UTC(2026, 7, 8),
  retentionExpiresAt: Date.UTC(2027, 7, 8),
};

function request(headers: Record<string, string> = {}, body: Record<string, unknown> = {}) {
  return new Request("https://vault.example/api/v1/consent/log", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "https://example.test",
      "idempotency-key": "idem-route-0001",
      "x-optinvault-site-key": SITE_KEY,
      ...headers,
    },
    body: JSON.stringify({
      disclosure_version: "v1",
      affirmative_action: "form_submit",
      form_url: "https://example.test/signup",
      email: "person@example.test",
      ...body,
    }),
  });
}

function streamedRequest(
  chunks: Uint8Array[],
  headers: Record<string, string> = {},
): Request {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
  return new Request("https://vault.example/api/v1/consent/log", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "https://example.test",
      "idempotency-key": "idem-stream-0001",
      "x-optinvault-site-key": SITE_KEY,
      ...headers,
    },
    body: stream,
    duplex: "half",
  } as RequestInit & { duplex: "half" });
}

describe("POST /api/v1/consent/log", () => {
  it("accepts either publishable credential header and never derives tenant from JSON", async () => {
    const capture = vi.fn().mockResolvedValue(captureResult);
    const handlers = createConsentLogHandlers({ capture });

    const response = await handlers.POST(
      request(
        {
          "x-optinvault-site-key": "",
          authorization: `Publishable ${SITE_KEY}`,
        },
        { tenant_id: "attacker" },
      ),
    );

    expect(response.status).toBe(400);
    expect(capture).not.toHaveBeenCalled();

    const valid = await handlers.POST(
      request({ "x-optinvault-site-key": "", authorization: `Publishable ${SITE_KEY}` }),
    );
    expect(valid.status).toBe(201);
    expect(capture).toHaveBeenCalledWith(
      expect.objectContaining({ email: "person@example.test" }),
      expect.objectContaining({
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-route-0001",
      }),
    );
    expect(await valid.json()).toMatchObject({
      consent_id: "consent-1",
      certificate_code: "cert-1",
    });
  });

  it("ignores browser X-Forwarded-For unless a trusted-edge dependency supplies an IP", async () => {
    const capture = vi.fn().mockResolvedValue(captureResult);
    const defaultHandlers = createConsentLogHandlers({ capture });
    await defaultHandlers.POST(request({ "x-forwarded-for": "10.0.0.1" }));
    expect(capture.mock.calls[0][1].trustedEdge).toBeUndefined();

    const trusted = createConsentLogHandlers(
      { capture },
      {
        trustedEdge: {
          getClientIp: vi.fn().mockResolvedValue({ ip: "203.0.113.8", source: "vercel" }),
        },
      },
    );
    await trusted.POST(request({ "x-forwarded-for": "10.0.0.1" }));
    expect(capture.mock.calls[1][1].trustedEdge).toEqual({
      ip: "203.0.113.8",
      source: "vercel",
    });
  });

  it("trusts only a single public direct-Vercel source header when explicitly configured", async () => {
    expect(() => createConfiguredTrustedEdgeResolver({ VERCEL: "1" })).toThrow(
      /CONSENT_TRUSTED_EDGE_PROVIDER=vercel/,
    );
    expect(() =>
      createConfiguredTrustedEdgeResolver({
        CONSENT_TRUSTED_EDGE_PROVIDER: "vercel",
        VERCEL: "0",
      }),
    ).toThrow(/directly on Vercel/);

    const resolver = createConfiguredTrustedEdgeResolver({
      CONSENT_TRUSTED_EDGE_PROVIDER: "vercel",
      VERCEL: "1",
    });
    expect(
      await resolver.getClientIp(
        request({
          "x-forwarded-for": "1.1.1.1",
          "x-vercel-forwarded-for": "8.8.8.8",
        }),
      ),
    ).toEqual({ ip: "8.8.8.8", source: "vercel" });
    expect(
      await resolver.getClientIp(request({ "x-forwarded-for": "8.8.8.8" })),
    ).toBeUndefined();
    expect(
      await resolver.getClientIp(
        request({ "x-vercel-forwarded-for": "8.8.8.8, 1.1.1.1" }),
      ),
    ).toBeUndefined();
    expect(
      await resolver.getClientIp(
        request({ "x-vercel-forwarded-for": "127.0.0.1" }),
      ),
    ).toBeUndefined();
  });

  it("maps validation/auth/conflict failures without leaking details and disables caching", async () => {
    const cases = [
      ["site_not_found", 401],
      ["origin_not_allowed", 403],
      ["source_unavailable", 503],
      ["idempotency_conflict", 409],
    ] as const;

    for (const [code, status] of cases) {
      const handlers = createConsentLogHandlers({
        capture: vi.fn().mockRejectedValue(new ConsentCaptureError(code)),
      });
      const response = await handlers.POST(request());
      expect(response.status).toBe(status);
      expect(response.headers.get("cache-control")).toContain("no-store");
      expect(response.headers.get("x-robots-tag")).toContain("noindex");
      expect(await response.json()).toEqual({ error: code });
    }
  });

  it("enforces the byte cap incrementally when Content-Length is missing", async () => {
    const capture = vi.fn().mockResolvedValue(captureResult);
    const handlers = createConsentLogHandlers({ capture });
    const streamed = streamedRequest([
      new Uint8Array(MAX_BODY_BYTES).fill(0x20),
      new Uint8Array([0x20]),
    ]);
    expect(streamed.headers.get("content-length")).toBeNull();
    const response = await handlers.POST(streamed);

    expect(response.status).toBe(413);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(capture).not.toHaveBeenCalled();
  });

  it("requires the exact JSON media type", async () => {
    const capture = vi.fn().mockResolvedValue(captureResult);
    const handlers = createConsentLogHandlers({ capture });
    const response = await handlers.POST(
      request({ "content-type": "application/jsontext" }),
    );

    expect(response.status).toBe(415);
    expect(capture).not.toHaveBeenCalled();
  });

  it("accepts an exactly 32 KiB streamed JSON body", async () => {
    const capture = vi.fn().mockResolvedValue(captureResult);
    const handlers = createConsentLogHandlers({ capture });
    const encoded = new TextEncoder().encode(
      JSON.stringify({
        disclosure_version: "v1",
        affirmative_action: "form_submit",
        form_url: "https://example.test/signup",
        email: "person@example.test",
      }),
    );
    const padding = new Uint8Array(MAX_BODY_BYTES - encoded.byteLength).fill(0x20);
    const response = await handlers.POST(streamedRequest([encoded, padding]));

    expect(response.status).toBe(201);
    expect(capture).toHaveBeenCalledOnce();
  });

  it("rejects malformed UTF-8 before parsing JSON", async () => {
    const capture = vi.fn().mockResolvedValue(captureResult);
    const handlers = createConsentLogHandlers({ capture });
    const response = await handlers.POST(
      streamedRequest([new Uint8Array([0x7b, 0x22, 0xc3, 0x28, 0x22, 0x7d])]),
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
    expect(capture).not.toHaveBeenCalled();
  });

  it("returns a bounded 429 response for exhausted capture buckets", async () => {
    const handlers = createConsentLogHandlers({
      capture: vi
        .fn()
        .mockRejectedValue(
          new ConsentCaptureError("rate_limited", { retryAfterSeconds: 17 }),
        ),
    });
    const response = await handlers.POST(request());

    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("17");
    expect(response.headers.get("access-control-allow-origin")).toBe(
      "https://example.test",
    );
    expect(await response.json()).toEqual({ error: "rate_limited" });
  });
});
