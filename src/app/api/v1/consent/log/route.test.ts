import { describe, expect, it, vi } from "vitest";

import { ConsentCaptureError, type ConsentCaptureResult } from "@/server/consent/service";

import { createConsentLogHandlers } from "./handler";

const SITE_KEY = `oiv_pk_${"b".repeat(43)}`;
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

  it("maps validation/auth/conflict failures without leaking details and disables caching", async () => {
    const cases = [
      ["site_not_found", 401],
      ["origin_not_allowed", 403],
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
});
