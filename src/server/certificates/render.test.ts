import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { CERTIFICATE_TITLE, renderEvidenceCertificate } from "./render";

describe("evidence certificate PDF", () => {
  it("renders a local-resource-only PDF with the required title", async () => {
    const pdf = await renderEvidenceCertificate({
      certificateCode: "cert-01",
      consentId: "consent-01",
      payloadSha256: "a".repeat(64),
      signatureHmac: "b".repeat(64),
      signatureKeyVersion: 2,
      verified: true,
      evidence: {
        schema_version: 1,
        subject: { email: "person@example.test" },
        controller: "Example Controller Inc.",
        purpose: "Product updates",
        disclosure: { version: "v1", text: "I agree to receive updates." },
        affirmative_action: "form_submit",
        form_url: "https://example.test/signup",
        occurred_at: "2026-08-08T11:59:00.000Z",
        received_at: "2026-08-08T12:00:00.000Z",
      },
    });

    expect(Buffer.isBuffer(pdf)).toBe(true);
    expect(pdf.subarray(0, 5).toString("ascii")).toBe("%PDF-");
    expect(pdf.toString("latin1")).toContain(CERTIFICATE_TITLE);
    expect(pdf.toString("latin1")).not.toMatch(/https?:\/\//i);
  });
});
