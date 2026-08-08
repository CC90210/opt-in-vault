import { createHash } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  createCertificateHandlers,
  createCertificateShareToken,
  hashCertificateShareToken,
  resolveVersionedConsentValue,
  type CertificateRecord,
} from "./handler";

const NOW = Date.UTC(2026, 7, 8);
const SHARE = `oiv_share_${"c".repeat(43)}`;

function record(overrides: Partial<CertificateRecord> = {}): CertificateRecord {
  return {
    code: "cert-1",
    tenantId: "tenant-1",
    consentId: "consent-1",
    shareTokenHash: createHash("sha256").update(SHARE).digest("hex"),
    shareExpiresAt: NOW + 60_000,
    revokedAt: null,
    retentionExpiresAt: NOW + 365 * 24 * 60 * 60 * 1_000,
    ...overrides,
  };
}

function context(code = "cert-1") {
  return { params: Promise.resolve({ code }) };
}

describe("GET /api/v1/certificate/[code]", () => {
  it("creates a random share credential whose persisted representation is only a keyed hash", () => {
    const pepper = "share-token-pepper-with-at-least-thirty-two-bytes";
    const first = createCertificateShareToken(pepper);
    const second = createCertificateShareToken(pepper);

    expect(first.rawToken).toMatch(/^oiv_share_[A-Za-z0-9_-]{43}$/);
    expect(first.rawToken).not.toBe(second.rawToken);
    expect(first.tokenHash).toBe(hashCertificateShareToken(first.rawToken, pepper));
    expect(first.tokenHash).toMatch(/^[a-f0-9]{64}$/);
    expect(first.tokenHash).not.toContain(first.rawToken.slice("oiv_share_".length));
  });

  it("selects bounded historical key material by the stored version", () => {
    expect(
      resolveVersionedConsentValue({
        targetVersion: 2,
        currentVersion: 3,
        currentValue: "current-value",
        serializedRing: JSON.stringify({ 1: "old-one", 2: "old-two" }),
        name: "test ring",
      }),
    ).toBe("old-two");
    expect(() =>
      resolveVersionedConsentValue({
        targetVersion: 4,
        currentVersion: 3,
        currentValue: "current-value",
        serializedRing: JSON.stringify({ 2: "old-two" }),
        name: "test ring",
      }),
    ).toThrow(/unavailable/i);
  });

  it("allows a matching tenant principal and returns protected PDF headers", async () => {
    const render = vi.fn().mockResolvedValue(Buffer.from("%PDF-test"));
    const markDownloaded = vi.fn().mockResolvedValue(undefined);
    const handlers = createCertificateHandlers({
      findCertificate: vi.fn().mockResolvedValue(record()),
      authorizeTenant: vi.fn().mockResolvedValue({ tenantId: "tenant-1" }),
      hashShareToken: vi.fn(),
      render,
      markDownloaded,
      now: () => NOW,
    });

    const response = await handlers.GET(
      new Request("https://vault.example/api/v1/certificate/cert-1"),
      context(),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/pdf");
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("x-robots-tag")).toContain("noindex");
    expect(response.headers.get("content-disposition")).toContain("cert-1.pdf");
    expect(Buffer.from(await response.arrayBuffer()).subarray(0, 5).toString()).toBe("%PDF-");
    expect(markDownloaded).toHaveBeenCalledWith(record());
  });

  it("allows a separate unexpired hashed share token", async () => {
    const item = record();
    const handlers = createCertificateHandlers({
      findCertificate: vi.fn().mockResolvedValue(item),
      authorizeTenant: vi.fn().mockResolvedValue(null),
      hashShareToken: (value) => createHash("sha256").update(value).digest("hex"),
      render: vi.fn().mockResolvedValue(Buffer.from("%PDF-shared")),
      markDownloaded: vi.fn(),
      now: () => NOW,
    });

    const response = await handlers.GET(
      new Request("https://vault.example/api/v1/certificate/cert-1", {
        headers: { authorization: `Share ${SHARE}` },
      }),
      context(),
    );
    expect(response.status).toBe(200);
  });

  it.each([
    ["expired", { shareExpiresAt: NOW }, SHARE],
    ["revoked", { revokedAt: NOW - 1 }, SHARE],
    ["wrong", {}, `oiv_share_${"d".repeat(43)}`],
  ])("rejects %s share access without revealing certificate existence", async (_name, overrides, share) => {
    const handlers = createCertificateHandlers({
      findCertificate: vi.fn().mockResolvedValue(record(overrides)),
      authorizeTenant: vi.fn().mockResolvedValue(null),
      hashShareToken: (value) => createHash("sha256").update(value).digest("hex"),
      render: vi.fn(),
      markDownloaded: vi.fn(),
      now: () => NOW,
    });
    const response = await handlers.GET(
      new Request("https://vault.example/api/v1/certificate/cert-1", {
        headers: { authorization: `Share ${share}` },
      }),
      context(),
    );
    expect(response.status).toBe(404);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("x-robots-tag")).toContain("noindex");
  });

  it("rejects a tenant from another workspace", async () => {
    const handlers = createCertificateHandlers({
      findCertificate: vi.fn().mockResolvedValue(record()),
      authorizeTenant: vi.fn().mockResolvedValue({ tenantId: "tenant-2" }),
      hashShareToken: vi.fn(),
      render: vi.fn(),
      markDownloaded: vi.fn(),
      now: () => NOW,
    });
    const response = await handlers.GET(
      new Request("https://vault.example/api/v1/certificate/cert-1"),
      context(),
    );
    expect(response.status).toBe(404);
  });

  it("rejects expired evidence even for its tenant and never accepts a share token in a URL", async () => {
    const item = record({ retentionExpiresAt: NOW });
    const handlers = createCertificateHandlers({
      findCertificate: vi.fn().mockResolvedValue(item),
      authorizeTenant: vi.fn().mockResolvedValue({ tenantId: "tenant-1" }),
      hashShareToken: (value) => createHash("sha256").update(value).digest("hex"),
      render: vi.fn(),
      markDownloaded: vi.fn(),
      now: () => NOW,
    });

    const expired = await handlers.GET(
      new Request("https://vault.example/api/v1/certificate/cert-1"),
      context(),
    );
    expect(expired.status).toBe(404);

    const queryHandlers = createCertificateHandlers({
      findCertificate: vi.fn().mockResolvedValue(record()),
      authorizeTenant: vi.fn().mockResolvedValue(null),
      hashShareToken: (value) => createHash("sha256").update(value).digest("hex"),
      render: vi.fn(),
      markDownloaded: vi.fn(),
      now: () => NOW,
    });
    const queryCredential = await queryHandlers.GET(
      new Request(`https://vault.example/api/v1/certificate/cert-1?share=${SHARE}`),
      context(),
    );
    expect(queryCredential.status).toBe(404);
  });
});
