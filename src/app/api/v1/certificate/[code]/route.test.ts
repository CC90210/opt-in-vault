import { createHash, randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";
import { describe, expect, it, vi } from "vitest";

import { createApiKey } from "@/server/auth/api-keys";
import {
  createSessionToken,
  SESSION_COOKIE_NAME,
} from "@/server/auth/session";

import {
  authorizeCertificateTenant,
  createCertificateHandlers,
  createCertificateShareToken,
  hashCertificateShareToken,
  resolveVersionedConsentValue,
  type CertificateRecord,
} from "./handler";

const NOW = Date.UTC(2026, 7, 8);
const SHARE = `oiv_share_${"c".repeat(43)}`;
const MIGRATIONS_FOLDER = fileURLToPath(
  new URL("../../../../../../drizzle", import.meta.url),
);
const CURRENT_API_PEPPER = "current-api-key-pepper-with-at-least-32-bytes";
const HISTORICAL_API_PEPPER = "historical-api-key-pepper-with-at-least-32-bytes";
const SESSION_SECRET = "certificate-session-secret-with-at-least-32-bytes";
const AUTH_ENVIRONMENT = {
  API_KEY_PEPPER: CURRENT_API_PEPPER,
  API_KEY_PEPPER_VERSION: "2",
  API_KEY_PEPPERS_JSON: JSON.stringify({ 1: HISTORICAL_API_PEPPER }),
  SESSION_SECRET,
};

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

describe("certificate tenant authorization", () => {
  let client: Client;
  let historicalRawKey: string;
  let historicalKeyHash: string;
  let tenantOneId: string;
  let tenantTwoId: string;

  beforeEach(async () => {
    client = createClient({ url: "file::memory:?cache=shared" });
    await migrate(drizzle(client), { migrationsFolder: MIGRATIONS_FOLDER });
    await client.execute("PRAGMA foreign_keys = ON");
    tenantOneId = `tenant-${randomUUID()}`;
    tenantTwoId = `tenant-${randomUUID()}`;
    const historicalKey = createApiKey(HISTORICAL_API_PEPPER, 1);
    historicalRawKey = historicalKey.rawKey;
    historicalKeyHash = historicalKey.hash;
    await client.batch(
      [
        {
          sql: "INSERT INTO tenants (id, slug, name, status) VALUES (?, ?, 'Tenant One', 'active')",
          args: [tenantOneId, tenantOneId],
        },
        {
          sql: "INSERT INTO tenants (id, slug, name, status) VALUES (?, ?, 'Tenant Two', 'active')",
          args: [tenantTwoId, tenantTwoId],
        },
        {
          sql: `INSERT INTO tenant_api_keys
                (id, tenant_id, prefix, key_hash, hash_key_version, scopes_json)
                VALUES (?, ?, ?, ?, 1, ?)`,
          args: [
            `key-${randomUUID()}`,
            tenantOneId,
            historicalKey.prefix,
            historicalKey.hash,
            JSON.stringify(["certificate:read"]),
          ],
        },
      ],
      "write",
    );
  });

  afterEach(() => client.close());

  it("accepts a historical pepper version but fails closed when its tenant becomes inactive", async () => {
    const request = new Request("https://vault.example/api/v1/certificate/cert-1", {
      headers: { authorization: `Bearer ${historicalRawKey}` },
    });

    await expect(
      authorizeCertificateTenant(client, request, AUTH_ENVIRONMENT, {
        now: () => NOW,
      }),
    ).resolves.toEqual({ tenantId: tenantOneId });

    await client.execute({
      sql: "UPDATE tenants SET status = 'paused' WHERE id = ?",
      args: [tenantOneId],
    });
    await expect(
      authorizeCertificateTenant(client, request, AUTH_ENVIRONMENT, {
        now: () => NOW,
      }),
    ).resolves.toBeNull();

    const inactiveSession = createSessionToken(
      {
        tenantId: tenantOneId,
        scopes: ["certificate:read"],
        expiresAt: NOW + 60_000,
      },
      SESSION_SECRET,
      { now: NOW },
    );
    await expect(
      authorizeCertificateTenant(
        client,
        new Request("https://vault.example/api/v1/certificate/cert-1", {
          headers: { cookie: `${SESSION_COOKIE_NAME}=${inactiveSession}` },
        }),
        AUTH_ENVIRONMENT,
        { now: () => NOW },
      ),
    ).resolves.toBeNull();

    const render = vi.fn();
    const response = await createCertificateHandlers({
      findCertificate: vi.fn().mockResolvedValue(record({ tenantId: tenantOneId })),
      authorizeTenant: (incoming) =>
        authorizeCertificateTenant(client, incoming, AUTH_ENVIRONMENT, {
          now: () => NOW,
        }),
      hashShareToken: vi.fn(),
      render,
      markDownloaded: vi.fn(),
      now: () => NOW,
    }).GET(request, context());
    const body = await response.text();

    expect(response.status).toBe(404);
    expect(body).toBe('{"error":"not_found"}');
    expect(body).not.toContain(historicalRawKey);
    expect(body).not.toContain(historicalKeyHash);
    expect(render).not.toHaveBeenCalled();
  });

  it("keeps share-token authorization independent from tenant credentials", async () => {
    const render = vi.fn().mockResolvedValue(Buffer.from("%PDF-shared"));
    const response = await createCertificateHandlers({
      findCertificate: vi
        .fn()
        .mockResolvedValue(record({ tenantId: tenantTwoId })),
      authorizeTenant: (request) =>
        authorizeCertificateTenant(client, request, AUTH_ENVIRONMENT, {
          now: () => NOW,
        }),
      hashShareToken: (value) => createHash("sha256").update(value).digest("hex"),
      render,
      markDownloaded: vi.fn(),
      now: () => NOW,
    }).GET(
      new Request("https://vault.example/api/v1/certificate/cert-1", {
        headers: { authorization: `Share ${SHARE}` },
      }),
      context(),
    );

    expect(response.status).toBe(200);
    expect(render).toHaveBeenCalledOnce();
  });

  it.each(["admin", "consent:read", "certificate:read"])(
    "preserves the %s certificate session scope",
    async (scope) => {
      const token = createSessionToken(
        {
          tenantId: tenantOneId,
          scopes: [scope],
          expiresAt: NOW + 60_000,
        },
        SESSION_SECRET,
        { now: NOW },
      );
      const request = new Request("https://vault.example/api/v1/certificate/cert-1", {
        headers: { cookie: `${SESSION_COOKIE_NAME}=${token}` },
      });

      await expect(
        authorizeCertificateTenant(client, request, AUTH_ENVIRONMENT, {
          now: () => NOW,
        }),
      ).resolves.toEqual({ tenantId: tenantOneId });
    },
  );

  it("rejects unrelated scopes and keeps a valid tenant credential isolated from another tenant's certificate", async () => {
    const unrelatedToken = createSessionToken(
      {
        tenantId: tenantOneId,
        scopes: ["dashboard:read"],
        expiresAt: NOW + 60_000,
      },
      SESSION_SECRET,
      { now: NOW },
    );
    await expect(
      authorizeCertificateTenant(
        client,
        new Request("https://vault.example/api/v1/certificate/cert-2", {
          headers: { cookie: `${SESSION_COOKIE_NAME}=${unrelatedToken}` },
        }),
        AUTH_ENVIRONMENT,
        { now: () => NOW },
      ),
    ).resolves.toBeNull();

    const render = vi.fn();
    const response = await createCertificateHandlers({
      findCertificate: vi.fn().mockResolvedValue(record({ tenantId: tenantTwoId })),
      authorizeTenant: (request) =>
        authorizeCertificateTenant(client, request, AUTH_ENVIRONMENT, {
          now: () => NOW,
        }),
      hashShareToken: vi.fn(),
      render,
      markDownloaded: vi.fn(),
      now: () => NOW,
    }).GET(
      new Request("https://vault.example/api/v1/certificate/cert-2", {
        headers: { authorization: `Bearer ${historicalRawKey}` },
      }),
      context("cert-2"),
    );

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "not_found" });
    expect(render).not.toHaveBeenCalled();
  });
});
