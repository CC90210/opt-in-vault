import { Buffer } from "node:buffer";

import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import {
  authenticateApiKey,
  createApiKey,
  extractApiKeyLookupPrefix,
  hashApiKey,
  verifyApiKey,
} from "./api-keys";

const pepper = "p".repeat(32);

describe("API key security", () => {
  it("creates a 256-bit bearer key and only returns persistable prefix/hash metadata", () => {
    const created = createApiKey(pepper, 7);
    const encodedSecret = created.rawKey.replace("oiv_sk_", "");

    expect(created.rawKey).toMatch(/^oiv_sk_[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(encodedSecret, "base64url")).toHaveLength(32);
    expect(created.prefix).toBe(created.rawKey.slice(0, 18));
    expect(created.hash).toMatch(/^[a-f0-9]{64}$/);
    expect(created.hash).not.toContain(encodedSecret);
    expect(created.hashKeyVersion).toBe(7);
  });

  it("hashes deterministically with a pepper and verifies without accepting tampering", () => {
    const rawKey = createApiKey(pepper, 1).rawKey;
    const hash = hashApiKey(rawKey, pepper);

    expect(hashApiKey(rawKey, pepper)).toBe(hash);
    expect(hashApiKey(rawKey, "q".repeat(32))).not.toBe(hash);
    expect(verifyApiKey(rawKey, hash, pepper)).toBe(true);
    expect(verifyApiKey(`${rawKey}x`, hash, pepper)).toBe(false);
    expect(verifyApiKey(rawKey, "not-a-hash", pepper)).toBe(false);
  });

  it("exports a validated lookup prefix without leaking the full credential", () => {
    const rawKey = createApiKey(pepper, 1).rawKey;

    expect(extractApiKeyLookupPrefix(rawKey)).toBe(rawKey.slice(0, 18));
    expect(extractApiKeyLookupPrefix(`${rawKey}x`)).toBeNull();
    expect(extractApiKeyLookupPrefix("not-an-api-key")).toBeNull();
  });

  it("returns tenant identity and stored scopes only for an active matching record", () => {
    const created = createApiKey(pepper, 2);
    const record = {
      id: "key_01",
      tenantId: "tenant_01",
      prefix: created.prefix,
      hash: created.hash,
      hashKeyVersion: created.hashKeyVersion,
      scopes: ["consent:write", "campaign:read"],
      expiresAt: Date.UTC(2026, 7, 9),
      revokedAt: null,
    };

    expect(
      authenticateApiKey(created.rawKey, record, new Map([[2, pepper]]), {
        now: Date.UTC(2026, 7, 8),
        requiredScope: "consent:write",
      }),
    ).toEqual({
      apiKeyId: "key_01",
      tenantId: "tenant_01",
      scopes: ["consent:write", "campaign:read"],
    });

    expect(
      authenticateApiKey(
        created.rawKey,
        { ...record, revokedAt: Date.now() },
        new Map([[2, pepper]]),
      ),
    ).toBeNull();
    expect(
      authenticateApiKey(created.rawKey, record, new Map([[2, pepper]]), {
        now: record.expiresAt,
      }),
    ).toBeNull();
    expect(
      authenticateApiKey(created.rawKey, record, new Map([[2, pepper]]), {
        requiredScope: "campaign:write",
      }),
    ).toBeNull();
    expect(
      authenticateApiKey(created.rawKey, record, new Map([[2, pepper]]), {
        now: Number.NaN,
      }),
    ).toBeNull();
  });

  it("rejects weak peppers", () => {
    expect(() => createApiKey("short", 1)).toThrow(/pepper/i);
  });

  it("fails closed for unknown versions and unbounded pepper rings", () => {
    const created = createApiKey(pepper, 3);
    const record = {
      id: "key_01",
      tenantId: "tenant_01",
      prefix: created.prefix,
      hash: created.hash,
      hashKeyVersion: 3,
      scopes: [] as string[],
      expiresAt: null,
      revokedAt: null,
    };
    const tooManyPeppers = new Map(
      Array.from({ length: 9 }, (_, index) => [index + 1, `${index}`.repeat(32)] as const),
    );

    expect(authenticateApiKey(created.rawKey, record, new Map([[2, pepper]]))).toBeNull();
    expect(authenticateApiKey(created.rawKey, record, tooManyPeppers)).toBeNull();
    expect(() => createApiKey(pepper, 0)).toThrow(/version/i);
  });
});
