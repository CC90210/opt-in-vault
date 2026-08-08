import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import {
  createSessionToken,
  MAX_SESSION_TOKEN_CHARS,
  MAX_SESSION_TTL_MS,
  serializeSessionCookie,
  verifySessionToken,
} from "./session";

const secret = "s".repeat(32);
const now = Date.UTC(2026, 7, 8, 12);

describe("dashboard sessions", () => {
  it("signs a payload containing tenant, scopes, and expiry", () => {
    const token = createSessionToken(
      {
        tenantId: "tenant_01",
        scopes: ["dashboard:read", "consent:write"],
        expiresAt: now + 60_000,
      },
      secret,
      { now },
    );
    const encodedPayload = token.split(".")[1];
    const wirePayload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf8"),
    );

    expect(wirePayload).toEqual({
      v: 2,
      tenant_id: "tenant_01",
      scopes: ["dashboard:read", "consent:write"],
      iat: now,
      exp: now + 60_000,
    });
    expect(verifySessionToken(token, secret, { now })).toEqual({
      tenantId: "tenant_01",
      scopes: ["dashboard:read", "consent:write"],
      issuedAt: now,
      expiresAt: now + 60_000,
    });
  });

  it("rejects tampered, expired, malformed, and wrong-secret tokens", () => {
    const token = createSessionToken(
      { tenantId: "tenant_01", scopes: [], expiresAt: now + 1_000 },
      secret,
      { now },
    );
    const tampered = `${token.slice(0, -1)}${token.endsWith("a") ? "b" : "a"}`;

    expect(verifySessionToken(tampered, secret, { now })).toBeNull();
    expect(verifySessionToken(token, "x".repeat(32), { now })).toBeNull();
    expect(verifySessionToken(token, secret, { now: now + 1_000 })).toBeNull();
    expect(verifySessionToken("garbage", secret, { now })).toBeNull();
  });

  it("rejects a non-canonical alias of an otherwise valid signature", () => {
    const token = createSessionToken(
      { tenantId: "tenant_01", scopes: [], expiresAt: now + 1_000 },
      secret,
      { now },
    );
    const parts = token.split(".");
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const lastIndex = alphabet.indexOf(parts[2].at(-1)!);
    parts[2] = `${parts[2].slice(0, -1)}${alphabet[lastIndex + 1]}`;

    expect(Buffer.from(parts[2], "base64url")).toEqual(
      Buffer.from(token.split(".")[2], "base64url"),
    );
    expect(verifySessionToken(parts.join("."), secret, { now })).toBeNull();
  });

  it("serializes a host-only, secure, HTTP-only cookie", () => {
    const token = createSessionToken(
      { tenantId: "tenant_01", scopes: [], expiresAt: now + 60_000 },
      secret,
      { now },
    );
    const cookie = serializeSessionCookie(token, secret, { now });

    expect(cookie).toContain("__Host-opt_in_vault_session=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("Max-Age=60");
    expect(cookie).not.toContain("Domain=");
  });

  it("enforces a signed short lifetime and derives cookie lifetime from the token", () => {
    expect(() =>
      createSessionToken(
        { tenantId: "tenant_01", scopes: [], expiresAt: now + MAX_SESSION_TTL_MS + 1 },
        secret,
        { now },
      ),
    ).toThrow(/lifetime/i);

    const token = createSessionToken(
      { tenantId: "tenant_01", scopes: [], expiresAt: now + 90_000 },
      secret,
      { now },
    );
    expect(serializeSessionCookie(token, secret, { now })).toContain("Max-Age=90");
    expect(verifySessionToken(token, secret, { now: now + 90_000 })).toBeNull();
  });

  it("never creates a token that its own verifier or cookie boundary rejects", () => {
    const oversizedScopes = Array.from({ length: 64 }, (_, index) =>
      (`scope${index}:` + "x".repeat(100)).slice(0, 100),
    );

    expect(() =>
      createSessionToken(
        { tenantId: "tenant_01", scopes: oversizedScopes, expiresAt: now + 60_000 },
        secret,
        { now },
      ),
    ).toThrow(/large/i);

    const token = createSessionToken(
      { tenantId: "tenant_01", scopes: [], expiresAt: now + 60_000 },
      secret,
      { now },
    );
    expect(token.length).toBeLessThanOrEqual(MAX_SESSION_TOKEN_CHARS);
    expect(verifySessionToken(token, secret, { now })).not.toBeNull();
  });

  it("fails closed for invalid injected clocks", () => {
    const token = createSessionToken(
      { tenantId: "tenant_01", scopes: [], expiresAt: now + 60_000 },
      secret,
      { now },
    );

    expect(verifySessionToken(token, secret, { now: Number.NaN })).toBeNull();
    expect(() => serializeSessionCookie(token, secret, { now: Number.NaN })).toThrow(/time/i);
    expect(() =>
      createSessionToken(
        { tenantId: "tenant_01", scopes: [], expiresAt: now + 60_000 },
        secret,
        { now: Number.NaN },
      ),
    ).toThrow(/time/i);
  });
});
