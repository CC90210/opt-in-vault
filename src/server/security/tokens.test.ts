import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import {
  createOpaqueToken,
  hashOpaqueToken,
  hashOpaqueTokenCandidates,
  MAX_OPAQUE_TOKEN_KEY_VERSIONS,
  verifyOpaqueTokenHash,
  verifyOpaqueToken,
} from "./tokens";

const signingSecret = "t".repeat(32);
const signingSecrets = new Map([["sig-1", signingSecret]]);
const now = Date.UTC(2026, 7, 8, 12);

const binding = {
  purpose: "unsubscribe",
  tenantId: "tenant_01",
  resourceId: "lead_01",
} as const;

describe("opaque signed tokens", () => {
  it("creates a random token that does not disclose its binding", () => {
    const token = createOpaqueToken({
      ...binding,
      signingSecret,
      signingKeyVersion: "sig-1",
      expiresAt: now + 60_000,
      now,
    });

    expect(token).toMatch(
      /^oiv2\.sig-1\.[a-z0-9]+\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/,
    );
    expect(token).not.toContain(binding.tenantId);
    expect(token).not.toContain(binding.resourceId);
    expect(token).not.toContain(binding.purpose);
    expect(
      verifyOpaqueToken(token, { ...binding, signingSecrets, now }),
    ).toBe(true);
  });

  it("rejects expiry, tampering, wrong purpose, tenant, resource, and secret", () => {
    const token = createOpaqueToken({
      ...binding,
      signingSecret,
      signingKeyVersion: "sig-1",
      expiresAt: now + 1_000,
      now,
    });
    const tampered = `${token.slice(0, -1)}${token.endsWith("a") ? "b" : "a"}`;

    expect(verifyOpaqueToken(token, { ...binding, signingSecrets, now: now + 1_000 })).toBe(
      false,
    );
    expect(verifyOpaqueToken(tampered, { ...binding, signingSecrets, now })).toBe(false);
    expect(
      verifyOpaqueToken(token, { ...binding, purpose: "certificate", signingSecrets, now }),
    ).toBe(false);
    expect(
      verifyOpaqueToken(token, { ...binding, tenantId: "tenant_02", signingSecrets, now }),
    ).toBe(false);
    expect(
      verifyOpaqueToken(token, { ...binding, resourceId: "lead_02", signingSecrets, now }),
    ).toBe(false);
    expect(
      verifyOpaqueToken(token, {
        ...binding,
        signingSecrets: new Map([["sig-1", "x".repeat(32)]]),
        now,
      }),
    ).toBe(false);
  });

  it("rejects a non-canonical alias of an otherwise valid signature", () => {
    const token = createOpaqueToken({
      ...binding,
      signingSecret,
      signingKeyVersion: "sig-1",
      expiresAt: now + 1_000,
      now,
    });
    const parts = token.split(".");
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const lastIndex = alphabet.indexOf(parts[4].at(-1)!);
    parts[4] = `${parts[4].slice(0, -1)}${alphabet[lastIndex + 1]}`;

    expect(Buffer.from(parts[4], "base64url")).toEqual(
      Buffer.from(token.split(".")[4], "base64url"),
    );
    expect(
      verifyOpaqueToken(parts.join("."), { ...binding, signingSecrets, now }),
    ).toBe(false);
  });

  it("provides versioned peppered hashes and bounded lookup candidates", () => {
    const token = createOpaqueToken({
      ...binding,
      signingSecret,
      signingKeyVersion: "sig-1",
      expiresAt: now + 60_000,
      now,
    });
    const oldPepper = "h".repeat(32);
    const newPepper = "n".repeat(32);
    const hash = hashOpaqueToken(token, oldPepper, "hash-1");

    expect(hash).toMatch(/^oivh1\.hash-1\.[a-f0-9]{64}$/);
    expect(hashOpaqueToken(token, oldPepper, "hash-1")).toBe(hash);
    expect(hash).not.toContain(token);
    expect(
      hashOpaqueTokenCandidates(
        token,
        new Map([
          ["hash-2", newPepper],
          ["hash-1", oldPepper],
        ]),
      ),
    ).toContain(hash);
    expect(
      verifyOpaqueTokenHash(
        token,
        hash,
        new Map([
          ["hash-2", newPepper],
          ["hash-1", oldPepper],
        ]),
      ),
    ).toBe(true);
  });

  it("selects signing secrets by authenticated version and rejects oversized rings", () => {
    const rotatedSecret = "r".repeat(32);
    const token = createOpaqueToken({
      ...binding,
      signingSecret: rotatedSecret,
      signingKeyVersion: "sig-2",
      expiresAt: now + 60_000,
      now,
    });

    expect(
      verifyOpaqueToken(token, {
        ...binding,
        signingSecrets: new Map([
          ["sig-1", signingSecret],
          ["sig-2", rotatedSecret],
        ]),
        now,
      }),
    ).toBe(true);
    expect(
      verifyOpaqueToken(token, { ...binding, signingSecrets, now }),
    ).toBe(false);

    const oversized = new Map(
      Array.from({ length: MAX_OPAQUE_TOKEN_KEY_VERSIONS + 1 }, (_, index) => [
        `sig-${index}`,
        `${index}`.repeat(32),
      ]),
    );
    expect(verifyOpaqueToken(token, { ...binding, signingSecrets: oversized, now })).toBe(
      false,
    );
  });

  it("fails closed for invalid injected clocks", () => {
    const token = createOpaqueToken({
      ...binding,
      signingSecret,
      signingKeyVersion: "sig-1",
      expiresAt: now + 60_000,
      now,
    });

    expect(
      verifyOpaqueToken(token, { ...binding, signingSecrets, now: Number.NaN }),
    ).toBe(false);
    expect(() =>
      createOpaqueToken({
        ...binding,
        signingSecret,
        signingKeyVersion: "sig-1",
        expiresAt: now + 60_000,
        now: Number.NaN,
      }),
    ).toThrow(/time/i);
  });
});
