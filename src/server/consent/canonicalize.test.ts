import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import {
  canonicalizeJson,
  hashCanonicalEvidence,
  signCanonicalEvidence,
  verifyCanonicalEvidence,
} from "./canonicalize";

describe("canonical consent evidence", () => {
  it("serializes JSON deterministically without mutating the source", () => {
    const source = {
      z: 3,
      nested: { beta: true, alpha: ["x", null, 1] },
      a: "first",
    };

    const canonical = canonicalizeJson(source);

    expect(canonical).toBe(
      '{"a":"first","nested":{"alpha":["x",null,1],"beta":true},"z":3}',
    );
    expect(Object.keys(source)).toEqual(["z", "nested", "a"]);
  });

  it("rejects non-JSON, lossy, cyclic, and unsafe values", () => {
    expect(() => canonicalizeJson({ bad: undefined })).toThrow(/JSON/i);
    expect(() => canonicalizeJson({ bad: Number.NaN })).toThrow(/finite/i);
    expect(() => canonicalizeJson({ bad: 9_007_199_254_740_992 })).toThrow(/safe/i);
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalizeJson(cyclic)).toThrow(/cyclic/i);
  });

  it("hashes and signs the exact canonical bytes with a versioned HMAC", () => {
    const canonical = canonicalizeJson({ consent: true, version: "2026-08" });
    const secret = "s".repeat(32);
    const hash = hashCanonicalEvidence(canonical);
    const signature = signCanonicalEvidence(canonical, secret, 7);

    expect(hash).toMatch(/^[a-f0-9]{64}$/);
    expect(signature).toMatch(/^[a-f0-9]{64}$/);
    expect(verifyCanonicalEvidence(canonical, hash, signature, secret, 7)).toBe(true);
    expect(
      verifyCanonicalEvidence(`${canonical} `, hash, signature, secret, 7),
    ).toBe(false);
    expect(verifyCanonicalEvidence(canonical, hash, signature, secret, 8)).toBe(false);
  });
});
