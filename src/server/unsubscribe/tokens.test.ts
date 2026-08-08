import {
  createUnsubscribeToken,
  hashUnsubscribeToken,
  isUnsubscribeTokenShape,
} from "./tokens";

describe("unsubscribe token primitives", () => {
  const tokenSecret = "test-only-unsubscribe-secret-with-enough-entropy";

  it("creates opaque high-entropy tokens and stores only a stable keyed hash", () => {
    const first = createUnsubscribeToken();
    const second = createUnsubscribeToken();

    expect(first).not.toBe(second);
    expect(first.length).toBeGreaterThanOrEqual(50);
    expect(isUnsubscribeTokenShape(first)).toBe(true);
    expect(hashUnsubscribeToken(first, tokenSecret)).toBe(
      hashUnsubscribeToken(first, tokenSecret),
    );
    expect(hashUnsubscribeToken(first, tokenSecret)).not.toContain(first);
    expect(hashUnsubscribeToken(second, tokenSecret)).not.toBe(
      hashUnsubscribeToken(first, tokenSecret),
    );
  });

  it("rejects malformed tokens before a database lookup", () => {
    expect(isUnsubscribeTokenShape("short")).toBe(false);
    expect(isUnsubscribeTokenShape("ouv_unsub_bad token")).toBe(false);
  });
});
