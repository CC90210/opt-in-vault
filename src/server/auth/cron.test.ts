import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { isCronAuthorized } from "./cron";

const secret = "c".repeat(32);

describe("cron authorization", () => {
  it("accepts only an exact bearer secret", () => {
    expect(isCronAuthorized(`Bearer ${secret}`, secret)).toBe(true);
    expect(isCronAuthorized(`bearer ${secret}`, secret)).toBe(true);
    expect(isCronAuthorized("Bearer wrong-secret", secret)).toBe(false);
    expect(isCronAuthorized(`Basic ${secret}`, secret)).toBe(false);
    expect(isCronAuthorized(`Bearer ${secret} extra`, secret)).toBe(false);
  });

  it("fails closed when configuration or the header is absent", () => {
    expect(isCronAuthorized(`Bearer ${secret}`, undefined)).toBe(false);
    expect(isCronAuthorized(`Bearer ${secret}`, "")).toBe(false);
    expect(isCronAuthorized(null, secret)).toBe(false);
    expect(isCronAuthorized(undefined, secret)).toBe(false);
    expect(isCronAuthorized("Bearer x", "x")).toBe(false);
  });

  it("rejects line breaks in the authorization value", () => {
    expect(isCronAuthorized(`Bearer ${secret}\r\nX-Evil: yes`, secret)).toBe(false);
  });
});
