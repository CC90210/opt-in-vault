import nextConfig from "../next.config";

async function headersForEnvironment(environment: "test" | "production") {
  vi.stubEnv("NODE_ENV", environment);
  const rules = await nextConfig.headers?.();
  vi.unstubAllEnvs();
  expect(rules).toHaveLength(1);
  return new Map(rules![0].headers.map(({ key, value }) => [key, value]));
}

describe("global response security headers", () => {
  it("prevents framing, cross-origin form actions, sniffing, and ambient browser access", async () => {
    const headers = await headersForEnvironment("test");

    expect(headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
    expect(headers.get("Content-Security-Policy")).toContain("form-action 'self'");
    expect(headers.get("X-Frame-Options")).toBe("DENY");
    expect(headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(headers.get("Permissions-Policy")).toContain("camera=()");
    expect(headers.get("Content-Security-Policy")).toContain("'unsafe-eval'");
    expect(headers.get("Content-Security-Policy")).toContain("connect-src 'self' ws: wss:");
  });

  it("adds HSTS only to production responses", async () => {
    const developmentHeaders = await headersForEnvironment("test");
    const productionHeaders = await headersForEnvironment("production");

    expect(developmentHeaders.has("Strict-Transport-Security")).toBe(false);
    expect(productionHeaders.get("Strict-Transport-Security")).toBe(
      "max-age=31536000",
    );
    expect(productionHeaders.get("Content-Security-Policy")).not.toContain("'unsafe-eval'");
    expect(productionHeaders.get("Content-Security-Policy")).not.toContain("ws: wss:");
  });
});
