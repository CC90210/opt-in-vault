import { createDispatchHandler } from "./handler";

const CRON_SECRET = "dispatch-test-secret-that-is-32-bytes-minimum";

describe("dispatch cron route", () => {
  it("fails closed when cron authorization or its configured secret is absent", async () => {
    const runCycle = vi.fn();
    const handler = createDispatchHandler({
      configuredSecret: () => CRON_SECRET,
      runCycle,
    });

    const missing = await handler(
      new Request("https://vault.example/api/v1/cron/dispatch", {
        method: "POST",
      }),
    );
    const wrong = await handler(
      new Request("https://vault.example/api/v1/cron/dispatch", {
        method: "POST",
        headers: { authorization: `Bearer ${"x".repeat(32)}` },
      }),
    );
    const noConfiguration = await createDispatchHandler({
      configuredSecret: () => undefined,
      runCycle,
    })(
      new Request("https://vault.example/api/v1/cron/dispatch", {
        method: "POST",
        headers: { authorization: `Bearer ${CRON_SECRET}` },
      }),
    );

    expect([missing.status, wrong.status, noConfiguration.status]).toEqual([
      401, 401, 401,
    ]);
    expect(runCycle).not.toHaveBeenCalled();
  });

  it("runs one bounded cycle for an authorized caller", async () => {
    const summary = {
      claimed: 2,
      accepted: 1,
      dryRun: 1,
      rejected: 0,
      unknown: 0,
      blocked: 0,
      deferred: 0,
      errors: [],
    };
    const runCycle = vi.fn().mockResolvedValue(summary);
    const handler = createDispatchHandler({
      configuredSecret: () => CRON_SECRET,
      runCycle,
      maxBatchSize: 25,
    });

    const response = await handler(
      new Request(
        "https://vault.example/api/v1/cron/dispatch?limit=999",
        {
          method: "POST",
          headers: { authorization: `Bearer ${CRON_SECRET}` },
        },
      ),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(response.json()).resolves.toEqual(summary);
    expect(runCycle).toHaveBeenCalledOnce();
    expect(runCycle).toHaveBeenCalledWith({ limit: 25 });
  });

  it("returns a non-secret diagnostic when dispatch fails", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const handler = createDispatchHandler({
      configuredSecret: () => CRON_SECRET,
      runCycle: vi.fn().mockRejectedValue(new Error("secret database detail")),
    });

    const response = await handler(
      new Request("https://vault.example/api/v1/cron/dispatch", {
        method: "POST",
        headers: { authorization: `Bearer ${CRON_SECRET}` },
      }),
    );

    expect(response.status).toBe(503);
    const body = await response.text();
    expect(JSON.parse(body)).toEqual({ error: "dispatch_unavailable" });
    expect(body).not.toContain("secret database detail");
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });
});
