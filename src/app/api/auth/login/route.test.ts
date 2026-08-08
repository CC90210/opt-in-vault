import { createLoginHandler } from "./handler";

const RAW_KEY = `oiv_sk_${"a".repeat(43)}`;

describe("dashboard login route", () => {
  it("exchanges a valid same-origin API key for a host-only session cookie", async () => {
    const exchangeApiKey = vi.fn().mockResolvedValue(
      "__Host-opt_in_vault_session=signed; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax",
    );
    const handler = createLoginHandler({ exchangeApiKey });
    const response = await handler(
      formRequest(RAW_KEY, { origin: "https://vault.example" }),
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/dashboard");
    expect(response.headers.get("set-cookie")).toContain(
      "__Host-opt_in_vault_session=signed",
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(exchangeApiKey).toHaveBeenCalledWith(RAW_KEY);
  });

  it("fails closed for invalid credentials without echoing the submitted key", async () => {
    const handler = createLoginHandler({
      exchangeApiKey: vi.fn().mockResolvedValue(null),
    });
    const response = await handler(
      formRequest(RAW_KEY, { origin: "https://vault.example" }),
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(
      "/login?error=invalid",
    );
    expect(await response.text()).not.toContain(RAW_KEY);
    expect(response.headers.get("set-cookie")).toBeNull();
  });

  it("rejects cross-origin and malformed submissions before authentication", async () => {
    const exchangeApiKey = vi.fn();
    const handler = createLoginHandler({ exchangeApiKey });
    const crossOrigin = await handler(
      formRequest(RAW_KEY, { origin: "https://attacker.example" }),
    );
    const malformed = await handler(
      formRequest("not-a-key", { origin: "https://vault.example" }),
    );

    expect(crossOrigin.status).toBe(403);
    expect(malformed.status).toBe(303);
    expect(exchangeApiKey).not.toHaveBeenCalled();
  });

  it("requires an explicit same-origin browser signal", async () => {
    const exchangeApiKey = vi.fn();
    const handler = createLoginHandler({ exchangeApiKey });

    const response = await handler(formRequest(RAW_KEY, {}));

    expect(response.status).toBe(403);
    expect(exchangeApiKey).not.toHaveBeenCalled();
  });

  it("bounds undeclared and malformed request bodies before parsing credentials", async () => {
    const exchangeApiKey = vi.fn();
    const handler = createLoginHandler({ exchangeApiKey });
    const oversized = await handler(
      new Request("https://vault.example/api/auth/login", {
        method: "POST",
        headers: {
          origin: "https://vault.example",
          "content-type": "application/x-www-form-urlencoded",
        },
        body: `apiKey=${"a".repeat(100_000)}`,
      }),
    );
    const malformedLength = await handler(
      formRequest(RAW_KEY, {
        origin: "https://vault.example",
        "content-length": "-1",
      }),
    );

    expect(oversized.status).toBe(413);
    expect(malformedLength.status).toBe(400);
    expect(exchangeApiKey).not.toHaveBeenCalled();
  });

  it("rejects media-type prefix lookalikes and never emits an absolute redirect", async () => {
    const exchangeApiKey = vi.fn().mockResolvedValue("session=value");
    const handler = createLoginHandler({ exchangeApiKey });
    const lookalike = await handler(
      new Request("https://vault.example/api/auth/login", {
        method: "POST",
        headers: {
          origin: "https://vault.example",
          "content-type": "application/x-www-form-urlencoded.evil",
        },
        body: new URLSearchParams({ apiKey: RAW_KEY }),
      }),
    );
    const poisonedHost = await handler(
      formRequest(RAW_KEY, { origin: "https://attacker-controlled.example" },
        "https://attacker-controlled.example/api/auth/login"),
    );

    expect(lookalike.status).toBe(415);
    expect(poisonedHost.headers.get("location")).toBe("/dashboard");
  });
});

function formRequest(
  apiKey: string,
  headers: Record<string, string>,
  url = "https://vault.example/api/auth/login",
): Request {
  return new Request(url, {
    method: "POST",
    headers: {
      ...headers,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ apiKey }),
  });
}
