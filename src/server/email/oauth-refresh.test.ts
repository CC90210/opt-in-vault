import {
  OAuthAccessTokenError,
  resolveOAuthAccessToken,
} from "./oauth-refresh";

describe("bounded OAuth access-token resolution", () => {
  it.each([
    [
      "google",
      "smtp",
      "https://oauth2.googleapis.com/token",
      null,
    ],
    [
      "microsoft",
      "smtp",
      "https://login.microsoftonline.com/common/oauth2/v2.0/token",
      "https://outlook.office.com/SMTP.Send offline_access",
    ],
    [
      "microsoft",
      "imap",
      "https://login.microsoftonline.com/common/oauth2/v2.0/token",
      "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
    ],
  ] as const)(
    "refreshes %s %s grants through the fixed provider endpoint",
    async (provider, purpose, expectedEndpoint, expectedScope) => {
      const fetchImpl = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ access_token: "fresh-access-token" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );

      await expect(
        resolveOAuthAccessToken({
          provider,
          purpose,
          credentials: {
            clientId: "client-id",
            clientSecret: "client-secret",
            refreshToken: "refresh-token",
            accessToken: "stale-access-token",
          },
          fetchImpl,
        }),
      ).resolves.toBe("fresh-access-token");

      expect(fetchImpl).toHaveBeenCalledTimes(1);
      const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(expectedEndpoint);
      expect(init).toMatchObject({
        method: "POST",
        redirect: "error",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json",
        },
      });
      expect(init.signal).toBeInstanceOf(AbortSignal);
      const body = new URLSearchParams(String(init.body));
      expect(body.get("grant_type")).toBe("refresh_token");
      expect(body.get("client_id")).toBe("client-id");
      expect(body.get("client_secret")).toBe("client-secret");
      expect(body.get("refresh_token")).toBe("refresh-token");
      expect(body.get("scope")).toBe(expectedScope);
    },
  );

  it("uses a bounded stored access token when no complete refresh grant exists", async () => {
    const fetchImpl = vi.fn();

    await expect(
      resolveOAuthAccessToken({
        provider: "google",
        purpose: "imap",
        credentials: {
          clientId: "partial-client-id",
          accessToken: "stored-access-token",
        },
        fetchImpl,
      }),
    ).resolves.toBe("stored-access-token");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it.each([
    new Response("x", {
      status: 200,
      headers: { "content-length": "65537" },
    }),
    new Response(JSON.stringify({ access_token: "x".repeat(16_385) }), {
      status: 200,
    }),
  ])("fails closed on oversized provider material", async (response) => {
    await expect(
      resolveOAuthAccessToken({
        provider: "google",
        purpose: "smtp",
        credentials: {
          clientId: "client-id",
          clientSecret: "client-secret",
          refreshToken: "refresh-token",
        },
        fetchImpl: vi.fn().mockResolvedValue(response),
      }),
    ).rejects.toMatchObject({ code: "oauth_refresh_failed" });
  });

  it("caps its abort deadline at ten seconds and exposes no provider secret", async () => {
    vi.useFakeTimers();
    try {
      const fetchImpl = vi.fn(
        (_url: string | URL | Request, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () => {
              reject(new Error("client_secret=must-not-leak"));
            });
          }),
      );
      const pending = resolveOAuthAccessToken({
        provider: "google",
        purpose: "imap",
        credentials: {
          clientId: "client-id",
          clientSecret: "client-secret",
          refreshToken: "refresh-token",
        },
        fetchImpl,
        timeoutMs: 60_000,
      });
      const rejection = expect(pending).rejects.toEqual(
        expect.objectContaining({
          name: "OAuthAccessTokenError",
          code: "oauth_refresh_failed",
          message: "OAuth access token is unavailable",
        }),
      );

      await vi.advanceTimersByTimeAsync(9_999);
      expect(fetchImpl.mock.calls[0]?.[1]?.signal?.aborted).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await rejection;
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects missing credentials with a stable secret-free error", async () => {
    await expect(
      resolveOAuthAccessToken({
        provider: "microsoft",
        purpose: "imap",
        credentials: {},
        fetchImpl: vi.fn(),
      }),
    ).rejects.toEqual(
      new OAuthAccessTokenError("oauth_credentials_missing"),
    );
  });
});
