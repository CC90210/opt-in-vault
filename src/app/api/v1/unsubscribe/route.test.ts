import { createUnsubscribeHandlers } from "./handler";

describe("RFC 8058 unsubscribe route", () => {
  const validToken = `ouv_unsub_${"a".repeat(43)}`;

  it("keeps GET non-mutating and returns a no-store confirmation page", async () => {
    const preview = vi.fn().mockResolvedValue({ status: "active" as const });
    const apply = vi.fn();
    const handlers = createUnsubscribeHandlers({ preview, apply });

    const response = await handlers.GET(
      new Request(`https://vault.example/api/v1/unsubscribe?token=${validToken}`),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("x-robots-tag")).toContain("noindex");
    await expect(response.text()).resolves.toContain("Confirm unsubscribe");
    expect(apply).not.toHaveBeenCalled();
  });

  it("accepts the exact RFC 8058 form field, applies once, and never redirects", async () => {
    const apply = vi.fn().mockResolvedValue({ status: "unsubscribed" as const });
    const handlers = createUnsubscribeHandlers({
      preview: vi.fn(),
      apply,
    });
    const body = new URLSearchParams({
      "List-Unsubscribe": "One-Click",
    });

    const response = await handlers.POST(
      new Request(
        `https://vault.example/api/v1/unsubscribe?token=${validToken}`,
        {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body,
        },
      ),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();
    expect(apply).toHaveBeenCalledTimes(1);
  });

  it("rejects invalid tokens and malformed one-click payloads without effects", async () => {
    const apply = vi.fn();
    const handlers = createUnsubscribeHandlers({
      preview: vi.fn().mockResolvedValue({ status: "invalid" as const }),
      apply,
    });

    const badToken = await handlers.GET(
      new Request("https://vault.example/api/v1/unsubscribe?token=bad"),
    );
    const badPost = await handlers.POST(
      new Request(
        `https://vault.example/api/v1/unsubscribe?token=${validToken}`,
        {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ "List-Unsubscribe": "No" }),
        },
      ),
    );

    expect(badToken.status).toBe(404);
    expect(badPost.status).toBe(400);
    expect(apply).not.toHaveBeenCalled();
  });

  it("rejects lookalike media types, extra fields, and oversized bodies", async () => {
    const apply = vi.fn();
    const handlers = createUnsubscribeHandlers({ preview: vi.fn(), apply });
    const url = `https://vault.example/api/v1/unsubscribe?token=${validToken}`;

    const lookalike = await handlers.POST(
      new Request(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded-evil" },
        body: "List-Unsubscribe=One-Click",
      }),
    );
    const extra = await handlers.POST(
      new Request(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
        body: "List-Unsubscribe=One-Click&extra=1",
      }),
    );
    const oversized = await handlers.POST(
      new Request(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: `List-Unsubscribe=One-Click&padding=${"x".repeat(256)}`,
      }),
    );

    expect([lookalike.status, extra.status, oversized.status]).toEqual([
      400, 400, 400,
    ]);
    expect(apply).not.toHaveBeenCalled();
  });
});
