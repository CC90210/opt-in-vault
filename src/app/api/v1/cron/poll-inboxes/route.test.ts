import { createPollInboxesHandler } from "./handler";

const CRON_SECRET = "poll-test-secret-that-is-at-least-32-bytes";

describe("poll inboxes cron route", () => {
  it("fails closed before invoking work when cron authorization is invalid", async () => {
    const poll = vi.fn();
    const handler = createPollInboxesHandler({ configuredSecret: CRON_SECRET, poll });
    const response = await handler(
      new Request("https://vault.example/api/v1/cron/poll-inboxes", {
        method: "POST",
        headers: { authorization: "Bearer wrong" },
      }),
    );
    expect(response.status).toBe(401);
    expect(poll).not.toHaveBeenCalled();
  });

  it("runs one bounded cycle for an exact bearer secret", async () => {
    const poll = vi.fn().mockResolvedValue({
      inboxesPolled: 2,
      messagesProcessed: 3,
      failures: 0,
    });
    const handler = createPollInboxesHandler({ configuredSecret: CRON_SECRET, poll });
    const response = await handler(
      new Request("https://vault.example/api/v1/cron/poll-inboxes", {
        method: "POST",
        headers: { authorization: `Bearer ${CRON_SECRET}` },
      }),
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ messagesProcessed: 3 });
    expect(poll).toHaveBeenCalledOnce();
  });
});
