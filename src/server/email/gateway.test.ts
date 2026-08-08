import {
  DeliveryRejectedError,
  DeliveryUncertainError,
  createGatewayTransport,
  sendViaGateway,
  type GatewayTransport,
} from "./gateway";

const baseMessage = {
  from: { address: "sender@example.com", name: "Sender" },
  to: "person@example.net",
  subject: "A useful subject",
  text: "Hello\n\nUnsubscribe: https://vault.example/u",
  html: "<p>Hello</p><p><a href=\"https://vault.example/u\">Unsubscribe</a></p>",
  messageId: "<job-1@example.com>",
  unsubscribeUrl:
    "https://vault.example/api/v1/unsubscribe?token=ouv_unsub_token",
};

describe("outbound email gateway", () => {
  it("connects Nodemailer to a pinned IP while preserving the original TLS identity", async () => {
    const transport: GatewayTransport = { sendMail: vi.fn() };
    const createTransport = vi.fn().mockReturnValue(transport);
    const resolveTarget = vi.fn().mockResolvedValue({
      hostname: "smtp.example.com",
      tlsServername: "smtp.example.com",
      port: 587,
      connectionAddress: "93.184.216.34",
      addresses: ["93.184.216.34"],
    });

    await expect(
      createGatewayTransport(
        {
          provider: "smtp",
          host: "smtp.example.com",
          port: 587,
          secure: false,
          username: "sender@example.com",
          password: "secret",
        },
        { resolveTarget: resolveTarget as never, createTransport },
      ),
    ).resolves.toBe(transport);
    expect(createTransport).toHaveBeenCalledWith(
      expect.objectContaining({
        host: "93.184.216.34",
        requireTLS: true,
        opportunisticTLS: false,
        socketTimeout: 45_000,
        tls: expect.objectContaining({
          servername: "smtp.example.com",
          rejectUnauthorized: true,
        }),
      }),
    );
  });

  it("bounds DNS resolution before any transport is constructed", async () => {
    const createTransport = vi.fn();
    await expect(
      createGatewayTransport(
        {
          provider: "smtp",
          host: "smtp.example.com",
          port: 587,
          secure: false,
          username: "sender@example.com",
          password: "secret",
        },
        {
          resolveTarget: vi.fn(() => new Promise(() => {})) as never,
          createTransport,
          resolveTimeoutMs: 5,
        },
      ),
    ).rejects.toMatchObject({ code: "smtp_dns_timeout" });
    expect(createTransport).not.toHaveBeenCalled();
  });

  it("defaults to dry-run and never calls the transport", async () => {
    const transport: GatewayTransport = { sendMail: vi.fn() };
    const result = await sendViaGateway(baseMessage, {
      liveSendsEnabled: false,
      transport,
    });

    expect(result).toEqual({ status: "dry_run" });
    expect(transport.sendMail).not.toHaveBeenCalled();
  });

  it("injects exact RFC 8058 headers on an explicitly enabled send", async () => {
    const sendMail = vi.fn().mockResolvedValue({
      messageId: "provider-id",
      accepted: ["person@example.net"],
      rejected: [],
      response: "250 accepted",
    });
    const result = await sendViaGateway(baseMessage, {
      liveSendsEnabled: true,
      transport: { sendMail },
    });

    expect(result).toEqual({
      status: "accepted",
      providerMessageId: "provider-id",
      response: "250 accepted",
    });
    expect(sendMail).toHaveBeenCalledWith(
      expect.objectContaining({
        messageId: "<job-1@example.com>",
        headers: {
          "List-Unsubscribe":
            "<https://vault.example/api/v1/unsubscribe?token=ouv_unsub_token>",
          "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        },
      }),
    );
  });

  it("separates definitive rejection from uncertain delivery and never retries internally", async () => {
    const rejected = Object.assign(new Error("Mailbox unavailable"), {
      responseCode: 550,
      code: "EENVELOPE",
    });
    const uncertain = Object.assign(new Error("Socket closed"), {
      code: "ECONNRESET",
    });

    await expect(
      sendViaGateway(baseMessage, {
        liveSendsEnabled: true,
        transport: { sendMail: vi.fn().mockRejectedValue(rejected) },
      }),
    ).rejects.toBeInstanceOf(DeliveryRejectedError);
    await expect(
      sendViaGateway(baseMessage, {
        liveSendsEnabled: true,
        transport: { sendMail: vi.fn().mockRejectedValue(uncertain) },
      }),
    ).rejects.toBeInstanceOf(DeliveryUncertainError);
  });

  it.each([
    ["ECONNREFUSED", "CONN"],
    ["ETLS", "CONN"],
    ["EAUTH", "AUTH"],
    ["EENVELOPE", "RCPT TO"],
  ])("treats known %s/%s pre-delivery failures as safely retryable", async (code, command) => {
    const failure = Object.assign(new Error("pre-delivery failure"), {
      code,
      command,
    });

    await expect(
      sendViaGateway(baseMessage, {
        liveSendsEnabled: true,
        transport: { sendMail: vi.fn().mockRejectedValue(failure) },
      }),
    ).rejects.toMatchObject({ name: "DeliveryRejectedError", code });
  });

  it("enforces a total send deadline, closes the transport, and quarantines the outcome", async () => {
    const close = vi.fn();
    const sendMail = vi.fn<GatewayTransport["sendMail"]>(
      () => new Promise(() => {}),
    );

    await expect(
      sendViaGateway(baseMessage, {
        liveSendsEnabled: true,
        transport: { sendMail, close },
        deadlineMs: 5,
      }),
    ).rejects.toMatchObject({
      name: "DeliveryUncertainError",
      code: "smtp_total_timeout",
    });
    expect(close).toHaveBeenCalledOnce();
  });

  it("quarantines resolved provider responses that confirm neither acceptance nor rejection", async () => {
    await expect(
      sendViaGateway(baseMessage, {
        liveSendsEnabled: true,
        transport: {
          sendMail: vi.fn().mockResolvedValue({ accepted: [], rejected: [] }),
        },
      }),
    ).rejects.toBeInstanceOf(DeliveryUncertainError);
    await expect(
      sendViaGateway(baseMessage, {
        liveSendsEnabled: true,
        transport: {
          sendMail: vi.fn().mockResolvedValue({
            accepted: ["someone-else@example.net"],
            rejected: [],
          }),
        },
      }),
    ).rejects.toBeInstanceOf(DeliveryUncertainError);
  });

  it("rejects display-name/header injection before transport", async () => {
    const transport: GatewayTransport = { sendMail: vi.fn() };
    await expect(
      sendViaGateway(
        { ...baseMessage, from: { ...baseMessage.from, name: "Sender\r\nBcc: victim@example.net" } },
        { liveSendsEnabled: true, transport },
      ),
    ).rejects.toThrow(/display name/i);
    expect(transport.sendMail).not.toHaveBeenCalled();
  });
});
