import { parseInboundSource } from "./parse";

describe("raw inbound parser", () => {
  it("extracts bounded reply metadata without rendering remote HTML", async () => {
    const source = Buffer.from(
      [
        "From: Person <person@example.net>",
        "To: sender@example.com",
        "Subject: Re: Hello",
        "Message-ID: <incoming@example.net>",
        "In-Reply-To: <outbound@example.com>",
        "References: <older@example.com> <outbound@example.com>",
        "Auto-Submitted: no",
        "Content-Type: text/plain; charset=utf-8",
        "",
        "Yes, let's talk.",
      ].join("\r\n"),
    );

    await expect(parseInboundSource(source)).resolves.toMatchObject({
      messageId: "<incoming@example.net>",
      inReplyTo: "<outbound@example.com>",
      references: ["<older@example.com>", "<outbound@example.com>"],
      fromAddress: "person@example.net",
      subject: "Re: Hello",
      text: "Yes, let's talk.",
      headers: { "auto-submitted": "no" },
    });
  });

  it("rejects missing senders and sources over the bounded raw limit", async () => {
    await expect(
      parseInboundSource(Buffer.from("Subject: Missing sender\r\n\r\nBody")),
    ).rejects.toThrow(/sender/i);
    await expect(parseInboundSource(Buffer.alloc(1_000_001))).rejects.toThrow(/size/i);
  });

  it("extracts structured DSN fields and truncates a hostile text body", async () => {
    const source = Buffer.from(
      [
        "From: Mail Delivery System <mailer-daemon@example.net>",
        "To: sender@example.com",
        "Subject: Delivery Status Notification",
        "Auto-Submitted: auto-generated",
        "Content-Type: multipart/report; report-type=delivery-status; boundary=dsn",
        "",
        "--dsn",
        "Content-Type: text/plain; charset=utf-8",
        "",
        "Delivery failed.",
        "--dsn",
        "Content-Type: message/delivery-status",
        "",
        "Reporting-MTA: dns; example.net",
        "",
        "Final-Recipient: rfc822; person@example.net",
        "Original-Message-ID: <outbound@example.com>",
        "Action: failed",
        "Status: 5.1.1",
        "--dsn--",
      ].join("\r\n"),
    );

    await expect(parseInboundSource(source)).resolves.toMatchObject({
      dsn: {
        originalMessageId: "<outbound@example.com>",
        finalRecipient: "person@example.net",
        action: "failed",
        status: "5.1.1",
      },
    });

    const largeBody = "x".repeat(300_000);
    const parsed = await parseInboundSource(
      Buffer.from(
        `From: Person <person@example.net>\r\nSubject: Re: Hello\r\nContent-Type: text/plain\r\n\r\n${largeBody}`,
      ),
    );
    expect(parsed.text.length).toBe(256_000);
    expect(parsed.textTruncated).toBe(true);
  });
});
