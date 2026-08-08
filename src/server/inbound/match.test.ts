import { matchInboundReply } from "./match";

const candidates = [
  {
    tenantId: "tenant-a",
    outboundMessageId: "out-1",
    messageId: "<message-1@example.com>",
    enrollmentId: "enrollment-1",
    leadId: "lead-1",
    recipientAddress: "person@example.net",
  },
  {
    tenantId: "tenant-a",
    outboundMessageId: "out-2",
    messageId: "<message-2@example.com>",
    enrollmentId: "enrollment-2",
    leadId: "lead-2",
    recipientAddress: "other@example.net",
  },
];

describe("inbound reply matching", () => {
  it("prioritizes In-Reply-To and References over sender fallback", () => {
    expect(
      matchInboundReply(
        {
          tenantId: "tenant-a",
          inReplyTo: "<message-1@example.com>",
          references: ["<message-2@example.com>"],
          fromAddress: "other@example.net",
        },
        candidates,
      ),
    ).toMatchObject({ outboundMessageId: "out-1", matchedBy: "in_reply_to" });
  });

  it("uses the newest matching reference and an unambiguous sender only", () => {
    expect(
      matchInboundReply(
        {
          tenantId: "tenant-a",
          references: ["<message-1@example.com>", "<message-2@example.com>"],
          fromAddress: "nobody@example.net",
        },
        candidates,
      ),
    ).toMatchObject({ outboundMessageId: "out-2", matchedBy: "references" });
    expect(
      matchInboundReply(
        { tenantId: "tenant-a", references: [], fromAddress: "person@example.net" },
        candidates,
      ),
    ).toMatchObject({ outboundMessageId: "out-1", matchedBy: "sender" });
  });

  it("fails closed on ambiguous sender fallback or another tenant", () => {
    const duplicated = [
      ...candidates,
      { ...candidates[0], outboundMessageId: "out-3", enrollmentId: "enrollment-3" },
    ];
    expect(
      matchInboundReply(
        { tenantId: "tenant-a", references: [], fromAddress: "person@example.net" },
        duplicated,
      ),
    ).toBeNull();
    expect(
      matchInboundReply(
        {
          tenantId: "tenant-b",
          inReplyTo: "<message-1@example.com>",
          references: [],
          fromAddress: "person@example.net",
        },
        candidates,
      ),
    ).toBeNull();
  });

  it("matches standards-based DSNs by original message id before final recipient", () => {
    expect(
      matchInboundReply(
        {
          tenantId: "tenant-a",
          references: [],
          fromAddress: "mailer-daemon@example.net",
          dsnOriginalMessageId: "<message-1@example.com>",
          dsnFinalRecipient: "other@example.net",
        },
        candidates,
      ),
    ).toMatchObject({ outboundMessageId: "out-1", matchedBy: "dsn_message_id" });
    expect(
      matchInboundReply(
        {
          tenantId: "tenant-a",
          references: [],
          fromAddress: "mailer-daemon@example.net",
          dsnFinalRecipient: "other@example.net",
        },
        candidates,
      ),
    ).toMatchObject({ outboundMessageId: "out-2", matchedBy: "dsn_recipient" });
  });
});
