import {
  pollImapMailbox,
  type ImapSession,
} from "./imap-client";

function fakeSession(options: {
  uidValidity: bigint;
  messages: Array<{ uid: number; source: Buffer; size?: number; modseq?: bigint }>;
}) {
  const release = vi.fn();
  const fetch = vi.fn(async function* () {
    for (const message of options.messages) yield { seq: message.uid, ...message };
  });
  const session = {
    mailbox: false as ImapSession["mailbox"],
    connect: vi.fn(),
    logout: vi.fn(),
    getMailboxLock: vi.fn(async () => {
      session.mailbox = {
        uidValidity: options.uidValidity,
        highestModseq: BigInt(99),
        exists: options.messages.length,
      };
      return { release };
    }),
    fetch,
  } satisfies ImapSession;
  return { session, fetch, release };
}

describe("bounded IMAP poller", () => {
  it("polls by UID in read-only mode and advances only processed messages", async () => {
    const { session, fetch, release } = fakeSession({
      uidValidity: BigInt(42),
      messages: [
        { uid: 11, source: Buffer.from("one") },
        { uid: 12, source: Buffer.from("two") },
      ],
    });
    const seen: number[] = [];

    const cursor = await pollImapMailbox(
      session,
      { mailbox: "INBOX", uidValidity: "42", lastUid: 10 },
      {
        maxMessages: 10,
        onMessage: async (message) => seen.push(message.uid),
        onOversized: vi.fn(),
      },
    );

    expect(session.getMailboxLock).toHaveBeenCalledWith(
      "INBOX",
      expect.objectContaining({ readOnly: true }),
    );
    expect(fetch).toHaveBeenCalledWith(
      "11:*",
      expect.objectContaining({ uid: true, source: expect.any(Object) }),
      { uid: true },
    );
    expect(seen).toEqual([11, 12]);
    expect(cursor).toEqual({ uidValidity: "42", lastUid: 12, highestModseq: "99" });
    expect(release).toHaveBeenCalledOnce();
    expect(session.logout).toHaveBeenCalledOnce();
  });

  it("resets to UID 1 after UIDVALIDITY changes and deduplicates later in storage", async () => {
    const { session, fetch } = fakeSession({
      uidValidity: BigInt(77),
      messages: [{ uid: 1, source: Buffer.from("new mailbox") }],
    });

    const cursor = await pollImapMailbox(
      session,
      { mailbox: "INBOX", uidValidity: "42", lastUid: 500 },
      { maxMessages: 10, onMessage: vi.fn(), onOversized: vi.fn() },
    );

    expect(fetch).toHaveBeenCalledWith("1:*", expect.anything(), { uid: true });
    expect(cursor.uidValidity).toBe("77");
    expect(cursor.lastUid).toBe(1);
  });

  it("bounds batches and routes oversized messages without parsing the body", async () => {
    const { session } = fakeSession({
      uidValidity: BigInt(42),
      messages: [
        { uid: 1, source: Buffer.alloc(1_000_001), size: 1_000_001 },
        { uid: 2, source: Buffer.from("ok") },
        { uid: 3, source: Buffer.from("not reached") },
      ],
    });
    const onMessage = vi.fn();
    const onOversized = vi.fn();

    const cursor = await pollImapMailbox(
      session,
      { mailbox: "INBOX", uidValidity: null, lastUid: 0 },
      { maxMessages: 2, onMessage, onOversized },
    );

    expect(onOversized).toHaveBeenCalledWith({ uid: 1, size: 1_000_001 });
    expect(onMessage).toHaveBeenCalledOnce();
    expect(cursor.lastUid).toBe(2);
  });

  it("stops cleanly at the poll deadline and returns the last durable UID", async () => {
    const { session } = fakeSession({
      uidValidity: BigInt(42),
      messages: [
        { uid: 1, source: Buffer.from("one") },
        { uid: 2, source: Buffer.from("two") },
      ],
    });
    const now = vi.fn().mockReturnValueOnce(100).mockReturnValue(200);
    const onMessage = vi.fn();
    const cursor = await pollImapMailbox(
      session,
      { mailbox: "INBOX", uidValidity: "42", lastUid: 0 },
      {
        maxMessages: 10,
        deadlineAt: 150,
        now,
        onMessage,
        onOversized: vi.fn(),
      },
    );

    expect(onMessage).toHaveBeenCalledOnce();
    expect(cursor.lastUid).toBe(1);
  });
});
