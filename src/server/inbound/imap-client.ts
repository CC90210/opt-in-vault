import "server-only";

import { ImapFlow } from "imapflow";

import { assertSafeEgressTarget } from "@/server/security/network";

const MAX_SOURCE_BYTES = 1_000_000;
const IMAP_TLS_PORTS = new Set([993]);
const MAX_IMAP_LINE_BYTES = 65_536;

export type ImapFetchMessage = {
  uid: number;
  source?: Buffer;
  size?: number;
  modseq?: bigint;
};

export type ImapSession = {
  mailbox:
    | false
    | {
        uidValidity: bigint;
        highestModseq?: bigint;
        exists: number;
      };
  connect(): Promise<void>;
  logout(): Promise<void>;
  getMailboxLock(
    path: string,
    options: { readOnly: true; acquireTimeout: number },
  ): Promise<{ release(): void }>;
  fetch(
    range: string,
    query: {
      uid: true;
      size: true;
      internalDate: true;
      source: { maxLength: number };
    },
    options: { uid: true },
  ): AsyncIterable<ImapFetchMessage>;
};

export type ImapCursor = {
  mailbox: string;
  uidValidity: string | null;
  lastUid: number;
};

export type ImapPollResult = {
  uidValidity: string;
  lastUid: number;
  highestModseq: string | null;
};

export async function pollImapMailbox(
  session: ImapSession,
  cursor: ImapCursor,
  options: {
    maxMessages: number;
    deadlineAt?: number;
    now?: () => number;
    onMessage(message: { uid: number; source: Buffer }): Promise<unknown>;
    onOversized(message: { uid: number; size: number }): Promise<unknown> | unknown;
    onUnprocessable?(message: { uid: number }): Promise<unknown> | unknown;
  },
): Promise<ImapPollResult> {
  if (
    !Number.isInteger(options.maxMessages) ||
    options.maxMessages < 1 ||
    options.maxMessages > 100
  ) {
    throw new Error("IMAP poll batch size must be between 1 and 100");
  }
  if (
    options.deadlineAt !== undefined &&
    (!Number.isSafeInteger(options.deadlineAt) || options.deadlineAt < 0)
  ) {
    throw new Error("IMAP poll deadline is invalid");
  }
  const now = options.now ?? Date.now;

  await session.connect();
  let lock: { release(): void } | undefined;
  try {
    lock = await session.getMailboxLock(cursor.mailbox, {
      readOnly: true,
      acquireTimeout: 10_000,
    });
    if (!session.mailbox) throw new Error("IMAP mailbox did not open");

    const uidValidity = session.mailbox.uidValidity.toString();
    const reset = cursor.uidValidity !== null && cursor.uidValidity !== uidValidity;
    const startUid = reset ? 1 : cursor.lastUid + 1;
    let lastUid = reset ? 0 : cursor.lastUid;
    let processed = 0;

    if (session.mailbox.exists > 0) {
      for await (const message of session.fetch(
        `${startUid}:*`,
        {
          uid: true,
          size: true,
          internalDate: true,
          source: { maxLength: MAX_SOURCE_BYTES + 1 },
        },
        { uid: true },
      )) {
        if (processed >= options.maxMessages) break;
        if (options.deadlineAt !== undefined && now() >= options.deadlineAt) break;
        if (
          !Number.isSafeInteger(message.uid) ||
          message.uid < startUid ||
          message.uid <= lastUid
        ) {
          throw new Error("IMAP server returned an invalid UID");
        }
        const source = message.source ?? Buffer.alloc(0);
        if (
          message.size !== undefined &&
          (!Number.isSafeInteger(message.size) || message.size < 0)
        ) {
          throw new Error("IMAP server returned an invalid message size");
        }
        const size = Math.max(message.size ?? 0, source.length);
        if (size > MAX_SOURCE_BYTES || source.length > MAX_SOURCE_BYTES) {
          await options.onOversized({ uid: message.uid, size });
        } else if (source.length === 0) {
          if (!options.onUnprocessable) {
            throw new Error("IMAP message source was empty");
          }
          await options.onUnprocessable({ uid: message.uid });
        } else {
          await options.onMessage({ uid: message.uid, source });
        }
        lastUid = message.uid;
        processed += 1;
      }
    }

    return {
      uidValidity,
      lastUid,
      highestModseq: session.mailbox.highestModseq?.toString() ?? null,
    };
  } finally {
    lock?.release();
    try {
      await session.logout();
    } catch {
      // The poll result or original processing error is more actionable than logout noise.
    }
  }
}

export async function createPinnedImapSession(configuration: {
  hostname: string;
  port: number;
  secure: boolean;
  username: string;
  password?: string;
  accessToken?: string;
}): Promise<ImapSession> {
  if (configuration.port !== 993 || configuration.secure !== true) {
    throw new Error("IMAP requires implicit TLS on port 993");
  }
  if (!configuration.password && !configuration.accessToken) {
    throw new Error("IMAP credentials are required");
  }
  const target = await assertSafeEgressTarget(
    {
      hostname: configuration.hostname,
      port: configuration.port,
    },
    { allowedPorts: IMAP_TLS_PORTS },
  );
  const session = new ImapFlow({
    host: target.connectionAddress,
    servername: target.tlsServername,
    port: target.port,
    secure: true,
    auth: {
      user: configuration.username,
      pass: configuration.password,
      accessToken: configuration.accessToken,
    },
    tls: {
      servername: target.tlsServername,
      minVersion: "TLSv1.2",
      rejectUnauthorized: true,
    },
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 30_000,
    maxLineLength: MAX_IMAP_LINE_BYTES,
    maxLiteralSize: MAX_SOURCE_BYTES + 1,
    disableCompression: true,
    logger: false,
  });
  return session as unknown as ImapSession;
}
