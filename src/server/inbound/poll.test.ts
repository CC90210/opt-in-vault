import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";

import { encryptSecret } from "@/server/security/encryption";
import { createInboxCredentialBinding } from "@/server/email/inbox-credentials";

import type { ImapSession } from "./imap-client";
import { pollConfiguredInboxes } from "./poll";

const MIGRATIONS_FOLDER = fileURLToPath(
  new URL("../../../drizzle", import.meta.url),
);
const CREDENTIAL_KEY = Buffer.alloc(32, 7);
const HISTORICAL_CREDENTIAL_KEY = Buffer.alloc(32, 8);
const CREDENTIAL_KEYS = new Map([
  ["1", CREDENTIAL_KEY],
  ["2", HISTORICAL_CREDENTIAL_KEY],
]);
const HASH_KEY = "test-only-suppression-hash-key-with-enough-entropy";

describe("configured inbox poll cycle", () => {
  let client: Client;
  let tenantId: string;
  let inboxId: string;

  beforeEach(async () => {
    client = createClient({ url: "file::memory:?cache=shared" });
    await migrate(drizzle(client), { migrationsFolder: MIGRATIONS_FOLDER });
    await client.execute("PRAGMA foreign_keys = ON");
    await client.execute("UPDATE sending_inboxes SET status = 'paused'");
    tenantId = `tenant-${randomUUID()}`;
    inboxId = `inbox-${tenantId}`;
    const credentialBinding = createInboxCredentialBinding({
      smtpHost: "smtp.example.com",
      imapHost: "imap.example.com",
    });
    const envelope = encryptSecret(
      JSON.stringify({ username: "sender@example.com", password: "test-password" }),
      HISTORICAL_CREDENTIAL_KEY,
      {
        tenantId,
        resourceType: "sending_inbox",
        resourceId: inboxId,
        field: "credentials",
        provider: "smtp",
        host: credentialBinding,
      },
      "2",
    );
    await client.batch(
      [
        {
          sql: "INSERT INTO tenants (id, slug, name) VALUES (?, ?, 'Tenant')",
          args: [tenantId, tenantId],
        },
        {
          sql: "INSERT INTO sending_domains (id, tenant_id, domain) VALUES (?, ?, 'example.com')",
          args: [`domain-${tenantId}`, tenantId],
        },
        {
          sql: "INSERT INTO sending_inboxes (id, tenant_id, domain_id, email_address, display_name, provider, smtp_host, imap_host, imap_port, encrypted_credentials, credential_key_version, credential_binding, status) VALUES (?, ?, ?, 'sender@example.com', 'Sender', 'smtp', 'smtp.example.com', 'imap.example.com', 993, ?, 2, ?, 'active')",
          args: [inboxId, tenantId, `domain-${tenantId}`, Buffer.from(envelope), credentialBinding],
        },
      ],
      "write",
    );
  });

  afterEach(() => client.close());

  async function configureOAuthInbox(
    provider: "google" | "microsoft",
    overrides: {
      smtpHost?: string;
      imapHost?: string;
      credentials?: Record<string, unknown>;
    } = {},
  ): Promise<void> {
    const smtpHost =
      overrides.smtpHost ??
      (provider === "google" ? "smtp.gmail.com" : "smtp.office365.com");
    const imapHost =
      overrides.imapHost ??
      (provider === "google" ? "imap.gmail.com" : "outlook.office365.com");
    const credentialBinding = createInboxCredentialBinding({ smtpHost, imapHost });
    const envelope = encryptSecret(
      JSON.stringify({
        username: "sender@example.com",
        oauth2: {
          clientId: "client-id",
          clientSecret: "client-secret",
          refreshToken: "refresh-token",
          accessToken: "stale-access-token",
        },
        ...overrides.credentials,
      }),
      HISTORICAL_CREDENTIAL_KEY,
      {
        tenantId,
        resourceType: "sending_inbox",
        resourceId: inboxId,
        field: "credentials",
        provider,
        host: credentialBinding,
      },
      "2",
    );
    await client.execute({
      sql: `
        UPDATE sending_inboxes
        SET provider = ?, smtp_host = ?, imap_host = ?, imap_port = 993,
            imap_secure = 1, encrypted_credentials = ?,
            credential_binding = ?
        WHERE tenant_id = ? AND id = ?
      `,
      args: [
        provider,
        smtpHost,
        imapHost,
        Buffer.from(envelope),
        credentialBinding,
        tenantId,
        inboxId,
      ],
    });
  }

  function emptySession(): ImapSession {
    const session = {
      mailbox: false as ImapSession["mailbox"],
      connect: vi.fn(),
      logout: vi.fn(),
      getMailboxLock: vi.fn(async () => {
        session.mailbox = { uidValidity: BigInt(70), exists: 0 };
        return { release: vi.fn() };
      }),
      fetch: vi.fn(async function* () {}),
    } satisfies ImapSession;
    return session;
  }

  it("decrypts credentials, processes UID mail once, and persists the cursor", async () => {
    const source = Buffer.from(
      "From: Unknown <unknown@example.net>\r\nSubject: Hello\r\nMessage-ID: <incoming@example.net>\r\n\r\nHello",
    );
    const sessionFactory = vi.fn(async () => {
      const session = {
        mailbox: false as ImapSession["mailbox"],
        connect: vi.fn(),
        logout: vi.fn(),
        getMailboxLock: vi.fn(async () => {
          session.mailbox = {
            uidValidity: BigInt(55),
            highestModseq: BigInt(7),
            exists: 1,
          };
          return { release: vi.fn() };
        }),
        fetch: vi.fn(async function* () {
          yield { uid: 9, source, size: source.length };
        }),
      } satisfies ImapSession;
      return session;
    });

    const first = await pollConfiguredInboxes(client, {
      credentialKeys: CREDENTIAL_KEYS,
      suppressionHashKey: HASH_KEY,
      maxInboxes: 5,
      maxMessagesPerInbox: 10,
      sessionFactory,
      now: () => 1_800_000_000_000,
    });

    expect(first).toEqual({ inboxesPolled: 1, messagesProcessed: 1, failures: 0 });
    expect(sessionFactory).toHaveBeenCalledWith(
      expect.objectContaining({
        hostname: "imap.example.com",
        port: 993,
        username: "sender@example.com",
        password: "test-password",
      }),
    );
    const state = await client.execute({
      sql: `
        SELECT
          (SELECT uid_validity FROM imap_cursors WHERE tenant_id = ?) AS uid_validity,
          (SELECT last_uid FROM imap_cursors WHERE tenant_id = ?) AS last_uid,
          (SELECT COUNT(*) FROM inbound_messages WHERE tenant_id = ?) AS messages
      `,
      args: [tenantId, tenantId, tenantId],
    });
    expect(state.rows[0]).toMatchObject({ uid_validity: "55", last_uid: 9, messages: 1 });
  });

  it.each([
    ["google", "https://oauth2.googleapis.com/token", null],
    [
      "microsoft",
      "https://login.microsoftonline.com/common/oauth2/v2.0/token",
      "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
    ],
  ] as const)(
    "refreshes %s credentials within the cycle and gives IMAP only the fresh token",
    async (provider, expectedEndpoint, expectedScope) => {
      await configureOAuthInbox(provider);
      const fetchImpl = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ access_token: "fresh-access-token" }), {
          status: 200,
        }),
      );
      const sessionFactory = vi.fn(async () => emptySession());

      const result = await pollConfiguredInboxes(client, {
        credentialKeys: CREDENTIAL_KEYS,
        suppressionHashKey: HASH_KEY,
        maxInboxes: 5,
        maxMessagesPerInbox: 10,
        sessionFactory,
        fetchImpl,
        now: () => 1_800_000_000_000,
      });

      expect(result).toEqual({ inboxesPolled: 1, messagesProcessed: 0, failures: 0 });
      expect(fetchImpl).toHaveBeenCalledTimes(1);
      const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(expectedEndpoint);
      expect(init.redirect).toBe("error");
      const body = new URLSearchParams(String(init.body));
      expect(body.get("scope")).toBe(expectedScope);
      expect(sessionFactory).toHaveBeenCalledWith({
        hostname:
          provider === "google" ? "imap.gmail.com" : "outlook.office365.com",
        port: 993,
        secure: true,
        username: "sender@example.com",
        accessToken: "fresh-access-token",
      });
      expect(JSON.stringify(sessionFactory.mock.calls)).not.toContain(
        "refresh-token",
      );
      expect(JSON.stringify(sessionFactory.mock.calls)).not.toContain(
        "client-secret",
      );
    },
  );

  it("maps OAuth refresh failures to a secret-free authentication diagnostic", async () => {
    await configureOAuthInbox("google");
    const onDiagnostic = vi.fn();
    const sessionFactory = vi.fn();

    const result = await pollConfiguredInboxes(client, {
      credentialKeys: CREDENTIAL_KEYS,
      suppressionHashKey: HASH_KEY,
      maxInboxes: 5,
      maxMessagesPerInbox: 10,
      sessionFactory,
      fetchImpl: vi.fn().mockRejectedValue(
        new Error("client_secret=must-not-leak&refresh_token=must-not-leak"),
      ),
      onDiagnostic,
      now: () => 1_800_000_000_000,
    });

    expect(result).toEqual({ inboxesPolled: 0, messagesProcessed: 0, failures: 1 });
    expect(sessionFactory).not.toHaveBeenCalled();
    expect(onDiagnostic).toHaveBeenCalledWith(
      expect.objectContaining({
        code: "imap_oauth_refresh_failed",
        errorName: "KnownPollError",
      }),
    );
    expect(JSON.stringify(onDiagnostic.mock.calls)).not.toContain("must-not-leak");
    const state = await client.execute({
      sql: "SELECT auth_error_at FROM sending_inboxes WHERE tenant_id = ? AND id = ?",
      args: [tenantId, inboxId],
    });
    expect(state.rows[0]?.auth_error_at).toBe(1_800_000_000_000);
  });

  it.each([
    ["google", "smtp.gmail.com", "imap.attacker.example"],
    ["microsoft", "smtp.office365.com", "imap.attacker.example"],
  ] as const)(
    "rejects a non-provider %s IMAP host before decrypt, refresh, or session creation",
    async (provider, smtpHost, imapHost) => {
      await configureOAuthInbox(provider, { smtpHost, imapHost });
      const fetchImpl = vi.fn();
      const sessionFactory = vi.fn();
      const onDiagnostic = vi.fn();

      const result = await pollConfiguredInboxes(client, {
        credentialKeys: CREDENTIAL_KEYS,
        suppressionHashKey: HASH_KEY,
        maxInboxes: 5,
        maxMessagesPerInbox: 10,
        sessionFactory,
        fetchImpl,
        onDiagnostic,
        now: () => 1_800_000_000_000,
      });

      expect(result).toEqual({ inboxesPolled: 0, messagesProcessed: 0, failures: 1 });
      expect(fetchImpl).not.toHaveBeenCalled();
      expect(sessionFactory).not.toHaveBeenCalled();
      expect(onDiagnostic).toHaveBeenCalledWith(
        expect.objectContaining({ code: "imap_provider_host_invalid" }),
      );
    },
  );

  it("bounds asynchronous IMAP session setup by the remaining cycle deadline", async () => {
    vi.useFakeTimers();
    try {
      let signalSessionStarted!: () => void;
      const sessionStarted = new Promise<void>((resolve) => {
        signalSessionStarted = resolve;
      });
      const sessionFactory = vi.fn(
        () =>
          new Promise<ImapSession>(() => {
            signalSessionStarted();
          }),
      );
      const onDiagnostic = vi.fn();
      const pending = pollConfiguredInboxes(client, {
        credentialKeys: CREDENTIAL_KEYS,
        suppressionHashKey: HASH_KEY,
        maxInboxes: 5,
        maxMessagesPerInbox: 10,
        maxCycleMs: 1_000,
        sessionFactory,
        onDiagnostic,
        now: () => 1_800_000_000_000,
      });
      await sessionStarted;
      await vi.advanceTimersByTimeAsync(999);
      expect(onDiagnostic).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);

      await expect(pending).resolves.toEqual({
        inboxesPolled: 0,
        messagesProcessed: 0,
        failures: 1,
      });
      expect(onDiagnostic).toHaveBeenCalledWith(
        expect.objectContaining({ code: "imap_session_setup_timeout" }),
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("records a safe failure notification instead of swallowing poll errors", async () => {
    const onDiagnostic = vi.fn();
    const result = await pollConfiguredInboxes(client, {
      credentialKeys: CREDENTIAL_KEYS,
      suppressionHashKey: HASH_KEY,
      maxInboxes: 5,
      maxMessagesPerInbox: 10,
      sessionFactory: vi.fn(async () => {
        throw new Error("password=must-not-leak");
      }),
      onDiagnostic,
      now: () => 1_800_000_000_000,
    });

    expect(result).toEqual({ inboxesPolled: 0, messagesProcessed: 0, failures: 1 });
    const notification = await client.execute({
      sql: "SELECT payload_json FROM notifications WHERE tenant_id = ?",
      args: [tenantId],
    });
    expect(String(notification.rows[0]?.payload_json)).toContain("inbox_poll_failed");
    expect(String(notification.rows[0]?.payload_json)).not.toContain("password");
    expect(JSON.stringify(onDiagnostic.mock.calls)).not.toContain("password");
    expect(onDiagnostic).toHaveBeenCalledWith(
      expect.objectContaining({ code: "inbox_poll_failed", inboxId }),
    );
    const state = await client.execute({
      sql: "SELECT inbox.auth_error_at, run.status, run.error_code FROM sending_inboxes AS inbox JOIN worker_runs AS run ON run.tenant_id = inbox.tenant_id AND run.bucket_key = ? WHERE inbox.tenant_id = ? AND inbox.id = ?",
      args: [`inbox:${inboxId}`, tenantId, inboxId],
    });
    expect(state.rows[0]).toMatchObject({
      auth_error_at: null,
      status: "failed",
      error_code: "inbox_poll_failed",
    });
  });

  it("rejects a credential envelope whose stored endpoint binding was tampered", async () => {
    await client.execute({
      sql: "UPDATE sending_inboxes SET credential_binding = 'wrong-binding' WHERE tenant_id = ? AND id = ?",
      args: [tenantId, inboxId],
    });
    const sessionFactory = vi.fn();
    const result = await pollConfiguredInboxes(client, {
      credentialKeys: CREDENTIAL_KEYS,
      suppressionHashKey: HASH_KEY,
      maxInboxes: 5,
      maxMessagesPerInbox: 10,
      sessionFactory,
      onDiagnostic: vi.fn(),
      now: () => 1_800_000_000_000,
    });
    expect(result).toEqual({ inboxesPolled: 0, messagesProcessed: 0, failures: 1 });
    expect(sessionFactory).not.toHaveBeenCalled();
    const state = await client.execute({
      sql: "SELECT auth_error_at FROM sending_inboxes WHERE tenant_id = ? AND id = ?",
      args: [tenantId, inboxId],
    });
    expect(state.rows[0]?.auth_error_at).toBe(1_800_000_000_000);
  });

  it("honors an active per-inbox lease and backs off a recent failed run", async () => {
    await client.execute({
      sql: "INSERT INTO worker_runs (id, tenant_id, run_type, bucket_key, status, lease_expires_at, started_at) VALUES ('other-worker', ?, 'poll_inboxes', ?, 'running', ?, ?)",
      args: [tenantId, `inbox:${inboxId}`, 1_800_000_060_000, 1_800_000_000_000],
    });
    const sessionFactory = vi.fn();
    const leased = await pollConfiguredInboxes(client, {
      credentialKeys: CREDENTIAL_KEYS,
      suppressionHashKey: HASH_KEY,
      maxInboxes: 5,
      maxMessagesPerInbox: 10,
      sessionFactory,
      now: () => 1_800_000_000_000,
    });
    expect(leased).toEqual({ inboxesPolled: 0, messagesProcessed: 0, failures: 0 });
    expect(sessionFactory).not.toHaveBeenCalled();

    await client.execute({
      sql: "UPDATE worker_runs SET status = 'failed', lease_expires_at = NULL, finished_at = ? WHERE tenant_id = ? AND bucket_key = ?",
      args: [1_800_000_000_000, tenantId, `inbox:${inboxId}`],
    });
    const backedOff = await pollConfiguredInboxes(client, {
      credentialKeys: CREDENTIAL_KEYS,
      suppressionHashKey: HASH_KEY,
      maxInboxes: 5,
      maxMessagesPerInbox: 10,
      sessionFactory,
      now: () => 1_800_000_000_001,
    });
    expect(backedOff).toEqual({ inboxesPolled: 0, messagesProcessed: 0, failures: 0 });
    expect(sessionFactory).not.toHaveBeenCalled();
  });

  it("durably records poison MIME and advances the cursor without retrying forever", async () => {
    const source = Buffer.from("Subject: no sender\r\n\r\nmalformed inbound");
    const sessionFactory = vi.fn(async () => {
      const session = {
        mailbox: false as ImapSession["mailbox"],
        connect: vi.fn(),
        logout: vi.fn(),
        getMailboxLock: vi.fn(async () => {
          session.mailbox = { uidValidity: BigInt(56), exists: 1 };
          return { release: vi.fn() };
        }),
        fetch: vi.fn(async function* () {
          yield { uid: 10, source, size: source.length };
        }),
      } satisfies ImapSession;
      return session;
    });
    const result = await pollConfiguredInboxes(client, {
      credentialKeys: CREDENTIAL_KEYS,
      suppressionHashKey: HASH_KEY,
      maxInboxes: 5,
      maxMessagesPerInbox: 10,
      sessionFactory,
      now: () => 1_800_000_000_000,
    });
    expect(result).toEqual({ inboxesPolled: 1, messagesProcessed: 1, failures: 0 });
    const state = await client.execute({
      sql: "SELECT message.from_address, message.classification, cursor.last_uid, notification.payload_json FROM inbound_messages AS message JOIN imap_cursors AS cursor ON cursor.tenant_id = message.tenant_id AND cursor.inbox_id = message.inbox_id JOIN notifications AS notification ON notification.tenant_id = message.tenant_id WHERE message.tenant_id = ?",
      args: [tenantId],
    });
    expect(state.rows[0]).toMatchObject({
      from_address: "unknown@invalid.invalid",
      classification: "other",
      last_uid: 10,
    });
    expect(String(state.rows[0]?.payload_json)).toContain("inbound_missing_sender");
    expect(String(state.rows[0]?.payload_json)).not.toContain("malformed inbound");
  });

  it("prevents a stale worker from regressing a newer cursor", async () => {
    let releaseFirst!: () => void;
    let signalFirstFetch!: () => void;
    const firstFetchStarted = new Promise<void>((resolve) => {
      signalFirstFetch = resolve;
    });
    const firstCanFinish = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let factoryCalls = 0;
    const sessionFactory = vi.fn(async () => {
      factoryCalls += 1;
      const call = factoryCalls;
      const uid = call === 1 ? 10 : 20;
      const source = Buffer.from(
        `From: Unknown <unknown@example.net>\r\nSubject: ${call}\r\nMessage-ID: <incoming-${call}@example.net>\r\n\r\nHello`,
      );
      const session = {
        mailbox: false as ImapSession["mailbox"],
        connect: vi.fn(),
        logout: vi.fn(),
        getMailboxLock: vi.fn(async () => {
          session.mailbox = { uidValidity: BigInt(60), exists: 1 };
          return { release: vi.fn() };
        }),
        fetch: vi.fn(async function* () {
          if (call === 1) {
            signalFirstFetch();
            await firstCanFinish;
          }
          yield { uid, source, size: source.length };
        }),
      } satisfies ImapSession;
      return session;
    });
    const diagnostic = vi.fn();
    const first = pollConfiguredInboxes(client, {
      credentialKeys: CREDENTIAL_KEYS,
      suppressionHashKey: HASH_KEY,
      maxInboxes: 5,
      maxMessagesPerInbox: 10,
      sessionFactory,
      onDiagnostic: diagnostic,
      now: () => 1_800_000_000_000,
    });
    await firstFetchStarted;
    const second = await pollConfiguredInboxes(client, {
      credentialKeys: CREDENTIAL_KEYS,
      suppressionHashKey: HASH_KEY,
      maxInboxes: 5,
      maxMessagesPerInbox: 10,
      sessionFactory,
      onDiagnostic: diagnostic,
      now: () => 1_800_000_120_000,
    });
    releaseFirst();
    const stale = await first;

    expect(second).toEqual({ inboxesPolled: 1, messagesProcessed: 1, failures: 0 });
    expect(stale).toMatchObject({ inboxesPolled: 0, failures: 1 });
    expect(diagnostic).toHaveBeenCalledWith(
      expect.objectContaining({ code: "inbox_lease_lost", inboxId }),
    );
    const cursor = await client.execute({
      sql: "SELECT uid_validity, last_uid FROM imap_cursors WHERE tenant_id = ? AND inbox_id = ?",
      args: [tenantId, inboxId],
    });
    expect(cursor.rows[0]).toMatchObject({ uid_validity: "60", last_uid: 20 });
  });
});
