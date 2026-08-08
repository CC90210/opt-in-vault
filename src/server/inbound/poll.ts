import "server-only";

import { createHash, randomUUID } from "node:crypto";

import type { Client, Value } from "@libsql/client";

import {
  createInboxCredentialBinding,
  parseInboxCredentialPayload,
} from "@/server/email/inbox-credentials";
import {
  assertOAuthProviderHost,
  OAuthAccessTokenError,
  resolveOAuthAccessToken,
  type OAuthFetch,
  type OAuthProvider,
} from "@/server/email/oauth-refresh";
import {
  decryptSecretWithKeyRing,
  type EncryptionKeyRing,
} from "@/server/security/encryption";

import {
  createPinnedImapSession,
  pollImapMailbox,
  type ImapSession,
} from "./imap-client";
import { InboundParseError, parseInboundSource } from "./parse";
import { processInboundMessage } from "./service";

const INBOX_LEASE_GRACE_MS = 60_000;
const FAILURE_BACKOFF_MS = 60_000;
const DEFAULT_CYCLE_MS = 45_000;
const MAX_DISCOVERY_MULTIPLIER = 3;
const MAX_SESSION_SETUP_MS = 10_000;

type SessionConfiguration = {
  hostname: string;
  port: number;
  secure: boolean;
  username: string;
  password?: string;
  accessToken?: string;
};

export type InboxPollDiagnostic = Readonly<{
  inboxId: string;
  code: string;
  errorName: string;
  stackFrames: readonly string[];
}>;

export type PollOptions = {
  credentialKeys: EncryptionKeyRing;
  suppressionHashKey: string;
  maxInboxes: number;
  maxMessagesPerInbox: number;
  maxCycleMs?: number;
  sessionFactory?: (configuration: SessionConfiguration) => Promise<ImapSession>;
  fetchImpl?: OAuthFetch;
  onDiagnostic?: (diagnostic: InboxPollDiagnostic) => void;
  now?: () => number;
};

class KnownPollError extends Error {
  constructor(
    readonly code: string,
    readonly authFailure = false,
  ) {
    super(code);
    this.name = "KnownPollError";
  }
}

class InboxLeaseLostError extends KnownPollError {
  constructor() {
    super("inbox_lease_lost");
    this.name = "InboxLeaseLostError";
  }
}

function remainingOperationMs(
  deadlineAt: number,
  now: () => number,
  maximumMs: number,
  timeoutCode: string,
): number {
  const currentTime = now();
  const remaining = deadlineAt - currentTime;
  if (!Number.isSafeInteger(currentTime) || currentTime < 0 || remaining <= 0) {
    throw new KnownPollError(timeoutCode);
  }
  return Math.min(maximumMs, remaining);
}

async function runWithTimeout<T>(
  operation: () => Promise<T>,
  timeoutMs: number,
  timeoutCode: string,
): Promise<T> {
  return await new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new KnownPollError(timeoutCode)),
      timeoutMs,
    );
    Promise.resolve()
      .then(operation)
      .then(
        (value) => {
          clearTimeout(timeout);
          resolve(value);
        },
        (error: unknown) => {
          clearTimeout(timeout);
          reject(error);
        },
      );
  });
}

function credentialBytes(value: Value): Buffer {
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  if (ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new KnownPollError("inbox_credential_invalid", true);
}

function validateBounds(options: PollOptions): void {
  const maxCycleMs = options.maxCycleMs ?? DEFAULT_CYCLE_MS;
  if (
    !Number.isInteger(options.maxInboxes) ||
    options.maxInboxes < 1 ||
    options.maxInboxes > 25 ||
    !Number.isInteger(options.maxMessagesPerInbox) ||
    options.maxMessagesPerInbox < 1 ||
    options.maxMessagesPerInbox > 100 ||
    !Number.isInteger(maxCycleMs) ||
    maxCycleMs < 1_000 ||
    maxCycleMs > 120_000
  ) {
    throw new Error("Inbox poll bounds are invalid");
  }
}

function durableId(prefix: string, parts: readonly (string | number)[]): string {
  const digest = createHash("sha256")
    .update(parts.map(String).join("\0"))
    .digest("hex");
  return `${prefix}_${digest}`;
}

function safeFailure(error: unknown): { code: string; authFailure: boolean } {
  if (error instanceof KnownPollError) {
    return { code: error.code, authFailure: error.authFailure };
  }
  const record =
    error && typeof error === "object" ? (error as Record<string, unknown>) : {};
  const rawCode = typeof record.code === "string" ? record.code.toUpperCase() : "";
  if (String(record.name) === "EgressTargetError") {
    return { code: "imap_egress_rejected", authFailure: false };
  }
  if (
    record.authenticationFailed === true ||
    ["AUTHENTICATIONFAILED", "EAUTH", "NOAUTH"].includes(rawCode)
  ) {
    return { code: "imap_auth_failed", authFailure: true };
  }
  if (["ETIMEDOUT", "ETIMEOUT", "ESOCKETTIMEDOUT"].includes(rawCode)) {
    return { code: "imap_timeout", authFailure: false };
  }
  return { code: "inbox_poll_failed", authFailure: false };
}

function emitDiagnostic(
  options: PollOptions,
  inboxId: string,
  failure: { code: string },
  error: unknown,
): void {
  const rawName = error instanceof Error ? error.name : "Error";
  const errorName = /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(rawName)
    ? rawName
    : "Error";
  const stackFrames =
    error instanceof Error && error.stack
      ? error.stack
          .split("\n")
          .slice(1)
          .filter((line) => /^\s*at\s/.test(line))
          .slice(0, 8)
      : [];
  const diagnostic: InboxPollDiagnostic = Object.freeze({
    inboxId,
    code: failure.code,
    errorName,
    stackFrames: Object.freeze(stackFrames),
  });
  if (options.onDiagnostic) {
    options.onDiagnostic(diagnostic);
  } else {
    console.error("Inbox poll failed", diagnostic);
  }
}

async function claimInboxLease(
  client: Client,
  tenantId: string,
  inboxId: string,
  startedAt: number,
  leaseDurationMs: number,
): Promise<string | null> {
  const leaseId = randomUUID();
  const result = await client.execute({
    sql: `
      INSERT INTO worker_runs
        (id, tenant_id, run_type, bucket_key, status, lease_expires_at,
         stats_json, error_code, started_at, finished_at)
      VALUES (?, ?, 'poll_inboxes', ?, 'running', ?, '{}', NULL, ?, NULL)
      ON CONFLICT (tenant_id, run_type, bucket_key) DO UPDATE SET
        id = excluded.id,
        status = 'running',
        lease_expires_at = excluded.lease_expires_at,
        stats_json = '{}',
        error_code = NULL,
        started_at = excluded.started_at,
        finished_at = NULL
      WHERE worker_runs.status = 'completed'
         OR (worker_runs.status = 'running'
             AND COALESCE(worker_runs.lease_expires_at, 0) <= excluded.started_at)
         OR (worker_runs.status = 'failed'
             AND COALESCE(worker_runs.finished_at, 0) <= ?)
      RETURNING id
    `,
    args: [
      leaseId,
      tenantId,
      `inbox:${inboxId}`,
      startedAt + leaseDurationMs,
      startedAt,
      startedAt - FAILURE_BACKOFF_MS,
    ],
  });
  return result.rows[0]?.id === leaseId ? leaseId : null;
}

type UnprocessableCode =
  | "inbound_invalid_source"
  | "inbound_missing_sender"
  | "inbound_malformed_mime"
  | "inbound_empty_source"
  | "inbound_message_oversized";

async function recordUnprocessableInbound(
  client: Client,
  input: {
    tenantId: string;
    inboxId: string;
    uidValidity: string;
    uid: number;
    receivedAt: number;
    code: UnprocessableCode;
    size?: number;
  },
): Promise<boolean> {
  const identity = [input.tenantId, input.inboxId, input.uidValidity, input.uid];
  const inboundId = durableId("inbound_invalid", identity);
  const notificationId = durableId("notification_invalid", [...identity, input.code]);
  const replyEventId = durableId("reply_invalid", identity);
  const results = await client.batch(
    [
      {
        sql: `
          INSERT INTO inbound_messages
            (id, tenant_id, inbox_id, uid_validity, uid, message_id, in_reply_to,
             references_json, from_address, subject, headers_json, text_snippet,
             classification, received_at)
          VALUES (?, ?, ?, ?, ?, NULL, NULL, '[]', 'unknown@invalid.invalid', NULL,
                  ?, NULL, 'other', ?)
          ON CONFLICT (tenant_id, inbox_id, uid_validity, uid) DO NOTHING
        `,
        args: [
          inboundId,
          input.tenantId,
          input.inboxId,
          input.uidValidity,
          input.uid,
          JSON.stringify({ processing_error: input.code, truncated: true }),
          input.receivedAt,
        ],
      },
      {
        sql: `
          INSERT INTO reply_events
            (id, tenant_id, inbound_message_id, enrollment_id, lead_id,
             classification, effect_applied_at)
          SELECT ?, ?, ?, NULL, NULL, 'other', NULL
          WHERE EXISTS (
            SELECT 1 FROM inbound_messages
            WHERE tenant_id = ? AND id = ?
          )
          ON CONFLICT (tenant_id, inbound_message_id) DO NOTHING
        `,
        args: [
          replyEventId,
          input.tenantId,
          inboundId,
          input.tenantId,
          inboundId,
        ],
      },
      {
        sql: `
          INSERT INTO notifications
            (id, tenant_id, type, payload_json, status, next_attempt_at)
          VALUES (?, ?, 'inbound_processing_failed', ?, 'pending', ?)
          ON CONFLICT (id) DO NOTHING
        `,
        args: [
          notificationId,
          input.tenantId,
          JSON.stringify({
            code: input.code,
            inboxId: input.inboxId,
            uid: input.uid,
            ...(input.size === undefined ? {} : { size: input.size }),
          }),
          input.receivedAt,
        ],
      },
    ],
    "write",
  );
  return results[0].rowsAffected === 1;
}

async function persistSuccessfulCursor(
  client: Client,
  input: {
    tenantId: string;
    inboxId: string;
    leaseId: string;
    uidValidity: string;
    lastUid: number;
    highestModseq: string | null;
    now: number;
    messagesProcessed: number;
  },
): Promise<void> {
  const results = await client.batch(
    [
      {
        sql: `
          INSERT INTO imap_cursors
            (id, tenant_id, inbox_id, mailbox, uid_validity, last_uid,
             highest_modseq, updated_at)
          SELECT ?, ?, ?, 'INBOX', ?, ?, ?, ?
          WHERE EXISTS (
            SELECT 1 FROM worker_runs
            WHERE tenant_id = ? AND id = ? AND run_type = 'poll_inboxes'
              AND bucket_key = ? AND status = 'running' AND lease_expires_at > ?
          )
          ON CONFLICT (tenant_id, inbox_id, mailbox) DO UPDATE SET
            uid_validity = excluded.uid_validity,
            last_uid = excluded.last_uid,
            highest_modseq = excluded.highest_modseq,
            updated_at = excluded.updated_at
          WHERE imap_cursors.uid_validity <> excluded.uid_validity
             OR excluded.last_uid >= imap_cursors.last_uid
        `,
        args: [
          randomUUID(),
          input.tenantId,
          input.inboxId,
          input.uidValidity,
          input.lastUid,
          input.highestModseq,
          input.now,
          input.tenantId,
          input.leaseId,
          `inbox:${input.inboxId}`,
          input.now,
        ],
      },
      {
        sql: `
          UPDATE sending_inboxes
          SET last_poll_at = ?, auth_error_at = NULL, updated_at = ?
          WHERE tenant_id = ? AND id = ?
            AND EXISTS (
              SELECT 1 FROM worker_runs
              WHERE tenant_id = ? AND id = ? AND status = 'running'
                AND run_type = 'poll_inboxes' AND bucket_key = ?
                AND lease_expires_at > ?
            )
        `,
        args: [
          input.now,
          input.now,
          input.tenantId,
          input.inboxId,
          input.tenantId,
          input.leaseId,
          `inbox:${input.inboxId}`,
          input.now,
        ],
      },
      {
        sql: `
          UPDATE worker_runs
          SET status = 'completed', lease_expires_at = NULL, error_code = NULL,
              stats_json = ?, finished_at = ?
          WHERE tenant_id = ? AND id = ? AND run_type = 'poll_inboxes'
            AND bucket_key = ? AND status = 'running' AND lease_expires_at > ?
        `,
        args: [
          JSON.stringify({ messagesProcessed: input.messagesProcessed }),
          input.now,
          input.tenantId,
          input.leaseId,
          `inbox:${input.inboxId}`,
          input.now,
        ],
      },
    ],
    "write",
  );
  if (results[2].rowsAffected !== 1) throw new InboxLeaseLostError();
}

async function recordPollFailure(
  client: Client,
  input: {
    tenantId: string;
    inboxId: string;
    leaseId: string;
    failure: { code: string; authFailure: boolean };
    now: number;
  },
): Promise<boolean> {
  const failed = await client.execute({
    sql: `
      UPDATE worker_runs
      SET status = 'failed', lease_expires_at = NULL, error_code = ?, finished_at = ?
      WHERE tenant_id = ? AND id = ? AND run_type = 'poll_inboxes'
        AND bucket_key = ? AND status = 'running'
      RETURNING id
    `,
    args: [
      input.failure.code,
      input.now,
      input.tenantId,
      input.leaseId,
      `inbox:${input.inboxId}`,
    ],
  });
  if (failed.rows.length === 0) return false;

  await client.batch(
    [
      {
        sql: `
          UPDATE sending_inboxes
          SET auth_error_at = CASE WHEN ? = 1 THEN ? ELSE auth_error_at END,
              updated_at = ?
          WHERE tenant_id = ? AND id = ?
        `,
        args: [
          input.failure.authFailure ? 1 : 0,
          input.now,
          input.now,
          input.tenantId,
          input.inboxId,
        ],
      },
      {
        sql: `
          INSERT INTO notifications
            (id, tenant_id, type, payload_json, status, next_attempt_at)
          VALUES (?, ?, 'inbound_poll_failed', ?, 'pending', ?)
          ON CONFLICT (id) DO NOTHING
        `,
        args: [
          durableId("notification_poll", [input.tenantId, input.inboxId, input.leaseId]),
          input.tenantId,
          JSON.stringify({ code: input.failure.code, inboxId: input.inboxId }),
          input.now,
        ],
      },
    ],
    "write",
  );
  return true;
}

export async function pollConfiguredInboxes(
  client: Client,
  options: PollOptions,
): Promise<{ inboxesPolled: number; messagesProcessed: number; failures: number }> {
  validateBounds(options);
  const now = options.now ?? Date.now;
  const startedAt = now();
  const maxCycleMs = options.maxCycleMs ?? DEFAULT_CYCLE_MS;
  const deadlineAt = startedAt + maxCycleMs;
  if (
    !Number.isSafeInteger(startedAt) ||
    startedAt < 0 ||
    !Number.isSafeInteger(deadlineAt)
  ) {
    throw new Error("Inbox poll clock is invalid");
  }
  const sessionFactory = options.sessionFactory ?? createPinnedImapSession;
  const discoveryLimit = Math.min(
    75,
    options.maxInboxes * MAX_DISCOVERY_MULTIPLIER,
  );
  const inboxes = await client.execute({
    sql: `
      SELECT inbox.id, inbox.tenant_id, inbox.provider, inbox.smtp_host,
             inbox.imap_host, inbox.imap_port, inbox.imap_secure,
             inbox.encrypted_credentials, inbox.credential_key_version,
             inbox.credential_binding, cursor.uid_validity, cursor.last_uid,
             cursor.highest_modseq
      FROM sending_inboxes AS inbox
      LEFT JOIN imap_cursors AS cursor
        ON cursor.tenant_id = inbox.tenant_id AND cursor.inbox_id = inbox.id
       AND cursor.mailbox = 'INBOX'
      WHERE inbox.status = 'active'
        AND inbox.imap_host IS NOT NULL AND inbox.imap_port IS NOT NULL
      ORDER BY COALESCE(inbox.last_poll_at, 0), inbox.id
      LIMIT ?
    `,
    args: [discoveryLimit],
  });

  let inboxesPolled = 0;
  let messagesProcessed = 0;
  let failures = 0;
  let claimed = 0;

  for (const row of inboxes.rows) {
    if (claimed >= options.maxInboxes || now() >= deadlineAt) break;
    const inboxId = String(row.id);
    const tenantId = String(row.tenant_id);
    const claimTime = now();
    const leaseId = await claimInboxLease(
      client,
      tenantId,
      inboxId,
      claimTime,
      maxCycleMs + INBOX_LEASE_GRACE_MS,
    );
    if (!leaseId) continue;
    claimed += 1;
    const beforeInbox = messagesProcessed;

    try {
      const host = String(row.imap_host);
      const smtpHost = row.smtp_host == null ? "" : String(row.smtp_host);
      const provider = String(row.provider);
      const oauthProvider =
        provider === "google" || provider === "microsoft"
          ? (provider as OAuthProvider)
          : null;
      if (oauthProvider) {
        try {
          assertOAuthProviderHost(oauthProvider, "smtp", smtpHost);
          assertOAuthProviderHost(oauthProvider, "imap", host);
        } catch (error) {
          if (error instanceof OAuthAccessTokenError) {
            throw new KnownPollError("imap_provider_host_invalid", true);
          }
          throw error;
        }
      }
      let credentials: ReturnType<typeof parseInboxCredentialPayload>;
      try {
        const binding = createInboxCredentialBinding({ smtpHost, imapHost: host });
        if (row.credential_binding == null || String(row.credential_binding) !== binding) {
          throw new Error("Binding mismatch");
        }
        const decrypted = decryptSecretWithKeyRing(
          credentialBytes(row.encrypted_credentials).toString("utf8"),
          options.credentialKeys,
          {
            tenantId,
            resourceType: "sending_inbox",
            resourceId: inboxId,
            field: "credentials",
            provider,
            host: binding,
          },
        );
        if (decrypted.keyVersion !== String(row.credential_key_version)) {
          throw new Error("Key version mismatch");
        }
        credentials = parseInboxCredentialPayload(decrypted.plaintext);
      } catch {
        throw new KnownPollError("inbox_credential_invalid", true);
      }

      let password = credentials.password;
      let accessToken = credentials.accessToken ?? credentials.oauth2?.accessToken;
      if (oauthProvider) {
        const storedOAuth =
          credentials.oauth2 ??
          (credentials.accessToken
            ? { accessToken: credentials.accessToken }
            : undefined);
        if (storedOAuth) {
          try {
            accessToken = await resolveOAuthAccessToken({
              provider: oauthProvider,
              purpose: "imap",
              credentials: storedOAuth,
              fetchImpl: options.fetchImpl,
              timeoutMs: remainingOperationMs(
                deadlineAt,
                now,
                10_000,
                "imap_oauth_refresh_failed",
              ),
            });
            password = undefined;
          } catch (error) {
            if (error instanceof OAuthAccessTokenError) {
              throw new KnownPollError(
                error.code === "oauth_refresh_failed"
                  ? "imap_oauth_refresh_failed"
                  : "imap_auth_failed",
                true,
              );
            }
            throw error;
          }
        }
      }
      if (!password && !accessToken) {
        throw new KnownPollError("inbox_credential_invalid", true);
      }
      const sessionConfiguration: SessionConfiguration = {
        hostname: host,
        port: Number(row.imap_port),
        secure: Boolean(row.imap_secure),
        username: credentials.username,
        ...(password ? { password } : {}),
        ...(accessToken ? { accessToken } : {}),
      };
      const session = await runWithTimeout(
        () => sessionFactory(sessionConfiguration),
        remainingOperationMs(
          deadlineAt,
          now,
          MAX_SESSION_SETUP_MS,
          "imap_session_setup_timeout",
        ),
        "imap_session_setup_timeout",
      );
      const uidValidity = () =>
        session.mailbox === false
          ? String(row.uid_validity ?? "")
          : session.mailbox.uidValidity.toString();
      const cursor = await pollImapMailbox(
        session,
        {
          mailbox: "INBOX",
          uidValidity: row.uid_validity == null ? null : String(row.uid_validity),
          lastUid: Number(row.last_uid ?? 0),
        },
        {
          maxMessages: options.maxMessagesPerInbox,
          deadlineAt,
          now,
          onMessage: async ({ uid, source }) => {
            let parsed: Awaited<ReturnType<typeof parseInboundSource>>;
            try {
              parsed = await parseInboundSource(source);
            } catch (error) {
              if (!(error instanceof InboundParseError)) throw error;
              const code = `inbound_${error.code}` as UnprocessableCode;
              if (
                await recordUnprocessableInbound(client, {
                  tenantId,
                  inboxId,
                  uidValidity: uidValidity(),
                  uid,
                  receivedAt: now(),
                  code,
                })
              ) {
                messagesProcessed += 1;
              }
              return;
            }
            const result = await processInboundMessage(
              client,
              {
                tenantId,
                inboxId,
                uidValidity: uidValidity(),
                uid,
                messageId: parsed.messageId,
                inReplyTo: parsed.inReplyTo,
                references: parsed.references,
                fromAddress: parsed.fromAddress,
                subject: parsed.subject,
                headers: parsed.headers,
                text: parsed.text,
                textTruncated: parsed.textTruncated,
                dsn: parsed.dsn,
                receivedAt: parsed.messageDate ?? now(),
              },
              { suppressionHashKey: options.suppressionHashKey, now },
            );
            if (result.status !== "duplicate") messagesProcessed += 1;
          },
          onOversized: async ({ uid, size }) => {
            if (
              await recordUnprocessableInbound(client, {
                tenantId,
                inboxId,
                uidValidity: uidValidity(),
                uid,
                receivedAt: now(),
                code: "inbound_message_oversized",
                size,
              })
            ) {
              messagesProcessed += 1;
            }
          },
          onUnprocessable: async ({ uid }) => {
            if (
              await recordUnprocessableInbound(client, {
                tenantId,
                inboxId,
                uidValidity: uidValidity(),
                uid,
                receivedAt: now(),
                code: "inbound_empty_source",
              })
            ) {
              messagesProcessed += 1;
            }
          },
        },
      );
      await persistSuccessfulCursor(client, {
        tenantId,
        inboxId,
        leaseId,
        uidValidity: cursor.uidValidity,
        lastUid: cursor.lastUid,
        highestModseq: cursor.highestModseq,
        now: now(),
        messagesProcessed: messagesProcessed - beforeInbox,
      });
      inboxesPolled += 1;
    } catch (error) {
      failures += 1;
      const failure = safeFailure(error);
      emitDiagnostic(options, inboxId, failure, error);
      await recordPollFailure(client, {
        tenantId,
        inboxId,
        leaseId,
        failure,
        now: now(),
      });
    }
  }

  return { inboxesPolled, messagesProcessed, failures };
}
