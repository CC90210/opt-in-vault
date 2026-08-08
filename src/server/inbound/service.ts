import "server-only";

import { randomUUID } from "node:crypto";

import type { Client, Transaction } from "@libsql/client";

import { addSuppressionWithinTransaction } from "@/server/suppression/service";

import { classifyInbound, type InboundClassification } from "./classify";
import { matchInboundReply, type ReplyCandidate } from "./match";
import type { ParsedDeliveryStatus } from "./parse";

const MAX_REFERENCES = 50;
const MAX_HEADER_JSON_LENGTH = 32_000;
const MAX_SNIPPET_LENGTH = 4_000;
const MAX_CLASSIFICATION_TEXT_LENGTH = 256_000;
const OUT_OF_OFFICE_DELAY_MS = 7 * 24 * 60 * 60 * 1_000;

export type InboundMessageInput = {
  tenantId: string;
  inboxId: string;
  uidValidity: string;
  uid: number;
  messageId: string | null;
  inReplyTo: string | null;
  references: string[];
  fromAddress: string;
  subject: string;
  headers: Record<string, string | undefined>;
  text: string;
  textTruncated?: boolean;
  dsn?: ParsedDeliveryStatus | null;
  receivedAt: number;
};

type InboundServiceOptions = {
  suppressionHashKey: string;
  now?: () => number;
};

function safeHeaders(
  headers: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const selected: Record<string, string> = {};
  const allowed = new Set([
    "auto-submitted",
    "content-type",
    "precedence",
    "x-autoreply",
    "x-autorespond",
  ]);
  for (const [rawName, rawValue] of Object.entries(headers)) {
    const name = rawName.trim().toLowerCase();
    if (!allowed.has(name) || rawValue === undefined) continue;
    const value = rawValue.slice(0, 2_000).replace(/[\u0000]/g, "");
    selected[name] = value;
  }
  const encoded = JSON.stringify(selected);
  if (encoded.length > MAX_HEADER_JSON_LENGTH) {
    throw new Error("Inbound headers exceed the storage limit");
  }
  return selected;
}

function validateInput(input: InboundMessageInput): void {
  if (!input.tenantId.trim() || !input.inboxId.trim() || !input.uidValidity.trim()) {
    throw new Error("Inbound mailbox identity is required");
  }
  if (!Number.isSafeInteger(input.uid) || input.uid < 1) {
    throw new Error("Inbound UID is invalid");
  }
  if (!Number.isSafeInteger(input.receivedAt) || input.receivedAt < 0) {
    throw new Error("Inbound received timestamp is invalid");
  }
  if (input.references.length > MAX_REFERENCES) {
    throw new Error("Inbound reference count exceeds the limit");
  }
  if (
    input.fromAddress.length > 320 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.fromAddress) ||
    /[\u0000-\u001f\u007f]/.test(input.fromAddress)
  ) {
    throw new Error("Inbound sender address is invalid");
  }
  for (const messageId of [input.messageId, input.inReplyTo]) {
    if (
      messageId !== null &&
      (messageId.length > 998 || !/^<[^<>\s]+@[^<>\s]+>$/.test(messageId))
    ) {
      throw new Error("Inbound message identity is invalid");
    }
  }
  for (const reference of input.references) {
    if (reference.length > 998 || /[\r\n\u0000]/.test(reference)) {
      throw new Error("Inbound reference is invalid");
    }
  }
  if (
    input.dsn &&
    (!/^(?:failed|delayed|delivered|relayed|expanded)$/.test(input.dsn.action) ||
      !/^[245]\.\d{1,3}\.\d{1,3}$/.test(input.dsn.status) ||
      (input.dsn.originalMessageId !== null &&
        !/^<[^<>\s]+@[^<>\s]+>$/.test(input.dsn.originalMessageId)) ||
      (input.dsn.finalRecipient !== null &&
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.dsn.finalRecipient)))
  ) {
    throw new Error("Inbound delivery status is invalid");
  }
}

function candidatesFromRows(
  tenantId: string,
  rows: readonly Record<string, unknown>[],
): ReplyCandidate[] {
  return rows.map((row) => ({
    tenantId,
    outboundMessageId: String(row.outbound_id),
    messageId: String(row.message_id),
    enrollmentId: String(row.enrollment_id),
    leadId: String(row.lead_id),
    recipientAddress: String(row.normalized_email),
  }));
}

async function candidateMessages(
  transaction: Transaction,
  input: InboundMessageInput,
): Promise<ReplyCandidate[]> {
  const referenced = [
    input.dsn?.originalMessageId,
    input.inReplyTo,
    ...input.references,
  ]
    .filter((value): value is string => Boolean(value))
    .map((value) => value.trim().toLowerCase());
  if (referenced.length > 0) {
    const result = await transaction.execute({
      sql: `
        SELECT message.id AS outbound_id, message.message_id,
               job.enrollment_id, message.lead_id, lead.normalized_email
        FROM outbound_messages AS message
        JOIN send_jobs AS job
          ON job.tenant_id = message.tenant_id AND job.id = message.job_id
        JOIN leads AS lead
          ON lead.tenant_id = message.tenant_id AND lead.id = message.lead_id
        JOIN campaign_enrollments AS enrollment
          ON enrollment.tenant_id = job.tenant_id AND enrollment.id = job.enrollment_id
        WHERE message.tenant_id = ?
          AND message.status IN ('accepted', 'unknown')
          AND LOWER(message.message_id) IN (${referenced.map(() => "?").join(", ")})
          AND enrollment.status IN ('active', 'paused', 'replied')
        ORDER BY COALESCE(message.sent_at, message.created_at) DESC
        LIMIT 101
      `,
      args: [input.tenantId, ...referenced],
    });
    if (result.rows.length > 100) return [];
    if (result.rows.length > 0) {
      return candidatesFromRows(
        input.tenantId,
        result.rows as unknown as readonly Record<string, unknown>[],
      );
    }
  }

  const recipient =
    input.dsn?.finalRecipient?.trim().toLowerCase() ??
    input.fromAddress.trim().toLowerCase();
  const result = await transaction.execute({
    sql: `
      SELECT message.id AS outbound_id, message.message_id,
             job.enrollment_id, message.lead_id, lead.normalized_email
      FROM outbound_messages AS message
      JOIN send_jobs AS job
        ON job.tenant_id = message.tenant_id AND job.id = message.job_id
      JOIN leads AS lead
        ON lead.tenant_id = message.tenant_id AND lead.id = message.lead_id
      JOIN campaign_enrollments AS enrollment
        ON enrollment.tenant_id = job.tenant_id AND enrollment.id = job.enrollment_id
      WHERE message.tenant_id = ?
        AND message.status IN ('accepted', 'unknown')
        AND lead.normalized_email = ?
        AND enrollment.status IN ('active', 'paused', 'replied')
      ORDER BY COALESCE(message.sent_at, message.created_at) DESC
      LIMIT 101
    `,
    args: [input.tenantId, recipient],
  });
  if (result.rows.length > 100) return [];
  return candidatesFromRows(
    input.tenantId,
    result.rows as unknown as readonly Record<string, unknown>[],
  );
}

async function cancelQueuedWork(
  transaction: Transaction,
  tenantId: string,
  enrollmentId: string,
  now: number,
  reason: string,
): Promise<void> {
  await transaction.execute({
    sql: `
      UPDATE send_jobs
      SET status = 'cancelled', lease_token_hash = NULL, lease_expires_at = NULL,
          last_error_code = ?, updated_at = ?
      WHERE tenant_id = ? AND enrollment_id = ?
        AND status IN ('queued', 'leased')
    `,
    args: [reason, now, tenantId, enrollmentId],
  });
}

async function applyMatchedEffect(
  transaction: Transaction,
  match: NonNullable<ReturnType<typeof matchInboundReply>>,
  input: InboundMessageInput,
  classification: InboundClassification,
  automated: boolean,
  inboundId: string,
  options: Required<InboundServiceOptions>,
): Promise<boolean> {
  const now = options.now();
  let genericHumanEffect = false;
  if (!automated) {
    const paused = await transaction.execute({
      sql: `
        UPDATE campaign_enrollments
        SET status = 'paused', pause_reason = 'reply_received', updated_at = ?
        WHERE tenant_id = ? AND id = ? AND status IN ('pending', 'active', 'paused')
      `,
      args: [now, input.tenantId, match.enrollmentId],
    });
    genericHumanEffect = paused.rowsAffected > 0;
    if (genericHumanEffect) {
      await cancelQueuedWork(
        transaction,
        input.tenantId,
        match.enrollmentId,
        now,
        "reply_received",
      );
    }
  }

  if (classification === "unsubscribe") {
    await addSuppressionWithinTransaction(transaction, {
      tenantId: input.tenantId,
      identifierType: "email",
      identifier: match.recipientAddress,
      reason: "unsubscribe",
      source: "reply",
      hashKey: options.suppressionHashKey,
    });
    return true;
  }

  if (classification === "out_of_office") {
    const deferUntil = now + OUT_OF_OFFICE_DELAY_MS;
    const updated = await transaction.execute({
      sql: `
        UPDATE campaign_enrollments
        SET pause_reason = 'out_of_office', next_send_at = ?, updated_at = ?
        WHERE tenant_id = ? AND id = ? AND status = 'active'
        RETURNING id
      `,
      args: [deferUntil, now, input.tenantId, match.enrollmentId],
    });
    if (updated.rows.length === 0) return false;
    // Clearing a live lease makes its dispatch CAS fail while keeping the same
    // unique job available for a future claim after the OOO window.
    await transaction.execute({
      sql: `
        UPDATE send_jobs
        SET status = 'queued', due_at = CASE WHEN due_at < ? THEN ? ELSE due_at END,
            lease_token_hash = NULL, lease_expires_at = NULL,
            last_error_code = 'out_of_office', updated_at = ?
        WHERE tenant_id = ? AND enrollment_id = ? AND status IN ('queued', 'leased')
      `,
      args: [
        deferUntil,
        deferUntil,
        now,
        input.tenantId,
        match.enrollmentId,
      ],
    });
    return true;
  }

  if (classification === "bounce") {
    await addSuppressionWithinTransaction(transaction, {
      tenantId: input.tenantId,
      identifierType: "email",
      identifier: match.recipientAddress,
      reason: "bounce",
      source: "delivery_status",
      hashKey: options.suppressionHashKey,
    });
    await transaction.execute({
      sql: "UPDATE campaign_enrollments SET status = 'bounced', pause_reason = 'bounce', updated_at = ? WHERE tenant_id = ? AND id = ? AND status IN ('pending', 'active', 'paused', 'unsubscribed')",
      args: [now, input.tenantId, match.enrollmentId],
    });
    await transaction.execute({
      sql: "UPDATE leads SET status = 'bounced', updated_at = ? WHERE tenant_id = ? AND id = ? AND status IN ('active', 'unsubscribed')",
      args: [now, input.tenantId, match.leadId],
    });
    await cancelQueuedWork(
      transaction,
      input.tenantId,
      match.enrollmentId,
      now,
      "bounce",
    );
    return true;
  }

  if (classification === "interested" || classification === "not_interested") {
    const enrollment = await transaction.execute({
      sql: "UPDATE campaign_enrollments SET status = 'replied', pause_reason = ?, updated_at = ? WHERE tenant_id = ? AND id = ? AND status IN ('pending', 'active', 'paused')",
      args: [classification, now, input.tenantId, match.enrollmentId],
    });
    if (enrollment.rowsAffected > 0) {
      await transaction.execute({
        sql: "UPDATE leads SET status = 'replied', updated_at = ? WHERE tenant_id = ? AND id = ? AND status = 'active'",
        args: [now, input.tenantId, match.leadId],
      });
    }
    if (classification === "interested" && enrollment.rowsAffected > 0) {
      await transaction.execute({
        sql: `
          INSERT INTO notifications
            (id, tenant_id, type, payload_json, status, next_attempt_at)
          VALUES (?, ?, 'interested_reply', ?, 'pending', ?)
        `,
        args: [
          randomUUID(),
          input.tenantId,
          JSON.stringify({
            enrollmentId: match.enrollmentId,
            inboundMessageId: inboundId,
            leadId: match.leadId,
          }),
          now,
        ],
      });
    }
    return enrollment.rowsAffected > 0;
  }
  return genericHumanEffect;
}

export async function processInboundMessage(
  client: Client,
  input: InboundMessageInput,
  options: InboundServiceOptions,
): Promise<
  | { status: "duplicate" }
  | { status: "unmatched"; classification: InboundClassification }
  | { status: "processed"; classification: InboundClassification; matchedBy: string }
> {
  validateInput(input);
  const headers = safeHeaders(input.headers);
  const storedHeaders = {
    ...headers,
    ...((input.textTruncated ?? false) ||
    input.text.length > MAX_CLASSIFICATION_TEXT_LENGTH
      ? { "x-opt-in-vault-text-truncated": "true" }
      : {}),
  };
  const resolvedOptions: Required<InboundServiceOptions> = {
    suppressionHashKey: options.suppressionHashKey,
    now: options.now ?? Date.now,
  };
  const transaction = await client.transaction("write");
  try {
    const inboundId = randomUUID();
    const inserted = await transaction.execute({
      sql: `
        INSERT INTO inbound_messages
          (id, tenant_id, inbox_id, uid_validity, uid, message_id, in_reply_to,
           references_json, from_address, subject, headers_json, text_snippet,
           classification, received_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (tenant_id, inbox_id, uid_validity, uid) DO NOTHING
        RETURNING id
      `,
      args: [
        inboundId,
        input.tenantId,
        input.inboxId,
        input.uidValidity,
        input.uid,
        input.messageId,
        input.inReplyTo,
        JSON.stringify(input.references),
        input.fromAddress.trim().toLowerCase(),
        input.subject.slice(0, 998),
        JSON.stringify(storedHeaders),
        input.text.slice(0, MAX_SNIPPET_LENGTH),
        null,
        input.receivedAt,
      ],
    });
    if (inserted.rows.length === 0) {
      await transaction.commit();
      return { status: "duplicate" };
    }

    const hardBounce =
      input.dsn?.action === "failed" && /^5\./.test(input.dsn.status);
    const classification = classifyInbound({
      text: input.text.slice(0, MAX_CLASSIFICATION_TEXT_LENGTH),
      subject: input.subject.slice(0, 998),
      headers,
      structuredDsn: hardBounce,
    });
    await transaction.execute({
      sql: "UPDATE inbound_messages SET classification = ? WHERE tenant_id = ? AND id = ?",
      args: [classification.classification, input.tenantId, inboundId],
    });

    const candidates = await candidateMessages(transaction, input);
    const match = matchInboundReply(
      {
        ...input,
        dsnOriginalMessageId: input.dsn?.originalMessageId,
        dsnFinalRecipient: input.dsn?.finalRecipient,
      },
      candidates,
    );
    const effectApplied = match
      ? await applyMatchedEffect(
          transaction,
          match,
          input,
          classification.classification,
          classification.automated,
          inboundId,
          resolvedOptions,
        )
      : false;
    await transaction.execute({
      sql: `
        INSERT INTO reply_events
          (id, tenant_id, inbound_message_id, enrollment_id, lead_id,
           classification, effect_applied_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      args: [
        randomUUID(),
        input.tenantId,
        inboundId,
        match?.enrollmentId ?? null,
        match?.leadId ?? null,
        classification.classification,
        effectApplied ? resolvedOptions.now() : null,
      ],
    });
    if (!match) {
      await transaction.commit();
      return { status: "unmatched", classification: classification.classification };
    }

    await transaction.commit();
    return {
      status: "processed",
      classification: classification.classification,
      matchedBy: match.matchedBy,
    };
  } catch (error) {
    if (!transaction.closed) await transaction.rollback();
    throw error;
  }
}
