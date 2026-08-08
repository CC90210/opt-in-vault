import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";

import { processInboundMessage } from "./service";

const MIGRATIONS_FOLDER = fileURLToPath(
  new URL("../../../drizzle", import.meta.url),
);
const HASH_KEY = "test-only-suppression-hash-key-with-enough-entropy";

describe("inbound message service", () => {
  let client: Client;
  let tenantId: string;
  let inboxId: string;
  let outboundMessageId: string;

  beforeEach(async () => {
    client = createClient({ url: "file::memory:?cache=shared" });
    await migrate(drizzle(client), { migrationsFolder: MIGRATIONS_FOLDER });
    await client.execute("PRAGMA foreign_keys = ON");
    tenantId = `tenant-${randomUUID()}`;
    inboxId = `inbox-${tenantId}`;
    outboundMessageId = `<message-${tenantId}@example.com>`;

    await client.batch(
      [
        {
          sql: "INSERT INTO tenants (id, slug, name) VALUES (?, ?, 'Tenant')",
          args: [tenantId, tenantId],
        },
        {
          sql: "INSERT INTO sending_domains (id, tenant_id, domain, status) VALUES (?, ?, 'example.com', 'healthy')",
          args: [`domain-${tenantId}`, tenantId],
        },
        {
          sql: "INSERT INTO sending_inboxes (id, tenant_id, domain_id, email_address, display_name, provider, encrypted_credentials, credential_key_version, status) VALUES (?, ?, ?, 'sender@example.com', 'Sender', 'smtp', X'00', 1, 'active')",
          args: [inboxId, tenantId, `domain-${tenantId}`],
        },
        {
          sql: "INSERT INTO campaigns (id, tenant_id, name, status, approved_at) VALUES (?, ?, 'Campaign', 'active', 1)",
          args: [`campaign-${tenantId}`, tenantId],
        },
        {
          sql: "INSERT INTO sequence_steps (id, tenant_id, campaign_id, step_order, subject_template, body_template) VALUES (?, ?, ?, 1, 'One', 'Body')",
          args: [`step-1-${tenantId}`, tenantId, `campaign-${tenantId}`],
        },
        {
          sql: "INSERT INTO sequence_steps (id, tenant_id, campaign_id, step_order, subject_template, body_template) VALUES (?, ?, ?, 2, 'Two', 'Body')",
          args: [`step-2-${tenantId}`, tenantId, `campaign-${tenantId}`],
        },
        {
          sql: "INSERT INTO leads (id, tenant_id, email_address, normalized_email) VALUES (?, ?, 'person@example.net', 'person@example.net')",
          args: [`lead-${tenantId}`, tenantId],
        },
        {
          sql: "INSERT INTO campaign_enrollments (id, tenant_id, campaign_id, lead_id, inbox_id, status) VALUES (?, ?, ?, ?, ?, 'active')",
          args: [
            `enrollment-${tenantId}`,
            tenantId,
            `campaign-${tenantId}`,
            `lead-${tenantId}`,
            inboxId,
          ],
        },
        {
          sql: "INSERT INTO send_jobs (id, tenant_id, enrollment_id, campaign_id, lead_id, step_id, inbox_id, status, due_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'sent', 0)",
          args: [
            `job-1-${tenantId}`,
            tenantId,
            `enrollment-${tenantId}`,
            `campaign-${tenantId}`,
            `lead-${tenantId}`,
            `step-1-${tenantId}`,
            inboxId,
          ],
        },
        {
          sql: "INSERT INTO send_jobs (id, tenant_id, enrollment_id, campaign_id, lead_id, step_id, inbox_id, status, due_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', 0)",
          args: [
            `job-2-${tenantId}`,
            tenantId,
            `enrollment-${tenantId}`,
            `campaign-${tenantId}`,
            `lead-${tenantId}`,
            `step-2-${tenantId}`,
            inboxId,
          ],
        },
        {
          sql: "INSERT INTO outbound_messages (id, tenant_id, job_id, lead_id, inbox_id, message_id, subject, body_text, status, sent_at) VALUES (?, ?, ?, ?, ?, ?, 'Hello', 'Body', 'accepted', 1)",
          args: [
            `outbound-${tenantId}`,
            tenantId,
            `job-1-${tenantId}`,
            `lead-${tenantId}`,
            inboxId,
            outboundMessageId,
          ],
        },
      ],
      "write",
    );
  });

  afterEach(() => client.close());

  function inbound(
    uid: number,
    text: string,
    overrides: Partial<Parameters<typeof processInboundMessage>[1]> = {},
  ): Parameters<typeof processInboundMessage>[1] {
    return {
      tenantId,
      inboxId,
      uidValidity: "42",
      uid,
      messageId: `<incoming-${uid}@example.net>`,
      inReplyTo: outboundMessageId,
      references: [outboundMessageId],
      fromAddress: "person@example.net",
      subject: "Re: Hello",
      headers: {},
      text,
      receivedAt: 1_800_000_000_000,
      ...overrides,
    };
  }

  it("persists once, pauses a human reply, classifies it, and emits one interested notification", async () => {
    const first = await processInboundMessage(client, inbound(1, "Yes, let's book a call"), {
      suppressionHashKey: HASH_KEY,
      now: () => 1_800_000_000_100,
    });
    const replay = await processInboundMessage(client, inbound(1, "Yes, let's book a call"), {
      suppressionHashKey: HASH_KEY,
      now: () => 1_800_000_000_200,
    });

    expect(first).toMatchObject({ status: "processed", classification: "interested" });
    expect(replay).toEqual({ status: "duplicate" });
    const state = await client.execute({
      sql: `
        SELECT
          (SELECT status FROM campaign_enrollments WHERE tenant_id = ?) AS enrollment_status,
          (SELECT status FROM leads WHERE tenant_id = ?) AS lead_status,
          (SELECT COUNT(*) FROM notifications WHERE tenant_id = ?) AS notifications,
          (SELECT COUNT(*) FROM reply_events WHERE tenant_id = ?) AS reply_events,
          (SELECT status FROM send_jobs WHERE id = ?) AS next_job_status
      `,
      args: [tenantId, tenantId, tenantId, tenantId, `job-2-${tenantId}`],
    });
    expect(state.rows[0]).toMatchObject({
      enrollment_status: "replied",
      lead_status: "replied",
      notifications: 1,
      reply_events: 1,
      next_job_status: "cancelled",
    });
  });

  it("applies unsubscribe through the tenant suppression firewall", async () => {
    const result = await processInboundMessage(client, inbound(2, "Please unsubscribe me"), {
      suppressionHashKey: HASH_KEY,
      now: () => 1_800_000_000_100,
    });

    expect(result).toMatchObject({ status: "processed", classification: "unsubscribe" });
    const state = await client.execute({
      sql: `
        SELECT
          (SELECT COUNT(*) FROM suppressions WHERE tenant_id = ?) AS suppressions,
          (SELECT status FROM campaign_enrollments WHERE tenant_id = ?) AS enrollment_status
      `,
      args: [tenantId, tenantId],
    });
    expect(state.rows[0]).toMatchObject({
      suppressions: 1,
      enrollment_status: "unsubscribed",
    });
  });

  it("extends an out-of-office enrollment without treating it as a human reply", async () => {
    await client.execute({
      sql: "UPDATE send_jobs SET status = 'leased', lease_token_hash = 'active-lease', lease_expires_at = ? WHERE tenant_id = ? AND id = ?",
      args: [1_800_000_030_000, tenantId, `job-2-${tenantId}`],
    });
    const result = await processInboundMessage(
      client,
      inbound(3, "I am away", {
        subject: "Automatic reply: away",
        headers: { "auto-submitted": "auto-replied" },
      }),
      { suppressionHashKey: HASH_KEY, now: () => 1_800_000_000_000 },
    );

    expect(result).toMatchObject({ status: "processed", classification: "out_of_office" });
    const enrollment = await client.execute({
      sql: "SELECT enrollment.status, enrollment.next_send_at, job.status AS job_status, job.due_at, job.lease_token_hash FROM campaign_enrollments AS enrollment JOIN send_jobs AS job ON job.tenant_id = enrollment.tenant_id AND job.enrollment_id = enrollment.id WHERE enrollment.tenant_id = ? AND job.id = ?",
      args: [tenantId, `job-2-${tenantId}`],
    });
    expect(enrollment.rows[0]).toMatchObject({
      status: "active",
      next_send_at: 1_800_604_800_000,
      job_status: "queued",
      due_at: 1_800_604_800_000,
      lease_token_hash: null,
    });
  });

  it("never reopens a terminal enrollment for an out-of-office message", async () => {
    await client.execute({
      sql: "UPDATE campaign_enrollments SET status = 'replied', pause_reason = 'interested' WHERE tenant_id = ?",
      args: [tenantId],
    });
    const result = await processInboundMessage(
      client,
      inbound(30, "I am away", {
        subject: "Automatic reply: away",
        headers: { "auto-submitted": "auto-replied" },
      }),
      { suppressionHashKey: HASH_KEY, now: () => 1_800_000_000_000 },
    );
    expect(result).toMatchObject({ status: "processed", classification: "out_of_office" });
    const state = await client.execute({
      sql: "SELECT enrollment.status, enrollment.next_send_at, event.effect_applied_at FROM campaign_enrollments AS enrollment JOIN reply_events AS event ON event.tenant_id = enrollment.tenant_id WHERE enrollment.tenant_id = ?",
      args: [tenantId],
    });
    expect(state.rows[0]).toMatchObject({
      status: "replied",
      next_send_at: null,
      effect_applied_at: null,
    });
  });

  it("matches a structured DSN and applies a tenant-wide hard-bounce suppression", async () => {
    const result = await processInboundMessage(
      client,
      inbound(31, "Delivery failed", {
        inReplyTo: null,
        references: [],
        fromAddress: "mailer-daemon@example.net",
        subject: "Delivery Status Notification",
        headers: {
          "auto-submitted": "auto-generated",
          "content-type": "multipart/report; report-type=delivery-status",
        },
        dsn: {
          originalMessageId: outboundMessageId,
          finalRecipient: "person@example.net",
          action: "failed",
          status: "5.1.1",
        },
      }),
      { suppressionHashKey: HASH_KEY, now: () => 1_800_000_000_000 },
    );

    expect(result).toMatchObject({
      status: "processed",
      classification: "bounce",
      matchedBy: "dsn_message_id",
    });
    const state = await client.execute({
      sql: "SELECT (SELECT COUNT(*) FROM suppressions WHERE tenant_id = ?) AS suppressions, (SELECT status FROM leads WHERE tenant_id = ?) AS lead_status, (SELECT status FROM campaign_enrollments WHERE tenant_id = ?) AS enrollment_status, (SELECT status FROM send_jobs WHERE id = ?) AS next_job_status",
      args: [tenantId, tenantId, tenantId, `job-2-${tenantId}`],
    });
    expect(state.rows[0]).toMatchObject({
      suppressions: 1,
      lead_status: "bounced",
      enrollment_status: "bounced",
      next_job_status: "cancelled",
    });
  });

  it("stores unmatched mail without applying lead effects", async () => {
    const result = await processInboundMessage(
      client,
      inbound(4, "Hello", {
        inReplyTo: null,
        references: [],
        fromAddress: "unknown@example.net",
      }),
      { suppressionHashKey: HASH_KEY },
    );
    expect(result).toMatchObject({ status: "unmatched" });
    const enrollment = await client.execute({
      sql: "SELECT status FROM campaign_enrollments WHERE tenant_id = ?",
      args: [tenantId],
    });
    expect(enrollment.rows[0]?.status).toBe("active");
  });
});
