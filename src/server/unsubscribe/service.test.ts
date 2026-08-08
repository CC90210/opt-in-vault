import { randomUUID } from "node:crypto";
import { join } from "node:path";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";

import { createUnsubscribeService } from "./service";
import { createUnsubscribeToken, hashUnsubscribeToken } from "./tokens";

const TOKEN_SECRET = "test-only-unsubscribe-secret-with-enough-entropy";
const HASH_KEY = "test-only-suppression-hash-key-with-enough-entropy";

describe("unsubscribe service", () => {
  let client: Client;
  let tenantId: string;
  let token: string;

  beforeEach(async () => {
    client = createClient({ url: "file::memory:?cache=shared" });
    await migrate(drizzle(client), {
      migrationsFolder: join(process.cwd(), "drizzle"),
    });
    await client.execute("PRAGMA foreign_keys = ON");
    tenantId = `tenant-${randomUUID()}`;
    token = createUnsubscribeToken();
    await client.batch(
      [
        {
          sql: "INSERT INTO tenants (id, slug, name) VALUES (?, ?, ?)",
          args: [tenantId, tenantId, "Tenant"],
        },
        {
          sql: "INSERT INTO campaigns (id, tenant_id, name) VALUES (?, ?, 'Campaign')",
          args: [`campaign-${tenantId}`, tenantId],
        },
        {
          sql: "INSERT INTO sequence_steps (id, tenant_id, campaign_id, step_order, subject_template, body_template) VALUES (?, ?, ?, 1, 'Subject', 'Body')",
          args: [`step-${tenantId}`, tenantId, `campaign-${tenantId}`],
        },
        {
          sql: "INSERT INTO leads (id, tenant_id, email_address, normalized_email) VALUES (?, ?, 'person@example.com', 'person@example.com')",
          args: [`lead-${tenantId}`, tenantId],
        },
        {
          sql: "INSERT INTO campaign_enrollments (id, tenant_id, campaign_id, lead_id, status) VALUES (?, ?, ?, ?, 'active')",
          args: [
            `enrollment-${tenantId}`,
            tenantId,
            `campaign-${tenantId}`,
            `lead-${tenantId}`,
          ],
        },
        {
          sql: "INSERT INTO unsubscribe_tokens (id, tenant_id, lead_id, token_hash) VALUES (?, ?, ?, ?)",
          args: [
            `token-${tenantId}`,
            tenantId,
            `lead-${tenantId}`,
            hashUnsubscribeToken(token, TOKEN_SECRET),
          ],
        },
        {
          sql: "INSERT INTO send_jobs (id, tenant_id, enrollment_id, campaign_id, lead_id, step_id, status, due_at, unsubscribe_token_id) VALUES (?, ?, ?, ?, ?, ?, 'queued', 0, ?)",
          args: [
            `job-${tenantId}`,
            tenantId,
            `enrollment-${tenantId}`,
            `campaign-${tenantId}`,
            `lead-${tenantId}`,
            `step-${tenantId}`,
            `token-${tenantId}`,
          ],
        },
      ],
      "write",
    );
  });

  afterEach(() => client.close());

  it("previews without mutation, then applies idempotently and cancels queued work", async () => {
    const service = createUnsubscribeService(client, {
      tokenSecret: TOKEN_SECRET,
      suppressionHashKey: HASH_KEY,
      now: () => 1_800_000_000_000,
    });

    await expect(service.preview(token)).resolves.toEqual({ status: "active" });
    const before = await client.execute({
      sql: "SELECT COUNT(*) AS count FROM suppressions WHERE tenant_id = ?",
      args: [tenantId],
    });
    expect(Number(before.rows[0]?.count)).toBe(0);

    await expect(service.apply(token)).resolves.toEqual({ status: "unsubscribed" });
    await expect(service.apply(token)).resolves.toEqual({ status: "unsubscribed" });
    await expect(service.preview(token)).resolves.toEqual({ status: "unsubscribed" });

    const rows = await client.execute({
      sql: `
        SELECT
          (SELECT COUNT(*) FROM suppressions WHERE tenant_id = ?) AS suppressions,
          (SELECT COUNT(*) FROM suppression_events WHERE tenant_id = ?) AS events,
          (SELECT status FROM send_jobs WHERE tenant_id = ?) AS job_status,
          (SELECT used_at FROM unsubscribe_tokens WHERE tenant_id = ?) AS used_at
      `,
      args: [tenantId, tenantId, tenantId, tenantId],
    });
    expect(Number(rows.rows[0]?.suppressions)).toBe(1);
    expect(Number(rows.rows[0]?.events)).toBe(1);
    expect(rows.rows[0]?.job_status).toBe("cancelled");
    expect(Number(rows.rows[0]?.used_at)).toBe(1_800_000_000_000);
  });

  it("fails closed for expired or malformed tokens without adding suppression", async () => {
    await client.execute({
      sql: "UPDATE unsubscribe_tokens SET expires_at = ? WHERE tenant_id = ?",
      args: [100, tenantId],
    });
    const service = createUnsubscribeService(client, {
      tokenSecret: TOKEN_SECRET,
      suppressionHashKey: HASH_KEY,
      now: () => 101,
    });

    await expect(service.apply(token)).resolves.toEqual({ status: "expired" });
    await expect(service.apply("bad")).resolves.toEqual({ status: "invalid" });
    const result = await client.execute({
      sql: "SELECT COUNT(*) AS count FROM suppressions WHERE tenant_id = ?",
      args: [tenantId],
    });
    expect(Number(result.rows[0]?.count)).toBe(0);
  });
});
