import { join } from "node:path";
import { randomUUID } from "node:crypto";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";

import {
  addSuppression,
  isSuppressed,
  normalizeEmail,
  normalizePhone,
} from "./service";

const HASH_KEY = "test-only-suppression-hash-key-with-enough-entropy";

async function seedTenant(client: Client, tenantId: string) {
  await client.execute({
    sql: "INSERT INTO tenants (id, slug, name) VALUES (?, ?, ?)",
    args: [tenantId, tenantId, tenantId],
  });
}

describe("suppression service", () => {
  let client: Client;
  let tenantA: string;
  let tenantB: string;

  beforeEach(async () => {
    client = createClient({ url: "file::memory:?cache=shared" });
    await migrate(drizzle(client), {
      migrationsFolder: join(process.cwd(), "drizzle"),
    });
    await client.execute("PRAGMA foreign_keys = ON");
    tenantA = `tenant-a-${randomUUID()}`;
    tenantB = `tenant-b-${randomUUID()}`;
    await seedTenant(client, tenantA);
    await seedTenant(client, tenantB);
  });

  afterEach(() => client.close());

  it("normalizes email and E.164 phone identifiers without provider-specific rewriting", () => {
    expect(normalizeEmail("  Person+Tag@Example.COM ")).toBe(
      "person+tag@example.com",
    );
    expect(normalizePhone("+1 (514) 555-0100")).toBe("+15145550100");
    expect(() => normalizeEmail("not-an-email")).toThrow();
    expect(() => normalizePhone("514-555-0100")).toThrow();
  });

  it("is idempotent within one tenant and isolated across tenants", async () => {
    const first = await addSuppression(client, {
      tenantId: tenantA,
      identifierType: "email",
      identifier: "Person@Example.com",
      reason: "unsubscribe",
      source: "one_click",
      hashKey: HASH_KEY,
    });
    const replay = await addSuppression(client, {
      tenantId: tenantA,
      identifierType: "email",
      identifier: "person@example.com",
      reason: "unsubscribe",
      source: "one_click",
      hashKey: HASH_KEY,
    });

    expect(first.created).toBe(true);
    expect(replay.created).toBe(false);
    expect(replay.suppressionId).toBe(first.suppressionId);
    await expect(
      isSuppressed(client, {
        tenantId: tenantA,
        identifierType: "email",
        identifier: "PERSON@example.com",
        hashKey: HASH_KEY,
      }),
    ).resolves.toBe(true);
    await expect(
      isSuppressed(client, {
        tenantId: tenantB,
        identifierType: "email",
        identifier: "person@example.com",
        hashKey: HASH_KEY,
      }),
    ).resolves.toBe(false);

    const rows = await client.execute(
      "SELECT tenant_id, identifier_hash FROM suppressions ORDER BY tenant_id",
    );
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]?.identifier_hash).not.toContain("person@example.com");
  });

  it("cancels queued work tenant-wide while leaving another tenant untouched", async () => {
    for (const tenantId of [tenantA, tenantB]) {
      await client.batch(
        [
          {
            sql: "INSERT INTO campaigns (id, tenant_id, name) VALUES (?, ?, ?)",
            args: [`campaign-${tenantId}`, tenantId, "Sequence"],
          },
          {
            sql: "INSERT INTO sequence_steps (id, tenant_id, campaign_id, step_order, subject_template, body_template) VALUES (?, ?, ?, 1, 'Hi', 'Body')",
            args: [`step-${tenantId}`, tenantId, `campaign-${tenantId}`],
          },
          {
            sql: "INSERT INTO leads (id, tenant_id, email_address, normalized_email) VALUES (?, ?, ?, ?)",
            args: [`lead-${tenantId}`, tenantId, "person@example.com", "person@example.com"],
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
            sql: "INSERT INTO send_jobs (id, tenant_id, enrollment_id, campaign_id, lead_id, step_id, status, due_at) VALUES (?, ?, ?, ?, ?, ?, 'queued', 0)",
            args: [
              `job-${tenantId}`,
              tenantId,
              `enrollment-${tenantId}`,
              `campaign-${tenantId}`,
              `lead-${tenantId}`,
              `step-${tenantId}`,
            ],
          },
        ],
        "write",
      );
    }

    const result = await addSuppression(client, {
      tenantId: tenantA,
      identifierType: "email",
      identifier: "person@example.com",
      reason: "unsubscribe",
      source: "reply",
      hashKey: HASH_KEY,
    });

    expect(result.cancelledJobs).toBe(1);
    const jobs = await client.execute(
      "SELECT tenant_id, status FROM send_jobs ORDER BY tenant_id",
    );
    expect(jobs.rows).toEqual([
      expect.objectContaining({ tenant_id: tenantA, status: "cancelled" }),
      expect.objectContaining({ tenant_id: tenantB, status: "queued" }),
    ]);
    const lead = await client.execute({
      sql: "SELECT status FROM leads WHERE tenant_id = ? AND id = ?",
      args: [tenantA, `lead-${tenantA}`],
    });
    expect(lead.rows[0]?.status).toBe("unsubscribed");
  });
});
