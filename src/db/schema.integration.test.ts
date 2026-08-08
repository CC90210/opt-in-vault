import { join } from "node:path";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";

const REQUIRED_TABLES = [
  "tenants",
  "tenant_api_keys",
  "capture_sites",
  "sending_domains",
  "dns_checks",
  "sending_inboxes",
  "campaigns",
  "sequence_steps",
  "leads",
  "campaign_enrollments",
  "send_jobs",
  "delivery_attempts",
  "outbound_messages",
  "inbox_daily_usage",
  "worker_runs",
  "imap_cursors",
  "inbound_messages",
  "reply_events",
  "consent_logs",
  "consent_certificates",
  "suppressions",
  "suppression_events",
  "unsubscribe_tokens",
  "notifications",
  "audit_events",
  "rate_limit_buckets",
] as const;

const TENANT_OWNED_TABLES = REQUIRED_TABLES.filter(
  (table) => table !== "tenants",
);

const NON_CASCADING_EVIDENCE_TABLES = [
  "consent_logs",
  "consent_certificates",
  "suppressions",
  "suppression_events",
  "delivery_attempts",
  "outbound_messages",
  "audit_events",
] as const;

describe("database schema migration", () => {
  let client: Client;

  beforeEach(async () => {
    client = createClient({ url: "file::memory:" });

    await migrate(drizzle(client), {
      migrationsFolder: join(process.cwd(), "drizzle"),
    });
    await client.execute("PRAGMA foreign_keys = ON");
  });

  afterEach(async () => {
    client?.close();
  });

  it("executes the checked-in migration and creates every required table", async () => {
    const result = await client.execute(
      "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name",
    );
    const names = result.rows.map((row) => String(row.name));

    expect(names).toEqual(expect.arrayContaining([...REQUIRED_TABLES]));
  });

  it("enables foreign keys and leaves a clean foreign-key check", async () => {
    const pragma = await client.execute("PRAGMA foreign_keys");
    const violations = await client.execute("PRAGMA foreign_key_check");

    expect(Number(pragma.rows[0]?.foreign_keys)).toBe(1);
    expect(violations.rows).toHaveLength(0);
  });

  it("makes tenant ownership non-null on every tenant-owned table", async () => {
    for (const table of TENANT_OWNED_TABLES) {
      const columns = await client.execute(`PRAGMA table_info(${table})`);
      const tenantId = columns.rows.find((column) => column.name === "tenant_id");

      expect(tenantId, `${table}.tenant_id is missing`).toBeDefined();
      expect(Number(tenantId?.notnull), `${table}.tenant_id is nullable`).toBe(1);
    }
  });

  it("rejects forged cross-tenant composite references", async () => {
    await seedTenants(client);
    await client.execute(
      "INSERT INTO campaigns (id, tenant_id, name) VALUES ('campaign-a', 'tenant-a', 'A')",
    );

    await expect(
      client.execute(
        "INSERT INTO sequence_steps (id, tenant_id, campaign_id, step_order, subject_template, body_template) VALUES ('step-b', 'tenant-b', 'campaign-a', 1, 'Hello', 'Body')",
      ),
    ).rejects.toThrow(/foreign key/i);
  });

  it("rejects updates and deletes of consent evidence", async () => {
    await client.execute(
      "INSERT INTO tenants (id, slug, name) VALUES ('tenant-a', 'tenant-a', 'Tenant A')",
    );
    await client.execute(
      "INSERT INTO consent_logs (id, tenant_id, subject_identifier_hash, controller, purpose, disclosure_version, affirmative_action, canonical_payload, payload_sha256, signature_hmac, signature_key_version, idempotency_key, occurred_at) VALUES ('consent-a', 'tenant-a', 'subject-hash', 'Controller', 'Updates', 'v1', 'submit', '{}', 'payload-hash', 'signature', 1, 'idem-a', 1000)",
    );

    await expect(
      client.execute(
        "UPDATE consent_logs SET canonical_payload = '{\"changed\":true}' WHERE id = 'consent-a'",
      ),
    ).rejects.toThrow(/immutable/i);
    await expect(
      client.execute("DELETE FROM consent_logs WHERE id = 'consent-a'"),
    ).rejects.toThrow(/immutable/i);
  });

  it("enforces tenant-wide suppression uniqueness without cross-tenant collisions", async () => {
    await seedTenants(client);
    await client.execute(
      "INSERT INTO suppressions (id, tenant_id, identifier_type, identifier_hash, reason) VALUES ('suppression-a', 'tenant-a', 'email', 'same-hash', 'manual')",
    );

    await expect(
      client.execute(
        "INSERT INTO suppressions (id, tenant_id, identifier_type, identifier_hash, reason) VALUES ('suppression-a2', 'tenant-a', 'email', 'same-hash', 'unsubscribe')",
      ),
    ).rejects.toThrow(/unique/i);
    await expect(
      client.execute(
        "INSERT INTO suppressions (id, tenant_id, identifier_type, identifier_hash, reason) VALUES ('suppression-b', 'tenant-b', 'email', 'same-hash', 'manual')",
      ),
    ).resolves.toBeDefined();
  });

  it("enforces sending-inbox limits and status values", async () => {
    await client.execute(
      "INSERT INTO tenants (id, slug, name) VALUES ('tenant-a', 'tenant-a', 'Tenant A')",
    );
    await client.execute(
      "INSERT INTO sending_domains (id, tenant_id, domain) VALUES ('domain-a', 'tenant-a', 'example.test')",
    );

    const validInbox =
      "INSERT INTO sending_inboxes (id, tenant_id, domain_id, email_address, display_name, provider, encrypted_credentials, credential_key_version, daily_limit, status)";
    await expect(
      client.execute(
        `${validInbox} VALUES ('inbox-a', 'tenant-a', 'domain-a', 'a@example.test', 'A', 'smtp', X'00', 1, 0, 'active')`,
      ),
    ).rejects.toThrow(/check/i);
    await expect(
      client.execute(
        `${validInbox} VALUES ('inbox-b', 'tenant-a', 'domain-a', 'b@example.test', 'B', 'smtp', X'00', 1, 10, 'invented')`,
      ),
    ).rejects.toThrow(/check/i);
  });

  it("defaults campaigns to dry-run and 180-450 second jitter", async () => {
    await client.execute(
      "INSERT INTO tenants (id, slug, name) VALUES ('tenant-a', 'tenant-a', 'Tenant A')",
    );
    await client.execute(
      "INSERT INTO campaigns (id, tenant_id, name) VALUES ('campaign-a', 'tenant-a', 'A')",
    );
    const campaign = await client.execute(
      "SELECT dry_run, jitter_min_seconds, jitter_max_seconds FROM campaigns WHERE id = 'campaign-a'",
    );

    expect(campaign.rows[0]).toMatchObject({
      dry_run: 1,
      jitter_min_seconds: 180,
      jitter_max_seconds: 450,
    });
  });

  it("creates the indexes used to claim due work", async () => {
    const result = await client.execute(
      "SELECT name FROM sqlite_schema WHERE type = 'index' AND name IN ('send_jobs_due_idx', 'campaign_enrollments_due_idx', 'notifications_due_idx', 'unsubscribe_tokens_expiry_idx') ORDER BY name",
    );

    expect(result.rows.map((row) => row.name)).toEqual([
      "campaign_enrollments_due_idx",
      "notifications_due_idx",
      "send_jobs_due_idx",
      "unsubscribe_tokens_expiry_idx",
    ]);
  });

  it("never cascades tenant deletion into evidence, delivery, suppression, or audit records", async () => {
    for (const table of NON_CASCADING_EVIDENCE_TABLES) {
      const foreignKeys = await client.execute(`PRAGMA foreign_key_list(${table})`);
      const tenantForeignKeys = foreignKeys.rows.filter(
        (foreignKey) =>
          foreignKey.table === "tenants" && foreignKey.from === "tenant_id",
      );

      expect(tenantForeignKeys, `${table} has no direct tenant foreign key`).not.toHaveLength(
        0,
      );
      expect(
        tenantForeignKeys.every((foreignKey) => foreignKey.on_delete !== "CASCADE"),
        `${table} cascades evidence from tenants`,
      ).toBe(true);
    }
  });
});

async function seedTenants(client: Client) {
  await client.batch(
    [
      "INSERT INTO tenants (id, slug, name) VALUES ('tenant-a', 'tenant-a', 'Tenant A')",
      "INSERT INTO tenants (id, slug, name) VALUES ('tenant-b', 'tenant-b', 'Tenant B')",
    ],
    "write",
  );
}
