import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";

import {
  getCampaigns,
  getConsentRecords,
  getDashboardSnapshot,
  getInboxHealth,
  getSuppressions,
} from "./queries";

const MIGRATIONS_FOLDER = fileURLToPath(
  new URL("../../../drizzle", import.meta.url),
);

describe("dashboard queries", () => {
  let client: Client;
  let tenantA: string;
  let tenantB: string;

  beforeEach(async () => {
    client = createClient({ url: "file::memory:?cache=shared" });
    await migrate(drizzle(client), { migrationsFolder: MIGRATIONS_FOLDER });
    await client.execute("PRAGMA foreign_keys = ON");
    tenantA = `tenant-a-${randomUUID()}`;
    tenantB = `tenant-b-${randomUUID()}`;

    for (const [tenantId, label] of [
      [tenantA, "A"],
      [tenantB, "B"],
    ] as const) {
      await client.batch(
        [
          {
            sql: "INSERT INTO tenants (id, slug, name) VALUES (?, ?, ?)",
            args: [tenantId, tenantId, `Tenant ${label}`],
          },
          {
            sql: "INSERT INTO campaigns (id, tenant_id, name, status) VALUES (?, ?, ?, 'active')",
            args: [`campaign-${tenantId}`, tenantId, `Campaign ${label}`],
          },
          {
            sql: "INSERT INTO sending_domains (id, tenant_id, domain, status, dkim_selector) VALUES (?, ?, ?, 'healthy', 'selector')",
            args: [`domain-${tenantId}`, tenantId, `${label.toLowerCase()}.example.com`],
          },
          {
            sql: "INSERT INTO sending_inboxes (id, tenant_id, domain_id, email_address, display_name, provider, encrypted_credentials, credential_key_version, status) VALUES (?, ?, ?, ?, 'Sender', 'smtp', X'00', 1, 'active')",
            args: [
              `inbox-${tenantId}`,
              tenantId,
              `domain-${tenantId}`,
              `sender@${label.toLowerCase()}.example.com`,
            ],
          },
          {
            sql: "INSERT INTO consent_logs (id, tenant_id, subject_identifier_hash, controller, purpose, disclosure_version, affirmative_action, canonical_payload_ciphertext, payload_key_version, payload_sha256, signature_hmac, signature_key_version, idempotency_key, occurred_at, received_at, retention_expires_at) VALUES (?, ?, ?, 'Controller', 'Updates', 'v1', 'submit', X'01', 1, ?, 'signature', 1, ?, 1000, 1000, 2000)",
            args: [
              `consent-${tenantId}`,
              tenantId,
              `subject-${tenantId}`,
              `payload-${tenantId}`,
              `idem-${tenantId}`,
            ],
          },
          {
            sql: "INSERT INTO suppressions (id, tenant_id, identifier_type, identifier_hash, reason, source) VALUES (?, ?, 'email', ?, 'unsubscribe', 'manual')",
            args: [`suppression-${tenantId}`, tenantId, `hash-${tenantId}`],
          },
        ],
        "write",
      );
    }
  });

  afterEach(() => client.close());

  it("hydrates only live metrics for the authenticated tenant", async () => {
    const snapshot = await getDashboardSnapshot(client, tenantA);
    expect(snapshot.tenant).toMatchObject({ id: tenantA, name: "Tenant A" });
    expect(snapshot.metrics).toMatchObject({
      activeCampaigns: 1,
      activeInboxes: 1,
      healthyDomains: 1,
      consentRecords: 1,
      suppressions: 1,
    });
    expect(JSON.stringify(snapshot)).not.toContain(tenantB);
  });

  it("tenant-scopes every operator list", async () => {
    const [campaigns, inboxes, consents, suppressions] = await Promise.all([
      getCampaigns(client, tenantA),
      getInboxHealth(client, tenantA),
      getConsentRecords(client, tenantA),
      getSuppressions(client, tenantA),
    ]);
    const serialized = JSON.stringify({ campaigns, inboxes, consents, suppressions });
    expect(serialized).toContain("Campaign A");
    expect(serialized).not.toContain("Campaign B");
    expect(campaigns).toMatchObject({ total: 1 });
    expect(inboxes).toMatchObject({ total: 1 });
    expect(consents).toMatchObject({ total: 1 });
    expect(suppressions).toMatchObject({ total: 1 });
    expect(campaigns.items).toHaveLength(1);
    expect(inboxes.items).toHaveLength(1);
    expect(consents.items).toHaveLength(1);
    expect(suppressions.items).toHaveLength(1);
  });

  it("counts a replied enrollment once even when it has multiple send jobs", async () => {
    const campaignId = `campaign-${tenantA}`;
    const leadId = `lead-${tenantA}`;
    const enrollmentId = `enrollment-${tenantA}`;
    const stepOne = `step-one-${tenantA}`;
    const stepTwo = `step-two-${tenantA}`;
    await client.batch(
      [
        {
          sql: "INSERT INTO leads (id, tenant_id, email_address, normalized_email) VALUES (?, ?, 'reply@example.net', 'reply@example.net')",
          args: [leadId, tenantA],
        },
        {
          sql: "INSERT INTO campaign_enrollments (id, tenant_id, campaign_id, lead_id, inbox_id, status) VALUES (?, ?, ?, ?, ?, 'replied')",
          args: [enrollmentId, tenantA, campaignId, `lead-${tenantA}`, `inbox-${tenantA}`],
        },
        {
          sql: "INSERT INTO sequence_steps (id, tenant_id, campaign_id, step_order, subject_template, body_template) VALUES (?, ?, ?, 1, 'One', 'Body')",
          args: [stepOne, tenantA, campaignId],
        },
        {
          sql: "INSERT INTO sequence_steps (id, tenant_id, campaign_id, step_order, subject_template, body_template) VALUES (?, ?, ?, 2, 'Two', 'Body')",
          args: [stepTwo, tenantA, campaignId],
        },
        {
          sql: "INSERT INTO send_jobs (id, tenant_id, enrollment_id, campaign_id, lead_id, step_id, inbox_id, status, due_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', 1000)",
          args: [`job-one-${tenantA}`, tenantA, enrollmentId, campaignId, leadId, stepOne, `inbox-${tenantA}`],
        },
        {
          sql: "INSERT INTO send_jobs (id, tenant_id, enrollment_id, campaign_id, lead_id, step_id, inbox_id, status, due_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'sent', 1000)",
          args: [`job-two-${tenantA}`, tenantA, enrollmentId, campaignId, leadId, stepTwo, `inbox-${tenantA}`],
        },
      ],
      "write",
    );

    const campaigns = await getCampaigns(client, tenantA);

    expect(campaigns.items[0]).toMatchObject({
      enrollments: 1,
      replies: 1,
      pending: 1,
    });
  });

  it("throws on malformed live database values instead of fabricating zeroes", async () => {
    const malformedClient = {
      execute: vi.fn(async (statement: { sql: string }) =>
        statement.sql.includes("FROM tenants AS tenant")
          ? {
              rows: [
                {
                  id: tenantA,
                  name: "Tenant A",
                  status: "active",
                  active_campaigns: "not-an-integer",
                  active_inboxes: 1,
                  healthy_domains: 1,
                  domains_needing_attention: 0,
                  pending_messages: 0,
                  unknown_deliveries: 0,
                  consent_records: 0,
                  suppressions: 0,
                  pending_notifications: 0,
                },
              ],
            }
          : { rows: [] },
      ),
    } as unknown as Client;

    await expect(getDashboardSnapshot(malformedClient, tenantA)).rejects.toThrow(
      /active campaigns/i,
    );
  });
});
