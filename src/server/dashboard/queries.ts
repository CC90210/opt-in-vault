import "server-only";

import type { Client } from "@libsql/client";

function integer(value: unknown, field: string): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (
    typeof value === "bigint" &&
    value >= BigInt(Number.MIN_SAFE_INTEGER) &&
    value <= BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    return Number(value);
  }
  throw new Error(`Dashboard ${field} is invalid`);
}

function optionalInteger(value: unknown, field: string): number | null {
  return value == null ? null : integer(value, field);
}

function text(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\u0000")) {
    throw new Error(`Dashboard ${field} is invalid`);
  }
  return value;
}

function booleanFlag(value: unknown, field: string): boolean {
  const parsed = integer(value, field);
  if (parsed !== 0 && parsed !== 1) {
    throw new Error(`Dashboard ${field} is invalid`);
  }
  return parsed === 1;
}

function countResult(
  rows: ReadonlyArray<Record<string, unknown>>,
  field: string,
): number {
  const row = rows[0];
  if (!row) throw new Error(`Dashboard ${field} is missing`);
  return integer(row.total, field);
}

export async function getDashboardSnapshot(client: Client, tenantId: string) {
  const [summary, events] = await Promise.all([
    client.execute({
      sql: `
        SELECT tenant.id, tenant.name, tenant.status,
          (SELECT COUNT(*) FROM campaigns WHERE tenant_id = tenant.id AND status = 'active') AS active_campaigns,
          (SELECT COUNT(*) FROM sending_inboxes WHERE tenant_id = tenant.id AND status = 'active') AS active_inboxes,
          (SELECT COUNT(*) FROM sending_domains WHERE tenant_id = tenant.id AND status = 'healthy') AS healthy_domains,
          (SELECT COUNT(*) FROM sending_domains WHERE tenant_id = tenant.id AND status != 'healthy') AS domains_needing_attention,
          (SELECT COUNT(*) FROM send_jobs WHERE tenant_id = tenant.id AND status IN ('queued', 'leased', 'sending')) AS pending_messages,
          (SELECT COUNT(*) FROM send_jobs WHERE tenant_id = tenant.id AND status = 'unknown') AS unknown_deliveries,
          (SELECT COUNT(*) FROM consent_logs WHERE tenant_id = tenant.id) AS consent_records,
          (SELECT COUNT(*) FROM suppressions WHERE tenant_id = tenant.id) AS suppressions,
          (SELECT COUNT(*) FROM notifications WHERE tenant_id = tenant.id AND status = 'pending') AS pending_notifications
        FROM tenants AS tenant
        WHERE tenant.id = ?
        LIMIT 1
      `,
      args: [tenantId],
    }),
    client.execute({
      sql: `
        SELECT kind, state, occurred_at FROM (
          SELECT 'consent' AS kind, 'sealed' AS state, received_at AS occurred_at
          FROM consent_logs WHERE tenant_id = ?
          UNION ALL
          SELECT 'suppression' AS kind, reason AS state, created_at AS occurred_at
          FROM suppressions WHERE tenant_id = ?
          UNION ALL
          SELECT 'delivery' AS kind, status AS state, COALESCE(sent_at, created_at) AS occurred_at
          FROM outbound_messages WHERE tenant_id = ?
          UNION ALL
          SELECT 'reply' AS kind, COALESCE(classification, 'unclassified') AS state, received_at AS occurred_at
          FROM inbound_messages WHERE tenant_id = ?
        ) ORDER BY occurred_at DESC LIMIT 12
      `,
      args: [tenantId, tenantId, tenantId, tenantId],
    }),
  ]);
  const row = summary.rows[0];
  if (!row) throw new Error("Dashboard tenant not found");
  return {
    tenant: {
      id: text(row.id, "tenant id"),
      name: text(row.name, "tenant name"),
      status: text(row.status, "tenant status"),
    },
    metrics: {
      activeCampaigns: integer(row.active_campaigns, "active campaigns"),
      activeInboxes: integer(row.active_inboxes, "active inboxes"),
      healthyDomains: integer(row.healthy_domains, "healthy domains"),
      domainsNeedingAttention: integer(
        row.domains_needing_attention,
        "domains needing attention",
      ),
      pendingMessages: integer(row.pending_messages, "pending messages"),
      unknownDeliveries: integer(
        row.unknown_deliveries,
        "unknown deliveries",
      ),
      consentRecords: integer(row.consent_records, "consent records"),
      suppressions: integer(row.suppressions, "suppressions"),
      pendingNotifications: integer(
        row.pending_notifications,
        "pending notifications",
      ),
    },
    chain: events.rows.map((event) => ({
      kind: text(event.kind, "event kind"),
      state: text(event.state, "event state"),
      occurredAt: integer(event.occurred_at, "event occurrence time"),
    })),
  };
}

export async function getCampaigns(client: Client, tenantId: string) {
  const [result, count] = await Promise.all([
    client.execute({
      sql: `
      SELECT campaign.id, campaign.name, campaign.status, campaign.dry_run,
             campaign.approved_at, campaign.timezone,
             COUNT(DISTINCT enrollment.id) AS enrollments,
             COUNT(DISTINCT CASE WHEN enrollment.status = 'replied' THEN enrollment.id END) AS replies,
             SUM(CASE WHEN job.status IN ('queued', 'leased', 'sending') THEN 1 ELSE 0 END) AS pending
      FROM campaigns AS campaign
      LEFT JOIN campaign_enrollments AS enrollment
        ON enrollment.tenant_id = campaign.tenant_id AND enrollment.campaign_id = campaign.id
      LEFT JOIN send_jobs AS job
        ON job.tenant_id = enrollment.tenant_id AND job.enrollment_id = enrollment.id
      WHERE campaign.tenant_id = ?
      GROUP BY campaign.id
      ORDER BY campaign.updated_at DESC, campaign.id
      LIMIT 100
    `,
      args: [tenantId],
    }),
    client.execute({
      sql: "SELECT COUNT(*) AS total FROM campaigns WHERE tenant_id = ?",
      args: [tenantId],
    }),
  ]);
  return {
    items: result.rows.map((row) => ({
      id: text(row.id, "campaign id"),
      name: text(row.name, "campaign name"),
      status: text(row.status, "campaign status"),
      dryRun: booleanFlag(row.dry_run, "campaign dry-run flag"),
      approvedAt: optionalInteger(row.approved_at, "campaign approval time"),
      timezone: text(row.timezone, "campaign timezone"),
      enrollments: integer(row.enrollments, "campaign enrollments"),
      replies: integer(row.replies, "campaign replies"),
      pending: integer(row.pending, "campaign pending messages"),
    })),
    total: countResult(count.rows, "campaign total"),
  };
}

export async function getInboxHealth(client: Client, tenantId: string) {
  const [result, count] = await Promise.all([
    client.execute({
      sql: `
      SELECT inbox.id, inbox.email_address, inbox.display_name, inbox.provider,
             inbox.status, inbox.daily_limit, inbox.next_available_at,
             inbox.last_poll_at, inbox.auth_error_at,
             domain.id AS domain_id, domain.domain, domain.status AS domain_status,
             domain.dkim_mode, domain.last_dns_check_at,
             COALESCE(usage.reserved_count, 0) AS reserved_today,
             COALESCE(usage.sent_count, 0) AS sent_today
      FROM sending_inboxes AS inbox
      JOIN sending_domains AS domain
        ON domain.tenant_id = inbox.tenant_id AND domain.id = inbox.domain_id
      LEFT JOIN inbox_daily_usage AS usage
        ON usage.tenant_id = inbox.tenant_id AND usage.inbox_id = inbox.id
       AND usage.usage_date = ?
      WHERE inbox.tenant_id = ?
      ORDER BY inbox.email_address
      LIMIT 200
    `,
      args: [new Date().toISOString().slice(0, 10), tenantId],
    }),
    client.execute({
      sql: "SELECT COUNT(*) AS total FROM sending_inboxes WHERE tenant_id = ?",
      args: [tenantId],
    }),
  ]);
  return {
    items: result.rows.map((row) => ({
      id: text(row.id, "inbox id"),
      emailAddress: text(row.email_address, "inbox email address"),
      displayName: text(row.display_name, "inbox display name"),
      provider: text(row.provider, "inbox provider"),
      status: text(row.status, "inbox status"),
      dailyLimit: integer(row.daily_limit, "inbox daily limit"),
      reservedToday: integer(row.reserved_today, "inbox reserved count"),
      sentToday: integer(row.sent_today, "inbox sent count"),
      nextAvailableAt: integer(
        row.next_available_at,
        "inbox next availability",
      ),
      lastPollAt: optionalInteger(row.last_poll_at, "inbox last poll time"),
      hasAuthError:
        optionalInteger(row.auth_error_at, "inbox authentication error time") !==
        null,
      domain: {
        id: text(row.domain_id, "domain id"),
        name: text(row.domain, "domain name"),
        status: text(row.domain_status, "domain status"),
        dkimMode: text(row.dkim_mode, "domain DKIM mode"),
        lastCheckedAt: optionalInteger(
          row.last_dns_check_at,
          "domain last check time",
        ),
      },
    })),
    total: countResult(count.rows, "inbox total"),
  };
}

export async function getConsentRecords(client: Client, tenantId: string) {
  const [result, count] = await Promise.all([
    client.execute({
      sql: `
      SELECT log.id, log.subject_identifier_hash, log.controller, log.purpose,
             log.disclosure_version, log.affirmative_action, log.payload_sha256,
             log.signature_key_version, log.occurred_at, log.received_at,
             log.retention_expires_at, certificate.id AS certificate_id
      FROM consent_logs AS log
      LEFT JOIN consent_certificates AS certificate
        ON certificate.tenant_id = log.tenant_id AND certificate.consent_log_id = log.id
      WHERE log.tenant_id = ?
      ORDER BY log.received_at DESC
      LIMIT 200
    `,
      args: [tenantId],
    }),
    client.execute({
      sql: "SELECT COUNT(*) AS total FROM consent_logs WHERE tenant_id = ?",
      args: [tenantId],
    }),
  ]);
  return {
    items: result.rows.map((row) => ({
      id: text(row.id, "consent id"),
      subjectHash: text(row.subject_identifier_hash, "consent subject hash"),
      controller: text(row.controller, "consent controller"),
      purpose: text(row.purpose, "consent purpose"),
      disclosureVersion: text(
        row.disclosure_version,
        "consent disclosure version",
      ),
      affirmativeAction: text(
        row.affirmative_action,
        "consent affirmative action",
      ),
      evidenceHash: text(row.payload_sha256, "consent evidence hash"),
      signatureKeyVersion: integer(
        row.signature_key_version,
        "consent signature key version",
      ),
      occurredAt: integer(row.occurred_at, "consent occurrence time"),
      receivedAt: integer(row.received_at, "consent receipt time"),
      retentionExpiresAt: integer(
        row.retention_expires_at,
        "consent retention expiry",
      ),
      certificateId:
        row.certificate_id == null
          ? null
          : text(row.certificate_id, "certificate id"),
    })),
    total: countResult(count.rows, "consent total"),
  };
}

export async function getSuppressions(client: Client, tenantId: string) {
  const [result, count] = await Promise.all([
    client.execute({
      sql: `
      SELECT id, identifier_type, identifier_hash, reason, source, created_at
      FROM suppressions
      WHERE tenant_id = ?
      ORDER BY created_at DESC
      LIMIT 500
    `,
      args: [tenantId],
    }),
    client.execute({
      sql: "SELECT COUNT(*) AS total FROM suppressions WHERE tenant_id = ?",
      args: [tenantId],
    }),
  ]);
  return {
    items: result.rows.map((row) => ({
      id: text(row.id, "suppression id"),
      identifierType: text(
        row.identifier_type,
        "suppression identifier type",
      ),
      identifierHash: text(
        row.identifier_hash,
        "suppression identifier hash",
      ),
      reason: text(row.reason, "suppression reason"),
      source: text(row.source, "suppression source"),
      createdAt: integer(row.created_at, "suppression creation time"),
    })),
    total: countResult(count.rows, "suppression total"),
  };
}
