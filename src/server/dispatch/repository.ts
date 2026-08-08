import "server-only";

import { createHash, createHmac, randomBytes } from "node:crypto";

import type {
  Client,
  InStatement,
  ResultSet,
  Transaction,
} from "@libsql/client";

export const DISPATCH_SEND_DEADLINE_MS = 90_000;
export const DNS_FRESHNESS_MS = 24 * 60 * 60 * 1_000;

const DEFAULT_LEASE_DURATION_MS = 120_000;
const SEND_LEASE_GRACE_MS = 5_000;
const EXPIRED_SENDING_SWEEP_LIMIT = 50;
const MIN_JITTER_SECONDS = 180;
const MAX_JITTER_SECONDS = 450;
const DAY_MS = 86_400_000;

type SqlExecutor = {
  execute(statement: InStatement): Promise<ResultSet>;
};

export type ClaimedDispatchJob = {
  jobId: string;
  tenantId: string;
  leaseToken: string;
  leaseExpiresAt: number;
};

export type DispatchContext = {
  jobId: string;
  tenantId: string;
  enrollmentId: string;
  campaignId: string;
  leadId: string;
  stepId: string;
  inboxId: string;
  attemptCount: number;
  campaignStatus: string;
  enrollmentStatus: string;
  leadStatus: string;
  campaignApprovedAt: number | null;
  campaignDryRun: boolean;
  scheduleJson: string;
  timezone: string;
  jitterMinSeconds: number;
  jitterMaxSeconds: number;
  tenantStatus: string;
  inboxStatus: string;
  inboxNextAvailableAt: number;
  fromAddress: string;
  fromName: string;
  provider: "smtp" | "google" | "microsoft";
  smtpHost: string;
  smtpPort: number;
  smtpSecure: boolean;
  imapHost: string | null;
  encryptedCredentials: Buffer;
  credentialKeyVersion: number;
  credentialBinding: string;
  sendingDomain: string;
  domainStatus: string;
  domainLastDnsCheckAt: number | null;
  dkimSelector: string | null;
  dkimMode: "provider" | "local";
  normalizedEmail: string;
  firstName: string | null;
  lastName: string | null;
  companyName: string | null;
  phoneNumber: string | null;
  subjectTemplate: string;
  bodyTemplate: string;
  stepOrder: number;
  stepVersion: number;
  renderedSubject: string | null;
  renderedBody: string | null;
  stableMessageId: string | null;
};

export type PrepareDeliveryInput = {
  claim: ClaimedDispatchJob;
  now: number;
  usageDate: string;
  jitterSeconds: number;
  dryRun?: boolean;
  dryRunRetryAt?: number;
  quotaRetryAt?: number;
  suppressionIdentifierHash: string;
  renderedSubject: string;
  renderedBody: string;
  stableMessageId: string;
  unsubscribeTokenId: string;
  unsubscribeTokenHash: string;
  outboundMessageId: string;
  attemptId: string;
  headersJson?: string;
};

export type PrepareDeliveryResult =
  | { status: "ready"; attemptNumber: number }
  | { status: "dry_run" }
  | { status: "blocked"; code: string }
  | { status: "deferred"; code: string };

export type DispatchRepository = {
  materializeDueEnrollments(now: number, limit: number): Promise<number>;
  claimNext(now: number): Promise<ClaimedDispatchJob | null>;
  loadContext(claim: ClaimedDispatchJob): Promise<DispatchContext | null>;
  prepareDelivery(input: PrepareDeliveryInput): Promise<PrepareDeliveryResult>;
  recordAccepted(input: {
    claim: ClaimedDispatchJob;
    now: number;
    providerMessageId: string | null;
    jitterSeconds: number;
  }): Promise<void>;
  recordDefinitiveRejection(input: {
    claim: ClaimedDispatchJob;
    now: number;
    retryAt: number;
    errorCode: string;
    maxAttempts: number;
  }): Promise<void>;
  recordUncertain(input: {
    claim: ClaimedDispatchJob;
    now: number;
    errorCode: string;
  }): Promise<void>;
  deferClaim(input: {
    claim: ClaimedDispatchJob;
    now: number;
    retryAt: number;
    code: string;
  }): Promise<void>;
  failClaim(input: {
    claim: ClaimedDispatchJob;
    now: number;
    code: string;
  }): Promise<void>;
};

export class StaleDispatchLeaseError extends Error {
  constructor() {
    super("The dispatch lease is no longer current");
    this.name = "StaleDispatchLeaseError";
  }
}

function requireSecret(secret: string, label: string): void {
  if (Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error(`${label} must contain at least 32 bytes`);
  }
}

function requireUnixMs(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative Unix millisecond value`);
  }
  return value;
}

function requireInternalId(value: string, label: string): string {
  const normalized = value.trim();
  if (
    !normalized ||
    normalized.length > 512 ||
    /[\u0000-\u001f\u007f]/.test(normalized)
  ) {
    throw new Error(`Invalid ${label}`);
  }
  return normalized;
}

function safeErrorCode(value: string): string {
  return /^[A-Za-z0-9_.-]{1,64}$/.test(value)
    ? value
    : "dispatch_error";
}

function asString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) {
    throw new Error(`Database row is missing ${label}`);
  }
  return value;
}

function asNumber(value: unknown, label: string): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    throw new Error(`Database row has invalid ${label}`);
  }
  return number;
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function nullableNumber(value: unknown): number | null {
  return value === null || value === undefined ? null : asNumber(value, "number");
}

function asBuffer(value: unknown, label: string): Buffer {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  if (ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new Error(`Database row has invalid ${label}`);
}

function asProvider(value: unknown): DispatchContext["provider"] {
  if (value === "smtp" || value === "google" || value === "microsoft") {
    return value;
  }
  throw new Error("Database row has invalid inbox provider");
}

function asDkimMode(value: unknown): DispatchContext["dkimMode"] {
  if (value === "provider" || value === "local") return value;
  throw new Error("Database row has invalid DKIM mode");
}

function utcUsageDate(timestamp: number): string {
  return new Date(timestamp).toISOString().slice(0, 10);
}

function nextUtcDay(timestamp: number): number {
  const date = new Date(timestamp);
  return Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate() + 1,
  );
}

function deterministicId(namespace: string, ...parts: string[]): string {
  return `${namespace}_${createHash("sha256")
    .update(`opt-in-vault:${namespace}:v1\0`)
    .update(parts.join("\0"))
    .digest("hex")
    .slice(0, 40)}`;
}

export function hashDispatchLeaseToken(token: string, pepper: string): string {
  requireSecret(pepper, "Dispatch lease pepper");
  if (!token || Buffer.byteLength(token, "utf8") > 512) {
    throw new Error("Invalid dispatch lease token");
  }
  return createHmac("sha256", pepper)
    .update("opt-in-vault:dispatch-lease:v1\0")
    .update(token)
    .digest("hex");
}

async function inWriteTransaction<T>(
  client: Client,
  operation: (transaction: Transaction) => Promise<T>,
): Promise<T> {
  const transaction = await client.transaction("write");
  try {
    const result = await operation(transaction);
    await transaction.commit();
    return result;
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
}

async function loadContextFrom(
  executor: SqlExecutor,
  claim: ClaimedDispatchJob,
  leaseHash: string,
): Promise<DispatchContext | null> {
  const result = await executor.execute({
    sql: `
      SELECT
        job.id AS job_id,
        job.tenant_id,
        job.enrollment_id,
        job.campaign_id,
        job.lead_id,
        job.step_id,
        job.inbox_id,
        job.attempt_count,
        job.rendered_subject,
        job.rendered_body,
        job.stable_message_id,
        tenant.status AS tenant_status,
        campaign.status AS campaign_status,
        enrollment.status AS enrollment_status,
        campaign.approved_at AS campaign_approved_at,
        campaign.dry_run AS campaign_dry_run,
        campaign.schedule_json,
        campaign.timezone,
        campaign.jitter_min_seconds,
        campaign.jitter_max_seconds,
        step.step_order,
        step.version AS step_version,
        step.subject_template,
        step.body_template,
        lead.normalized_email,
        lead.status AS lead_status,
        lead.first_name,
        lead.last_name,
        lead.company_name,
        lead.phone_number,
        inbox.status AS inbox_status,
        inbox.next_available_at AS inbox_next_available_at,
        inbox.email_address AS from_address,
        inbox.display_name AS from_name,
        inbox.provider,
        inbox.smtp_host,
        inbox.smtp_port,
        inbox.smtp_secure,
        inbox.imap_host,
        inbox.encrypted_credentials,
        inbox.credential_key_version,
        inbox.credential_binding,
        domain.domain AS sending_domain,
        domain.status AS domain_status,
        domain.last_dns_check_at AS domain_last_dns_check_at,
        domain.dkim_selector,
        domain.dkim_mode
      FROM send_jobs AS job
      JOIN tenants AS tenant
        ON tenant.id = job.tenant_id
      JOIN campaign_enrollments AS enrollment
        ON enrollment.tenant_id = job.tenant_id
       AND enrollment.id = job.enrollment_id
       AND enrollment.campaign_id = job.campaign_id
       AND enrollment.lead_id = job.lead_id
      JOIN campaigns AS campaign
        ON campaign.tenant_id = job.tenant_id
       AND campaign.id = job.campaign_id
      JOIN sequence_steps AS step
        ON step.tenant_id = job.tenant_id
       AND step.id = job.step_id
       AND step.campaign_id = job.campaign_id
      JOIN leads AS lead
        ON lead.tenant_id = job.tenant_id
       AND lead.id = job.lead_id
      JOIN sending_inboxes AS inbox
        ON inbox.tenant_id = job.tenant_id
       AND inbox.id = job.inbox_id
       AND (enrollment.inbox_id IS NULL OR enrollment.inbox_id = job.inbox_id)
      JOIN sending_domains AS domain
        ON domain.tenant_id = inbox.tenant_id
       AND domain.id = inbox.domain_id
      WHERE job.id = ?
        AND job.tenant_id = ?
        AND job.status = 'leased'
        AND job.lease_token_hash = ?
      LIMIT 1
    `,
    args: [claim.jobId, claim.tenantId, leaseHash],
  });
  const row = result.rows[0];
  if (!row) return null;

  return {
    jobId: asString(row.job_id, "job id"),
    tenantId: asString(row.tenant_id, "tenant id"),
    enrollmentId: asString(row.enrollment_id, "enrollment id"),
    campaignId: asString(row.campaign_id, "campaign id"),
    leadId: asString(row.lead_id, "lead id"),
    stepId: asString(row.step_id, "step id"),
    inboxId: asString(row.inbox_id, "inbox id"),
    attemptCount: asNumber(row.attempt_count, "attempt count"),
    campaignStatus: asString(row.campaign_status, "campaign status"),
    enrollmentStatus: asString(row.enrollment_status, "enrollment status"),
    leadStatus: asString(row.lead_status, "lead status"),
    campaignApprovedAt: nullableNumber(row.campaign_approved_at),
    campaignDryRun: Number(row.campaign_dry_run) === 1,
    scheduleJson: asString(row.schedule_json, "campaign schedule"),
    timezone: asString(row.timezone, "campaign timezone"),
    jitterMinSeconds: asNumber(row.jitter_min_seconds, "minimum jitter"),
    jitterMaxSeconds: asNumber(row.jitter_max_seconds, "maximum jitter"),
    tenantStatus: asString(row.tenant_status, "tenant status"),
    inboxStatus: asString(row.inbox_status, "inbox status"),
    inboxNextAvailableAt: asNumber(
      row.inbox_next_available_at,
      "inbox availability",
    ),
    fromAddress: asString(row.from_address, "from address"),
    fromName: asString(row.from_name, "from name"),
    provider: asProvider(row.provider),
    smtpHost: asString(row.smtp_host, "SMTP host"),
    smtpPort: asNumber(row.smtp_port, "SMTP port"),
    smtpSecure: Number(row.smtp_secure) === 1,
    imapHost: nullableString(row.imap_host),
    encryptedCredentials: asBuffer(
      row.encrypted_credentials,
      "encrypted credentials",
    ),
    credentialKeyVersion: asNumber(
      row.credential_key_version,
      "credential key version",
    ),
    credentialBinding: asString(
      row.credential_binding,
      "credential binding",
    ),
    sendingDomain: asString(row.sending_domain, "sending domain"),
    domainStatus: asString(row.domain_status, "domain status"),
    domainLastDnsCheckAt: nullableNumber(row.domain_last_dns_check_at),
    dkimSelector: nullableString(row.dkim_selector),
    dkimMode: asDkimMode(row.dkim_mode),
    normalizedEmail: asString(row.normalized_email, "normalized email"),
    firstName: nullableString(row.first_name),
    lastName: nullableString(row.last_name),
    companyName: nullableString(row.company_name),
    phoneNumber: nullableString(row.phone_number),
    subjectTemplate: asString(row.subject_template, "subject template"),
    bodyTemplate: asString(row.body_template, "body template"),
    stepOrder: asNumber(row.step_order, "step order"),
    stepVersion: asNumber(row.step_version, "step version"),
    renderedSubject: nullableString(row.rendered_subject),
    renderedBody: nullableString(row.rendered_body),
    stableMessageId: nullableString(row.stable_message_id),
  };
}

async function transitionClaim(
  executor: SqlExecutor,
  claim: ClaimedDispatchJob,
  leaseHash: string,
  input: {
    status: "queued" | "failed" | "cancelled";
    now: number;
    code: string;
    retryAt?: number;
  },
): Promise<void> {
  const result = await executor.execute({
    sql: `
      UPDATE send_jobs
      SET status = ?,
          due_at = CASE WHEN ? IS NULL THEN due_at ELSE MAX(due_at, ?) END,
          lease_token_hash = NULL,
          lease_expires_at = NULL,
          last_error_code = ?,
          updated_at = ?
      WHERE id = ? AND tenant_id = ?
        AND status = 'leased' AND lease_token_hash = ?
    `,
    args: [
      input.status,
      input.retryAt ?? null,
      input.retryAt ?? null,
      safeErrorCode(input.code),
      input.now,
      claim.jobId,
      claim.tenantId,
      leaseHash,
    ],
  });
  if (result.rowsAffected !== 1) throw new StaleDispatchLeaseError();
}

export function createDispatchRepository(
  client: Client,
  options: {
    leasePepper: string;
    leaseDurationMs?: number;
    leaseTokenFactory?: () => string;
  },
): DispatchRepository {
  requireSecret(options.leasePepper, "Dispatch lease pepper");
  const leaseDurationMs =
    options.leaseDurationMs ?? DEFAULT_LEASE_DURATION_MS;
  if (!Number.isSafeInteger(leaseDurationMs) || leaseDurationMs < 1_000) {
    throw new Error("Dispatch lease duration must be at least one second");
  }
  const leaseTokenFactory =
    options.leaseTokenFactory ??
    (() => `ovl_${randomBytes(32).toString("base64url")}`);

  const leaseHashFor = (claim: ClaimedDispatchJob) =>
    hashDispatchLeaseToken(claim.leaseToken, options.leasePepper);

  return {
    async materializeDueEnrollments(now, limit) {
      requireUnixMs(now, "Materialization time");
      if (!Number.isInteger(limit) || limit < 1 || limit > 50) {
        throw new Error("Materialization limit must be between 1 and 50");
      }
      return inWriteTransaction(client, async (transaction) => {
        const due = await transaction.execute({
          sql: `
            SELECT enrollment.id AS enrollment_id, enrollment.tenant_id,
                   enrollment.campaign_id, enrollment.lead_id,
                   enrollment.inbox_id, enrollment.next_send_at, step.id AS step_id
            FROM campaign_enrollments AS enrollment
            JOIN campaigns AS campaign
              ON campaign.tenant_id = enrollment.tenant_id
             AND campaign.id = enrollment.campaign_id
            JOIN leads AS lead
              ON lead.tenant_id = enrollment.tenant_id
             AND lead.id = enrollment.lead_id
            JOIN sequence_steps AS step
              ON step.tenant_id = enrollment.tenant_id
             AND step.campaign_id = enrollment.campaign_id
             AND step.step_order = enrollment.current_step
            WHERE enrollment.status IN ('pending', 'active')
              AND enrollment.next_send_at IS NOT NULL
              AND enrollment.next_send_at <= ?
              AND campaign.status = 'active'
              AND campaign.approved_at IS NOT NULL
              AND lead.status = 'active'
              AND NOT EXISTS (
                SELECT 1 FROM send_jobs AS existing
                WHERE existing.tenant_id = enrollment.tenant_id
                  AND existing.enrollment_id = enrollment.id
                  AND existing.step_id = step.id
              )
            ORDER BY enrollment.next_send_at, enrollment.created_at, enrollment.id
            LIMIT ?
          `,
          args: [now, limit],
        });
        let created = 0;
        for (const row of due.rows) {
          const tenantId = asString(row.tenant_id, "due enrollment tenant id");
          const enrollmentId = asString(row.enrollment_id, "due enrollment id");
          const stepId = asString(row.step_id, "due enrollment step id");
          const inserted = await transaction.execute({
            sql: `
              INSERT INTO send_jobs
                (id, tenant_id, enrollment_id, campaign_id, lead_id, step_id,
                 inbox_id, status, due_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?)
              ON CONFLICT (tenant_id, enrollment_id, step_id) DO NOTHING
            `,
            args: [
              deterministicId("job", tenantId, enrollmentId, stepId),
              tenantId,
              enrollmentId,
              asString(row.campaign_id, "due enrollment campaign id"),
              asString(row.lead_id, "due enrollment lead id"),
              stepId,
              nullableString(row.inbox_id),
              asNumber(row.next_send_at, "due enrollment time"),
            ],
          });
          if (inserted.rowsAffected === 1) {
            created += 1;
            await transaction.execute({
              sql: `
                UPDATE campaign_enrollments
                SET status = 'active', updated_at = ?
                WHERE tenant_id = ? AND id = ? AND status = 'pending'
              `,
              args: [now, tenantId, enrollmentId],
            });
          }
        }
        return created;
      });
    },

    async claimNext(now) {
      requireUnixMs(now, "Claim time");
      const leaseToken = leaseTokenFactory();
      const leaseTokenHash = hashDispatchLeaseToken(
        leaseToken,
        options.leasePepper,
      );
      const leaseExpiresAt = now + leaseDurationMs;
      if (!Number.isSafeInteger(leaseExpiresAt)) {
        throw new Error("Dispatch lease expiry is outside the safe range");
      }

      return inWriteTransaction(client, async (transaction) => {
        await quarantineExpiredSending(transaction, now);
        const usageDate = utcUsageDate(now);
        const candidate = await transaction.execute({
          sql: `
            SELECT job.id, job.tenant_id, job.inbox_id AS job_inbox_id,
                   enrollment.inbox_id AS enrollment_inbox_id,
                   enrollment.id AS enrollment_id
            FROM send_jobs AS job
            JOIN campaign_enrollments AS enrollment
              ON enrollment.tenant_id = job.tenant_id
             AND enrollment.id = job.enrollment_id
            WHERE (
              (job.status = 'queued' AND job.due_at <= ?)
              OR (job.status = 'leased' AND job.lease_expires_at <= ?)
            )
              AND (
                job.inbox_id IS NULL OR enrollment.inbox_id IS NULL
                OR job.inbox_id = enrollment.inbox_id
              )
              AND (
                COALESCE(job.inbox_id, enrollment.inbox_id) IS NOT NULL
                OR EXISTS (
                  SELECT 1
                  FROM sending_inboxes AS available
                  JOIN sending_domains AS domain
                    ON domain.tenant_id = available.tenant_id
                   AND domain.id = available.domain_id
                  LEFT JOIN inbox_daily_usage AS usage
                    ON usage.tenant_id = available.tenant_id
                   AND usage.inbox_id = available.id
                   AND usage.usage_date = ?
                  WHERE available.tenant_id = job.tenant_id
                    AND available.status = 'active'
                    AND domain.status IN ('healthy', 'degraded')
                    AND available.next_available_at <= ?
                    AND COALESCE(usage.reserved_count + usage.sent_count, 0) + (
                      SELECT COUNT(*)
                      FROM send_jobs AS pending
                      WHERE pending.tenant_id = available.tenant_id
                        AND pending.inbox_id = available.id
                        AND pending.status = 'leased'
                        AND pending.lease_expires_at > ?
                    )
                        < available.daily_limit
                    AND (
                      SELECT COALESCE(SUM(total.reserved_count + total.sent_count), 0)
                      FROM inbox_daily_usage AS total
                      WHERE total.tenant_id = job.tenant_id
                        AND total.usage_date = ?
                    ) + (
                      SELECT COUNT(*)
                      FROM send_jobs AS pending
                      WHERE pending.tenant_id = job.tenant_id
                        AND pending.status = 'leased'
                        AND pending.lease_expires_at > ?
                    ) < (
                      SELECT tenant.daily_limit FROM tenants AS tenant
                      WHERE tenant.id = job.tenant_id
                    )
                )
              )
            ORDER BY
              CASE WHEN job.status = 'queued' THEN job.due_at ELSE job.lease_expires_at END,
              job.created_at,
              job.id
            LIMIT 1
          `,
          args: [now, now, usageDate, now, now, usageDate, now],
        });
        const row = candidate.rows[0];
        if (!row) return null;
        const jobId = asString(row.id, "job id");
        const tenantId = asString(row.tenant_id, "tenant id");
        const enrollmentId = asString(row.enrollment_id, "enrollment id");
        let inboxId =
          nullableString(row.job_inbox_id) ??
          nullableString(row.enrollment_inbox_id);
        if (!inboxId) {
          const selected = await transaction.execute({
            sql: `
              SELECT inbox.id
              FROM sending_inboxes AS inbox
              JOIN sending_domains AS domain
                ON domain.tenant_id = inbox.tenant_id
               AND domain.id = inbox.domain_id
              LEFT JOIN inbox_daily_usage AS usage
                ON usage.tenant_id = inbox.tenant_id
               AND usage.inbox_id = inbox.id
               AND usage.usage_date = ?
              LEFT JOIN (
                SELECT tenant_id, inbox_id, COUNT(*) AS claim_count
                FROM send_jobs
                WHERE status = 'leased' AND lease_expires_at > ?
                GROUP BY tenant_id, inbox_id
              ) AS pending
                ON pending.tenant_id = inbox.tenant_id
               AND pending.inbox_id = inbox.id
              WHERE inbox.tenant_id = ? AND inbox.status = 'active'
                AND domain.status IN ('healthy', 'degraded')
                AND inbox.next_available_at <= ?
                AND COALESCE(usage.reserved_count + usage.sent_count, 0)
                    + COALESCE(pending.claim_count, 0)
                    < inbox.daily_limit
                AND (
                  SELECT COALESCE(SUM(total.reserved_count + total.sent_count), 0)
                  FROM inbox_daily_usage AS total
                  WHERE total.tenant_id = inbox.tenant_id
                    AND total.usage_date = ?
                ) + (
                  SELECT COUNT(*)
                  FROM send_jobs AS tenant_pending
                  WHERE tenant_pending.tenant_id = inbox.tenant_id
                    AND tenant_pending.status = 'leased'
                    AND tenant_pending.lease_expires_at > ?
                ) < (
                  SELECT tenant.daily_limit FROM tenants AS tenant
                  WHERE tenant.id = inbox.tenant_id
                )
              ORDER BY COALESCE(usage.reserved_count + usage.sent_count, 0)
                         + COALESCE(pending.claim_count, 0),
                       inbox.next_available_at,
                       COALESCE(inbox.last_used_at, 0), inbox.id
              LIMIT 1
            `,
            args: [usageDate, now, tenantId, now, usageDate, now],
          });
          inboxId = nullableString(selected.rows[0]?.id);
          if (!inboxId) return null;
        }
        const pinned = await transaction.execute({
          sql: `
            UPDATE campaign_enrollments
            SET inbox_id = COALESCE(inbox_id, ?), updated_at = ?
            WHERE tenant_id = ? AND id = ?
              AND (inbox_id IS NULL OR inbox_id = ?)
          `,
          args: [inboxId, now, tenantId, enrollmentId, inboxId],
        });
        if (pinned.rowsAffected !== 1) return null;
        const update = await transaction.execute({
          sql: `
            UPDATE send_jobs
            SET status = 'leased', inbox_id = ?, lease_token_hash = ?, lease_expires_at = ?,
                last_error_code = NULL, updated_at = ?
            WHERE id = ? AND tenant_id = ?
              AND ((status = 'queued' AND due_at <= ?)
                OR (status = 'leased' AND lease_expires_at <= ?))
          `,
          args: [
            inboxId,
            leaseTokenHash,
            leaseExpiresAt,
            now,
            jobId,
            tenantId,
            now,
            now,
          ],
        });
        if (update.rowsAffected !== 1) return null;
        return { jobId, tenantId, leaseToken, leaseExpiresAt };
      });
    },

    async loadContext(claim) {
      return loadContextFrom(client, claim, leaseHashFor(claim));
    },

    async prepareDelivery(input) {
      requireUnixMs(input.now, "Preparation time");
      if (input.usageDate !== utcUsageDate(input.now)) {
        throw new Error("Dispatch quota date must match the preparation time");
      }
      if (input.quotaRetryAt !== undefined) {
        requireUnixMs(input.quotaRetryAt, "Quota retry time");
        if (input.quotaRetryAt < input.now) {
          throw new Error("Dispatch quota retry time cannot be in the past");
        }
      }
      if (input.dryRun) {
        if (input.dryRunRetryAt === undefined) {
          throw new Error("Dry-run retry time is required");
        }
        requireUnixMs(input.dryRunRetryAt, "Dry-run retry time");
        if (input.dryRunRetryAt <= input.now) {
          throw new Error("Dry-run retry time must be in the future");
        }
      }
      requireInternalId(input.unsubscribeTokenId, "unsubscribe token id");
      requireInternalId(input.outboundMessageId, "outbound message id");
      requireInternalId(input.attemptId, "delivery attempt id");
      if (!/^<[^<>\r\n]+@[^<>\r\n]+>$/.test(input.stableMessageId)) {
        throw new Error("Invalid stable Message-ID");
      }
      if (!input.renderedSubject || !input.renderedBody) {
        throw new Error("Rendered delivery content is required");
      }
      const leaseHash = leaseHashFor(input.claim);

      return inWriteTransaction(client, async (transaction) => {
        const sendLeaseExpiresAt =
          input.now + DISPATCH_SEND_DEADLINE_MS + SEND_LEASE_GRACE_MS;
        if (!Number.isSafeInteger(sendLeaseExpiresAt)) {
          throw new Error("Dispatch send lease expiry is outside the safe range");
        }
        const ownership = await transaction.execute({
          sql: `
            UPDATE send_jobs
            SET lease_expires_at = MAX(lease_expires_at, ?), updated_at = ?
            WHERE id = ? AND tenant_id = ?
              AND status = 'leased' AND lease_token_hash = ?
              AND lease_expires_at > ?
          `,
          args: [
            sendLeaseExpiresAt,
            input.now,
            input.claim.jobId,
            input.claim.tenantId,
            leaseHash,
            input.now,
          ],
        });
        if (ownership.rowsAffected !== 1) throw new StaleDispatchLeaseError();
        const context = await loadContextFrom(
          transaction,
          input.claim,
          leaseHash,
        );
        if (!context) throw new StaleDispatchLeaseError();
        if (
          !Number.isInteger(input.jitterSeconds) ||
          input.jitterSeconds < context.jitterMinSeconds ||
          input.jitterSeconds > context.jitterMaxSeconds ||
          input.jitterSeconds < MIN_JITTER_SECONDS ||
          input.jitterSeconds > MAX_JITTER_SECONDS
        ) {
          throw new Error("Dispatch jitter falls outside the campaign bounds");
        }

        const terminalGate =
          context.tenantStatus === "archived"
            ? "tenant_archived"
            : context.campaignStatus === "completed"
              ? "campaign_completed"
              : !["pending", "active", "paused"].includes(
                    context.enrollmentStatus,
                  )
                ? "enrollment_terminal"
                : context.leadStatus !== "active"
                  ? "lead_not_active"
                  : context.jitterMinSeconds < MIN_JITTER_SECONDS ||
                      context.jitterMaxSeconds > MAX_JITTER_SECONDS ||
                      context.jitterMinSeconds > context.jitterMaxSeconds
                    ? "campaign_jitter_invalid"
                    : null;
        if (terminalGate) {
          await transitionClaim(transaction, input.claim, leaseHash, {
            status:
              terminalGate === "enrollment_terminal" ||
              terminalGate === "lead_not_active" ||
              terminalGate === "campaign_completed"
                ? "cancelled"
                : "failed",
            now: input.now,
            code: terminalGate,
          });
          return { status: "blocked", code: terminalGate } as const;
        }

        const recoverableGate =
          context.tenantStatus !== "active"
            ? "tenant_inactive"
            : context.campaignStatus !== "active"
              ? "campaign_inactive"
              : context.campaignApprovedAt === null
                ? "campaign_unapproved"
                : context.enrollmentStatus !== "active"
                  ? "enrollment_inactive"
                  : context.inboxStatus !== "active"
                    ? "inbox_inactive"
                    : !["healthy", "degraded"].includes(
                          context.domainStatus,
                        )
                      ? "domain_unhealthy"
                      : context.domainLastDnsCheckAt !== null &&
                          context.domainLastDnsCheckAt > input.now
                        ? "domain_dns_invalid"
                        : context.domainLastDnsCheckAt === null ||
                            input.now - context.domainLastDnsCheckAt >
                              DNS_FRESHNESS_MS
                          ? "domain_dns_stale"
                      : null;
        if (recoverableGate) {
          await transitionClaim(transaction, input.claim, leaseHash, {
            status: "queued",
            now: input.now,
            retryAt: input.now + 5 * 60_000,
            code: recoverableGate,
          });
          return { status: "deferred", code: recoverableGate } as const;
        }

        if (context.inboxNextAvailableAt > input.now) {
          await transitionClaim(transaction, input.claim, leaseHash, {
            status: "queued",
            now: input.now,
            retryAt: context.inboxNextAvailableAt,
            code: "inbox_not_available",
          });
          return {
            status: "deferred",
            code: "inbox_not_available",
          } as const;
        }

        const suppression = await transaction.execute({
          sql: `
            SELECT 1 FROM suppressions
            WHERE tenant_id = ? AND identifier_type = 'email'
              AND identifier_hash = ?
            LIMIT 1
          `,
          args: [context.tenantId, input.suppressionIdentifierHash],
        });
        if (suppression.rows.length > 0) {
          await transitionClaim(transaction, input.claim, leaseHash, {
            status: "cancelled",
            now: input.now,
            code: "suppressed",
          });
          return { status: "blocked", code: "suppressed" } as const;
        }

        const existingMaterial = await transaction.execute({
          sql: `
            SELECT rendered_subject, rendered_body, stable_message_id,
                   unsubscribe_token_id
            FROM send_jobs
            WHERE tenant_id = ? AND id = ?
          `,
          args: [context.tenantId, context.jobId],
        });
        const material = existingMaterial.rows[0];
        if (
          (material?.rendered_subject !== null &&
            material?.rendered_subject !== input.renderedSubject) ||
          (material?.rendered_body !== null &&
            material?.rendered_body !== input.renderedBody) ||
          (material?.stable_message_id !== null &&
            material?.stable_message_id !== input.stableMessageId)
        ) {
          await transitionClaim(transaction, input.claim, leaseHash, {
            status: "failed",
            now: input.now,
            code: "immutable_material_mismatch",
          });
          return {
            status: "blocked",
            code: "immutable_material_mismatch",
          } as const;
        }

        await transaction.execute({
          sql: `
            INSERT INTO unsubscribe_tokens
              (id, tenant_id, lead_id, token_hash)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (token_hash) DO NOTHING
          `,
          args: [
            input.unsubscribeTokenId,
            context.tenantId,
            context.leadId,
            input.unsubscribeTokenHash,
          ],
        });
        const token = await transaction.execute({
          sql: `
            SELECT id FROM unsubscribe_tokens
            WHERE tenant_id = ? AND lead_id = ? AND token_hash = ?
            LIMIT 1
          `,
          args: [
            context.tenantId,
            context.leadId,
            input.unsubscribeTokenHash,
          ],
        });
        const resolvedTokenId = nullableString(token.rows[0]?.id);
        if (!resolvedTokenId) {
          throw new Error("Unsubscribe token hash belongs to another identity");
        }
        if (
          material?.unsubscribe_token_id !== null &&
          material?.unsubscribe_token_id !== resolvedTokenId
        ) {
          await transitionClaim(transaction, input.claim, leaseHash, {
            status: "failed",
            now: input.now,
            code: "unsubscribe_token_mismatch",
          });
          return {
            status: "blocked",
            code: "unsubscribe_token_mismatch",
          } as const;
        }

        if (input.dryRun) {
          const previewed = await transaction.execute({
            sql: `
              UPDATE send_jobs
              SET status = 'queued', due_at = MAX(due_at, ?),
                  rendered_subject = COALESCE(rendered_subject, ?),
                  rendered_body = COALESCE(rendered_body, ?),
                  stable_message_id = COALESCE(stable_message_id, ?),
                  unsubscribe_token_id = ?, lease_token_hash = NULL,
                  lease_expires_at = NULL, last_error_code = 'dry_run_preview',
                  updated_at = ?
              WHERE id = ? AND tenant_id = ?
                AND status = 'leased' AND lease_token_hash = ?
            `,
            args: [
              input.dryRunRetryAt!,
              input.renderedSubject,
              input.renderedBody,
              input.stableMessageId,
              resolvedTokenId,
              input.now,
              context.jobId,
              context.tenantId,
              leaseHash,
            ],
          });
          if (previewed.rowsAffected !== 1) throw new StaleDispatchLeaseError();
          await persistPreparedOutbound(transaction, context, input);
          return { status: "dry_run" } as const;
        }

        await transaction.execute({
          sql: `
            INSERT INTO inbox_daily_usage
              (tenant_id, inbox_id, usage_date, reserved_count, sent_count, updated_at)
            VALUES (?, ?, ?, 0, 0, ?)
            ON CONFLICT (tenant_id, inbox_id, usage_date) DO NOTHING
          `,
          args: [context.tenantId, context.inboxId, input.usageDate, input.now],
        });
        const reserved = await transaction.execute({
          sql: `
            UPDATE inbox_daily_usage
            SET reserved_count = reserved_count + 1, updated_at = ?
            WHERE tenant_id = ? AND inbox_id = ? AND usage_date = ?
              AND reserved_count + sent_count < (
                SELECT daily_limit FROM sending_inboxes
                WHERE tenant_id = ? AND id = ?
              )
              AND (
                SELECT COALESCE(SUM(reserved_count + sent_count), 0)
                FROM inbox_daily_usage
                WHERE tenant_id = ? AND usage_date = ?
              ) < (
                SELECT daily_limit FROM tenants WHERE id = ?
              )
          `,
          args: [
            input.now,
            context.tenantId,
            context.inboxId,
            input.usageDate,
            context.tenantId,
            context.inboxId,
            context.tenantId,
            input.usageDate,
            context.tenantId,
          ],
        });
        if (reserved.rowsAffected !== 1) {
          await transitionClaim(transaction, input.claim, leaseHash, {
            status: "queued",
            now: input.now,
            retryAt: input.quotaRetryAt ?? nextUtcDay(input.now),
            code: "daily_quota_exhausted",
          });
          return {
            status: "deferred",
            code: "daily_quota_exhausted",
          } as const;
        }

        const reservedAvailabilityAt = input.now + input.jitterSeconds * 1_000;
        if (!Number.isSafeInteger(reservedAvailabilityAt)) {
          throw new Error("Inbox availability time is outside the safe range");
        }
        const paced = await transaction.execute({
          sql: `
            UPDATE sending_inboxes
            SET next_available_at = MAX(next_available_at, ?), updated_at = ?
            WHERE tenant_id = ? AND id = ? AND status = 'active'
          `,
          args: [
            reservedAvailabilityAt,
            input.now,
            context.tenantId,
            context.inboxId,
          ],
        });
        if (paced.rowsAffected !== 1) {
          throw new Error("Sending inbox pacing slot could not be reserved");
        }

        const updated = await transaction.execute({
          sql: `
            UPDATE send_jobs
            SET status = 'sending',
                attempt_count = attempt_count + 1,
                rendered_subject = COALESCE(rendered_subject, ?),
                rendered_body = COALESCE(rendered_body, ?),
                stable_message_id = COALESCE(stable_message_id, ?),
                unsubscribe_token_id = ?,
                updated_at = ?
            WHERE id = ? AND tenant_id = ?
              AND status = 'leased' AND lease_token_hash = ?
            RETURNING attempt_count
          `,
          args: [
            input.renderedSubject,
            input.renderedBody,
            input.stableMessageId,
            resolvedTokenId,
            input.now,
            context.jobId,
            context.tenantId,
            leaseHash,
          ],
        });
        if (updated.rows.length !== 1) throw new StaleDispatchLeaseError();
        const attemptNumber = asNumber(
          updated.rows[0]?.attempt_count,
          "attempt number",
        );

        const attempt = await transaction.execute({
          sql: `
            INSERT INTO delivery_attempts
              (id, tenant_id, job_id, inbox_id, attempt_number, status, started_at)
            VALUES (?, ?, ?, ?, ?, 'sending', ?)
          `,
          args: [
            input.attemptId,
            context.tenantId,
            context.jobId,
            context.inboxId,
            attemptNumber,
            input.now,
          ],
        });
        if (attempt.rowsAffected !== 1) {
          throw new Error("Delivery attempt could not be persisted");
        }
        await persistPreparedOutbound(transaction, context, input);

        return { status: "ready", attemptNumber } as const;
      });
    },

    async recordAccepted(input) {
      await finishSuccessfulDelivery(client, leaseHashFor(input.claim), {
        ...input,
      });
    },

    async recordDefinitiveRejection(input) {
      requireUnixMs(input.now, "Rejection time");
      requireUnixMs(input.retryAt, "Retry time");
      if (!Number.isInteger(input.maxAttempts) || input.maxAttempts < 1) {
        throw new Error("Maximum attempts must be a positive integer");
      }
      const leaseHash = leaseHashFor(input.claim);
      await inWriteTransaction(client, async (transaction) => {
        const state = await currentSendingState(
          transaction,
          input.claim,
          leaseHash,
        );
        const terminal = state.attemptNumber >= input.maxAttempts;
        const attempt = await transaction.execute({
          sql: `
            UPDATE delivery_attempts
            SET status = 'rejected', error_code = ?, completed_at = ?
            WHERE tenant_id = ? AND job_id = ? AND attempt_number = ?
          `,
          args: [
            safeErrorCode(input.errorCode),
            input.now,
            input.claim.tenantId,
            input.claim.jobId,
            state.attemptNumber,
          ],
        });
        if (attempt.rowsAffected !== 1) {
          throw new Error("Rejected delivery attempt could not be reconciled");
        }
        const message = await transaction.execute({
          sql: `
            UPDATE outbound_messages
            SET status = 'rejected'
            WHERE tenant_id = ? AND job_id = ?
          `,
          args: [input.claim.tenantId, input.claim.jobId],
        });
        if (message.rowsAffected !== 1) {
          throw new Error("Rejected outbound message could not be reconciled");
        }
        await releaseReservedQuota(
          transaction,
          input.claim.tenantId,
          state.inboxId,
          state.usageDate,
          input.now,
          false,
        );
        const updated = await transaction.execute({
          sql: `
            UPDATE send_jobs
            SET status = ?, due_at = ?, lease_token_hash = NULL,
                lease_expires_at = NULL, last_error_code = ?, updated_at = ?
            WHERE tenant_id = ? AND id = ?
              AND status = 'sending' AND lease_token_hash = ?
          `,
          args: [
            terminal ? "failed" : "queued",
            input.retryAt,
            safeErrorCode(input.errorCode),
            input.now,
            input.claim.tenantId,
            input.claim.jobId,
            leaseHash,
          ],
        });
        if (updated.rowsAffected !== 1) throw new StaleDispatchLeaseError();
      });
    },

    async recordUncertain(input) {
      requireUnixMs(input.now, "Uncertain-delivery time");
      const leaseHash = leaseHashFor(input.claim);
      await inWriteTransaction(client, async (transaction) => {
        const state = await currentSendingState(
          transaction,
          input.claim,
          leaseHash,
        );
        const attempt = await transaction.execute({
          sql: `
            UPDATE delivery_attempts
            SET status = 'unknown', error_code = ?, completed_at = ?
            WHERE tenant_id = ? AND job_id = ? AND attempt_number = ?
          `,
          args: [
            safeErrorCode(input.errorCode),
            input.now,
            input.claim.tenantId,
            input.claim.jobId,
            state.attemptNumber,
          ],
        });
        if (attempt.rowsAffected !== 1) {
          throw new Error("Uncertain delivery attempt could not be reconciled");
        }
        const message = await transaction.execute({
          sql: `
            UPDATE outbound_messages
            SET status = 'unknown'
            WHERE tenant_id = ? AND job_id = ?
          `,
          args: [input.claim.tenantId, input.claim.jobId],
        });
        if (message.rowsAffected !== 1) {
          throw new Error("Uncertain outbound message could not be reconciled");
        }
        await releaseReservedQuota(
          transaction,
          input.claim.tenantId,
          state.inboxId,
          state.usageDate,
          input.now,
          true,
        );
        const updated = await transaction.execute({
          sql: `
            UPDATE send_jobs
            SET status = 'unknown', lease_token_hash = NULL,
                lease_expires_at = NULL, last_error_code = ?, updated_at = ?
            WHERE tenant_id = ? AND id = ?
              AND status = 'sending' AND lease_token_hash = ?
          `,
          args: [
            safeErrorCode(input.errorCode),
            input.now,
            input.claim.tenantId,
            input.claim.jobId,
            leaseHash,
          ],
        });
        if (updated.rowsAffected !== 1) throw new StaleDispatchLeaseError();
      });
    },

    async deferClaim(input) {
      requireUnixMs(input.now, "Deferral time");
      requireUnixMs(input.retryAt, "Deferral retry time");
      await inWriteTransaction(client, (transaction) =>
        transitionClaim(transaction, input.claim, leaseHashFor(input.claim), {
          status: "queued",
          now: input.now,
          retryAt: input.retryAt,
          code: input.code,
        }),
      );
    },

    async failClaim(input) {
      requireUnixMs(input.now, "Failure time");
      await inWriteTransaction(client, (transaction) =>
        transitionClaim(transaction, input.claim, leaseHashFor(input.claim), {
          status: "failed",
          now: input.now,
          code: input.code,
        }),
      );
    },
  };
}

async function quarantineExpiredSending(
  transaction: Transaction,
  now: number,
): Promise<void> {
  const expired = await transaction.execute({
    sql: `
      SELECT job.id, job.tenant_id, job.inbox_id, job.attempt_count,
             attempt.started_at
      FROM send_jobs AS job
      JOIN delivery_attempts AS attempt
        ON attempt.tenant_id = job.tenant_id
       AND attempt.job_id = job.id
       AND attempt.attempt_number = job.attempt_count
      WHERE job.status = 'sending' AND job.lease_expires_at <= ?
      ORDER BY job.lease_expires_at, job.id
      LIMIT ?
    `,
    args: [now, EXPIRED_SENDING_SWEEP_LIMIT],
  });
  for (const row of expired.rows) {
    const jobId = asString(row.id, "expired sending job id");
    const tenantId = asString(row.tenant_id, "expired sending tenant id");
    const inboxId = asString(row.inbox_id, "expired sending inbox id");
    const attemptNumber = asNumber(
      row.attempt_count,
      "expired sending attempt number",
    );
    const usageDate = utcUsageDate(
      asNumber(row.started_at, "expired sending start time"),
    );
    const attempt = await transaction.execute({
      sql: `
        UPDATE delivery_attempts
        SET status = 'unknown', error_code = 'worker_lost_after_send_start',
            completed_at = ?
        WHERE tenant_id = ? AND job_id = ? AND attempt_number = ?
          AND status = 'sending'
      `,
      args: [now, tenantId, jobId, attemptNumber],
    });
    if (attempt.rowsAffected !== 1) {
      throw new Error("Expired sending attempt could not be quarantined");
    }
    const message = await transaction.execute({
      sql: `
        UPDATE outbound_messages SET status = 'unknown'
        WHERE tenant_id = ? AND job_id = ? AND status = 'prepared'
      `,
      args: [tenantId, jobId],
    });
    if (message.rowsAffected !== 1) {
      throw new Error("Expired outbound message could not be quarantined");
    }
    await releaseReservedQuota(
      transaction,
      tenantId,
      inboxId,
      usageDate,
      now,
      true,
    );
    const job = await transaction.execute({
      sql: `
        UPDATE send_jobs
        SET status = 'unknown', lease_token_hash = NULL,
            lease_expires_at = NULL,
            last_error_code = 'worker_lost_after_send_start', updated_at = ?
        WHERE tenant_id = ? AND id = ? AND status = 'sending'
          AND lease_expires_at <= ?
      `,
      args: [now, tenantId, jobId, now],
    });
    if (job.rowsAffected !== 1) {
      throw new Error("Expired sending job could not be quarantined");
    }
    const notificationId = `notification_${createHash("sha256")
      .update(`dispatch-unknown\0${tenantId}\0${jobId}\0${attemptNumber}`)
      .digest("hex")
      .slice(0, 40)}`;
    await transaction.execute({
      sql: `
        INSERT INTO notifications
          (id, tenant_id, type, payload_json, status, next_attempt_at)
        VALUES (?, ?, 'dispatch_outcome_unknown', ?, 'pending', ?)
        ON CONFLICT (id) DO NOTHING
      `,
      args: [
        notificationId,
        tenantId,
        JSON.stringify({ code: "worker_lost_after_send_start", jobId }),
        now,
      ],
    });
  }
}

type SendingState = {
  inboxId: string;
  attemptNumber: number;
  usageDate: string;
  enrollmentId: string;
  campaignId: string;
  leadId: string;
  currentStepOrder: number;
  enrollmentStatus: string;
  jitterMinSeconds: number;
  jitterMaxSeconds: number;
};

async function currentSendingState(
  executor: SqlExecutor,
  claim: ClaimedDispatchJob,
  leaseHash: string,
): Promise<SendingState> {
  const result = await executor.execute({
    sql: `
      SELECT
        job.inbox_id,
        job.attempt_count,
        job.enrollment_id,
        job.campaign_id,
        job.lead_id,
        attempt.started_at,
        step.step_order,
        enrollment.status AS enrollment_status,
        campaign.jitter_min_seconds,
        campaign.jitter_max_seconds
      FROM send_jobs AS job
      JOIN delivery_attempts AS attempt
        ON attempt.tenant_id = job.tenant_id
       AND attempt.job_id = job.id
       AND attempt.attempt_number = job.attempt_count
      JOIN sequence_steps AS step
        ON step.tenant_id = job.tenant_id AND step.id = job.step_id
      JOIN campaign_enrollments AS enrollment
        ON enrollment.tenant_id = job.tenant_id
       AND enrollment.id = job.enrollment_id
      JOIN campaigns AS campaign
        ON campaign.tenant_id = job.tenant_id AND campaign.id = job.campaign_id
      WHERE job.tenant_id = ? AND job.id = ?
        AND job.status = 'sending' AND job.lease_token_hash = ?
      LIMIT 1
    `,
    args: [claim.tenantId, claim.jobId, leaseHash],
  });
  const row = result.rows[0];
  if (!row) throw new StaleDispatchLeaseError();
  const startedAt = asNumber(row.started_at, "attempt start time");
  return {
    inboxId: asString(row.inbox_id, "inbox id"),
    attemptNumber: asNumber(row.attempt_count, "attempt number"),
    usageDate: utcUsageDate(startedAt),
    enrollmentId: asString(row.enrollment_id, "enrollment id"),
    campaignId: asString(row.campaign_id, "campaign id"),
    leadId: asString(row.lead_id, "lead id"),
    currentStepOrder: asNumber(row.step_order, "step order"),
    enrollmentStatus: asString(row.enrollment_status, "enrollment status"),
    jitterMinSeconds: asNumber(row.jitter_min_seconds, "minimum jitter"),
    jitterMaxSeconds: asNumber(row.jitter_max_seconds, "maximum jitter"),
  };
}

async function releaseReservedQuota(
  executor: SqlExecutor,
  tenantId: string,
  inboxId: string,
  usageDate: string,
  now: number,
  consume: boolean,
): Promise<void> {
  const result = await executor.execute({
    sql: `
      UPDATE inbox_daily_usage
      SET reserved_count = reserved_count - 1,
          sent_count = sent_count + ?,
          updated_at = ?
      WHERE tenant_id = ? AND inbox_id = ? AND usage_date = ?
        AND reserved_count > 0
    `,
    args: [consume ? 1 : 0, now, tenantId, inboxId, usageDate],
  });
  if (result.rowsAffected !== 1) {
    throw new Error("Reserved dispatch quota could not be reconciled");
  }
}

async function persistPreparedOutbound(
  executor: SqlExecutor,
  context: DispatchContext,
  input: PrepareDeliveryInput,
): Promise<void> {
  const message = await executor.execute({
    sql: `
      INSERT INTO outbound_messages
        (id, tenant_id, job_id, lead_id, inbox_id, message_id,
         subject, body_text, headers_json, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared')
      ON CONFLICT (tenant_id, job_id) DO UPDATE SET
        status = 'prepared', provider_message_id = NULL, sent_at = NULL
    `,
    args: [
      input.outboundMessageId,
      context.tenantId,
      context.jobId,
      context.leadId,
      context.inboxId,
      input.stableMessageId,
      input.renderedSubject,
      input.renderedBody,
      input.headersJson ?? "{}",
    ],
  });
  if (message.rowsAffected !== 1) {
    throw new Error("Outbound message could not be persisted");
  }
}

async function finishSuccessfulDelivery(
  client: Client,
  leaseHash: string,
  input: {
    claim: ClaimedDispatchJob;
    now: number;
    providerMessageId: string | null;
    jitterSeconds: number;
  },
): Promise<void> {
  requireUnixMs(input.now, "Completion time");
  if (
    !Number.isInteger(input.jitterSeconds) ||
    input.jitterSeconds < MIN_JITTER_SECONDS ||
    input.jitterSeconds > MAX_JITTER_SECONDS
  ) {
    throw new Error("Dispatch jitter must be between 180 and 450 seconds");
  }

  await inWriteTransaction(client, async (transaction) => {
    const state = await currentSendingState(
      transaction,
      input.claim,
      leaseHash,
    );
    if (
      input.jitterSeconds < state.jitterMinSeconds ||
      input.jitterSeconds > state.jitterMaxSeconds
    ) {
      throw new Error("Dispatch jitter falls outside the campaign bounds");
    }

    const attempt = await transaction.execute({
      sql: `
        UPDATE delivery_attempts
        SET status = 'accepted', provider_message_id = ?, error_code = ?,
            completed_at = ?
        WHERE tenant_id = ? AND job_id = ? AND attempt_number = ?
      `,
      args: [
        input.providerMessageId,
        null,
        input.now,
        input.claim.tenantId,
        input.claim.jobId,
        state.attemptNumber,
      ],
    });
    if (attempt.rowsAffected !== 1) {
      throw new Error("Accepted delivery attempt could not be reconciled");
    }
    const message = await transaction.execute({
      sql: `
        UPDATE outbound_messages
        SET status = 'accepted', provider_message_id = ?, sent_at = ?
        WHERE tenant_id = ? AND job_id = ?
      `,
      args: [
        input.providerMessageId,
        input.now,
        input.claim.tenantId,
        input.claim.jobId,
      ],
    });
    if (message.rowsAffected !== 1) {
      throw new Error("Accepted outbound message could not be reconciled");
    }
    await releaseReservedQuota(
      transaction,
      input.claim.tenantId,
      state.inboxId,
      state.usageDate,
      input.now,
      true,
    );
    const completed = await transaction.execute({
      sql: `
        UPDATE send_jobs
        SET status = 'sent', lease_token_hash = NULL, lease_expires_at = NULL,
            last_error_code = ?, updated_at = ?
        WHERE tenant_id = ? AND id = ?
          AND status = 'sending' AND lease_token_hash = ?
      `,
      args: [
        null,
        input.now,
        input.claim.tenantId,
        input.claim.jobId,
        leaseHash,
      ],
    });
    if (completed.rowsAffected !== 1) throw new StaleDispatchLeaseError();

    const nextAvailableAt = input.now + input.jitterSeconds * 1_000;
    const inbox = await transaction.execute({
      sql: `
        UPDATE sending_inboxes
        SET next_available_at = MAX(next_available_at, ?),
            last_used_at = ?, updated_at = ?
        WHERE tenant_id = ? AND id = ?
      `,
      args: [
        nextAvailableAt,
        input.now,
        input.now,
        input.claim.tenantId,
        state.inboxId,
      ],
    });
    if (inbox.rowsAffected !== 1) {
      throw new Error("Sending inbox availability could not be reconciled");
    }

    if (state.enrollmentStatus !== "active") return;
    const nextStep = await transaction.execute({
      sql: `
        SELECT id, step_order, delay_days
        FROM sequence_steps
        WHERE tenant_id = ? AND campaign_id = ? AND step_order > ?
        ORDER BY step_order
        LIMIT 1
      `,
      args: [
        input.claim.tenantId,
        state.campaignId,
        state.currentStepOrder,
      ],
    });
    const row = nextStep.rows[0];
    if (!row) {
      await transaction.execute({
        sql: `
          UPDATE campaign_enrollments
          SET status = 'completed', next_send_at = NULL, updated_at = ?
          WHERE tenant_id = ? AND id = ? AND status = 'active'
        `,
        args: [input.now, input.claim.tenantId, state.enrollmentId],
      });
      return;
    }

    const nextStepId = asString(row.id, "next step id");
    const nextStepOrder = asNumber(row.step_order, "next step order");
    const delayDays = asNumber(row.delay_days, "next step delay");
    const dueAt =
      input.now + delayDays * DAY_MS + input.jitterSeconds * 1_000;
    if (!Number.isSafeInteger(dueAt)) {
      throw new Error("Next send due time is outside the safe range");
    }
    await transaction.execute({
      sql: `
        INSERT INTO send_jobs
          (id, tenant_id, enrollment_id, campaign_id, lead_id, step_id,
           inbox_id, status, due_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?)
        ON CONFLICT (tenant_id, enrollment_id, step_id) DO NOTHING
      `,
      args: [
        deterministicId("job", input.claim.tenantId, state.enrollmentId, nextStepId),
        input.claim.tenantId,
        state.enrollmentId,
        state.campaignId,
        state.leadId,
        nextStepId,
        state.inboxId,
        dueAt,
      ],
    });
    await transaction.execute({
      sql: `
        UPDATE campaign_enrollments
        SET current_step = ?, next_send_at = ?, updated_at = ?
        WHERE tenant_id = ? AND id = ? AND status = 'active'
      `,
      args: [
        nextStepOrder,
        dueAt,
        input.now,
        input.claim.tenantId,
        state.enrollmentId,
      ],
    });
  });
}
