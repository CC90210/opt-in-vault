import { sql } from "drizzle-orm";
import {
  blob,
  check,
  foreignKey,
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";

const nowMs = sql`(unixepoch('subsec') * 1000)`;

export const tenants = sqliteTable(
  "tenants",
  {
    id: text("id").primaryKey(),
    slug: text("slug").notNull(),
    name: text("name").notNull(),
    ownerEmail: text("owner_email"),
    controller: text("controller"),
    jurisdiction: text("jurisdiction"),
    tier: text("tier").notNull().default("enterprise"),
    status: text("status").notNull().default("active"),
    dailyLimit: integer("daily_limit").notNull().default(500),
    createdAt: integer("created_at").notNull().default(nowMs),
    updatedAt: integer("updated_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("tenants_slug_uq").on(table.slug),
    uniqueIndex("tenants_id_id_uq").on(table.id, table.id),
    check("tenants_status_ck", sql`${table.status} IN ('active', 'paused', 'archived')`),
    check("tenants_daily_limit_ck", sql`${table.dailyLimit} BETWEEN 1 AND 10000`),
  ],
);

export const tenantApiKeys = sqliteTable(
  "tenant_api_keys",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    prefix: text("prefix").notNull(),
    keyHash: text("key_hash").notNull(),
    scopesJson: text("scopes_json").notNull().default("[]"),
    expiresAt: integer("expires_at"),
    revokedAt: integer("revoked_at"),
    lastUsedAt: integer("last_used_at"),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("tenant_api_keys_prefix_uq").on(table.prefix),
    uniqueIndex("tenant_api_keys_hash_uq").on(table.keyHash),
    uniqueIndex("tenant_api_keys_tenant_id_id_uq").on(table.tenantId, table.id),
    index("tenant_api_keys_tenant_idx").on(table.tenantId, table.revokedAt),
  ],
);

export const captureSites = sqliteTable(
  "capture_sites",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    name: text("name").notNull(),
    publicKeyPrefix: text("public_key_prefix").notNull(),
    publicKeyHash: text("public_key_hash").notNull(),
    allowedOriginsJson: text("allowed_origins_json").notNull().default("[]"),
    formUrlPattern: text("form_url_pattern"),
    disclosureVersion: text("disclosure_version").notNull(),
    disclosureText: text("disclosure_text").notNull(),
    controller: text("controller").notNull(),
    purpose: text("purpose").notNull(),
    channelsJson: text("channels_json").notNull().default("[]"),
    status: text("status").notNull().default("active"),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("capture_sites_public_hash_uq").on(table.publicKeyHash),
    uniqueIndex("capture_sites_tenant_id_id_uq").on(table.tenantId, table.id),
    index("capture_sites_tenant_idx").on(table.tenantId, table.status),
    check("capture_sites_status_ck", sql`${table.status} IN ('active', 'paused', 'revoked')`),
  ],
);

export const sendingDomains = sqliteTable(
  "sending_domains",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    domain: text("domain").notNull(),
    dkimSelector: text("dkim_selector"),
    dkimMode: text("dkim_mode").notNull().default("provider"),
    status: text("status").notNull().default("pending"),
    lastDnsCheckAt: integer("last_dns_check_at"),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("sending_domains_tenant_domain_uq").on(table.tenantId, table.domain),
    uniqueIndex("sending_domains_tenant_id_id_uq").on(table.tenantId, table.id),
    index("sending_domains_tenant_status_idx").on(table.tenantId, table.status),
    check("sending_domains_dkim_mode_ck", sql`${table.dkimMode} IN ('provider', 'local')`),
    check("sending_domains_status_ck", sql`${table.status} IN ('pending', 'healthy', 'degraded', 'blocked')`),
  ],
);

export const dnsChecks = sqliteTable(
  "dns_checks",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    domainId: text("domain_id").notNull(),
    status: text("status").notNull(),
    spfStatus: text("spf_status").notNull(),
    dkimStatus: text("dkim_status").notNull(),
    dmarcStatus: text("dmarc_status").notNull(),
    mxStatus: text("mx_status").notNull(),
    recordsJson: text("records_json").notNull().default("{}"),
    errorCode: text("error_code"),
    checkedAt: integer("checked_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("dns_checks_tenant_id_id_uq").on(table.tenantId, table.id),
    index("dns_checks_domain_checked_idx").on(table.tenantId, table.domainId, table.checkedAt),
    foreignKey({
      name: "dns_checks_domain_fk",
      columns: [table.tenantId, table.domainId],
      foreignColumns: [sendingDomains.tenantId, sendingDomains.id],
    }).onDelete("restrict"),
    check("dns_checks_status_ck", sql`${table.status} IN ('healthy', 'degraded', 'blocked', 'error')`),
  ],
);

export const sendingInboxes = sqliteTable(
  "sending_inboxes",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    domainId: text("domain_id").notNull(),
    emailAddress: text("email_address").notNull(),
    displayName: text("display_name").notNull(),
    provider: text("provider").notNull(),
    smtpHost: text("smtp_host"),
    smtpPort: integer("smtp_port"),
    smtpSecure: integer("smtp_secure", { mode: "boolean" }).notNull().default(true),
    imapHost: text("imap_host"),
    imapPort: integer("imap_port"),
    imapSecure: integer("imap_secure", { mode: "boolean" }).notNull().default(true),
    encryptedCredentials: blob("encrypted_credentials", { mode: "buffer" }).notNull(),
    credentialKeyVersion: integer("credential_key_version").notNull(),
    credentialBinding: text("credential_binding"),
    dailyLimit: integer("daily_limit").notNull().default(40),
    status: text("status").notNull().default("paused"),
    nextAvailableAt: integer("next_available_at").notNull().default(0),
    lastUsedAt: integer("last_used_at"),
    lastPollAt: integer("last_poll_at"),
    authErrorAt: integer("auth_error_at"),
    createdAt: integer("created_at").notNull().default(nowMs),
    updatedAt: integer("updated_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("sending_inboxes_tenant_email_uq").on(table.tenantId, table.emailAddress),
    uniqueIndex("sending_inboxes_tenant_id_id_uq").on(table.tenantId, table.id),
    index("sending_inboxes_available_idx").on(table.tenantId, table.status, table.nextAvailableAt),
    foreignKey({
      name: "sending_inboxes_domain_fk",
      columns: [table.tenantId, table.domainId],
      foreignColumns: [sendingDomains.tenantId, sendingDomains.id],
    }).onDelete("restrict"),
    check("sending_inboxes_provider_ck", sql`${table.provider} IN ('smtp', 'google', 'microsoft')`),
    check("sending_inboxes_limit_ck", sql`${table.dailyLimit} BETWEEN 1 AND 50`),
    check("sending_inboxes_status_ck", sql`${table.status} IN ('active', 'paused', 'warmup', 'error')`),
  ],
);

export const campaigns = sqliteTable(
  "campaigns",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    name: text("name").notNull(),
    status: text("status").notNull().default("draft"),
    scheduleJson: text("schedule_json").notNull().default("{}"),
    timezone: text("timezone").notNull().default("UTC"),
    jitterMinSeconds: integer("jitter_min_seconds").notNull().default(180),
    jitterMaxSeconds: integer("jitter_max_seconds").notNull().default(450),
    dryRun: integer("dry_run", { mode: "boolean" }).notNull().default(true),
    approvedAt: integer("approved_at"),
    approvedByHash: text("approved_by_hash"),
    createdAt: integer("created_at").notNull().default(nowMs),
    updatedAt: integer("updated_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("campaigns_tenant_id_id_uq").on(table.tenantId, table.id),
    index("campaigns_tenant_status_idx").on(table.tenantId, table.status),
    check("campaigns_status_ck", sql`${table.status} IN ('draft', 'ready', 'active', 'paused', 'completed')`),
    check("campaigns_jitter_min_ck", sql`${table.jitterMinSeconds} BETWEEN 0 AND 3600`),
    check("campaigns_jitter_max_ck", sql`${table.jitterMaxSeconds} >= ${table.jitterMinSeconds} AND ${table.jitterMaxSeconds} <= 3600`),
  ],
);

export const sequenceSteps = sqliteTable(
  "sequence_steps",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    campaignId: text("campaign_id").notNull(),
    stepOrder: integer("step_order").notNull(),
    delayDays: integer("delay_days").notNull().default(0),
    subjectTemplate: text("subject_template").notNull(),
    bodyTemplate: text("body_template").notNull(),
    version: integer("version").notNull().default(1),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("sequence_steps_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("sequence_steps_campaign_order_uq").on(table.tenantId, table.campaignId, table.stepOrder),
    foreignKey({
      name: "sequence_steps_campaign_fk",
      columns: [table.tenantId, table.campaignId],
      foreignColumns: [campaigns.tenantId, campaigns.id],
    }).onDelete("restrict"),
    check("sequence_steps_order_ck", sql`${table.stepOrder} >= 1`),
    check("sequence_steps_delay_ck", sql`${table.delayDays} >= 0`),
  ],
);

export const leads = sqliteTable(
  "leads",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    emailAddress: text("email_address"),
    normalizedEmail: text("normalized_email"),
    phoneNumber: text("phone_number"),
    normalizedPhone: text("normalized_phone"),
    firstName: text("first_name"),
    lastName: text("last_name"),
    companyName: text("company_name"),
    status: text("status").notNull().default("active"),
    lawfulBasis: text("lawful_basis"),
    source: text("source"),
    jurisdiction: text("jurisdiction"),
    createdAt: integer("created_at").notNull().default(nowMs),
    updatedAt: integer("updated_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("leads_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("leads_tenant_email_uq").on(table.tenantId, table.normalizedEmail),
    index("leads_tenant_status_idx").on(table.tenantId, table.status),
    check("leads_status_ck", sql`${table.status} IN ('active', 'replied', 'unsubscribed', 'bounced', 'complained', 'archived')`),
  ],
);

export const campaignEnrollments = sqliteTable(
  "campaign_enrollments",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    campaignId: text("campaign_id").notNull(),
    leadId: text("lead_id").notNull(),
    inboxId: text("inbox_id"),
    status: text("status").notNull().default("pending"),
    currentStep: integer("current_step").notNull().default(1),
    nextSendAt: integer("next_send_at"),
    pauseReason: text("pause_reason"),
    createdAt: integer("created_at").notNull().default(nowMs),
    updatedAt: integer("updated_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("campaign_enrollments_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("campaign_enrollments_campaign_lead_uq").on(table.tenantId, table.campaignId, table.leadId),
    index("campaign_enrollments_due_idx").on(table.tenantId, table.status, table.nextSendAt),
    foreignKey({ name: "campaign_enrollments_campaign_fk", columns: [table.tenantId, table.campaignId], foreignColumns: [campaigns.tenantId, campaigns.id] }).onDelete("restrict"),
    foreignKey({ name: "campaign_enrollments_lead_fk", columns: [table.tenantId, table.leadId], foreignColumns: [leads.tenantId, leads.id] }).onDelete("restrict"),
    foreignKey({ name: "campaign_enrollments_inbox_fk", columns: [table.tenantId, table.inboxId], foreignColumns: [sendingInboxes.tenantId, sendingInboxes.id] }).onDelete("restrict"),
    check("campaign_enrollments_status_ck", sql`${table.status} IN ('pending', 'active', 'paused', 'completed', 'replied', 'unsubscribed', 'bounced', 'cancelled')`),
  ],
);

export const unsubscribeTokens = sqliteTable(
  "unsubscribe_tokens",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    leadId: text("lead_id").notNull(),
    tokenHash: text("token_hash").notNull(),
    expiresAt: integer("expires_at"),
    usedAt: integer("used_at"),
    revokedAt: integer("revoked_at"),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("unsubscribe_tokens_hash_uq").on(table.tokenHash),
    uniqueIndex("unsubscribe_tokens_tenant_id_id_uq").on(table.tenantId, table.id),
    index("unsubscribe_tokens_expiry_idx").on(table.tenantId, table.expiresAt, table.revokedAt),
    foreignKey({ name: "unsubscribe_tokens_lead_fk", columns: [table.tenantId, table.leadId], foreignColumns: [leads.tenantId, leads.id] }).onDelete("restrict"),
  ],
);

export const sendJobs = sqliteTable(
  "send_jobs",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    enrollmentId: text("enrollment_id").notNull(),
    stepId: text("step_id").notNull(),
    inboxId: text("inbox_id"),
    unsubscribeTokenId: text("unsubscribe_token_id"),
    status: text("status").notNull().default("queued"),
    dueAt: integer("due_at").notNull(),
    leaseTokenHash: text("lease_token_hash"),
    leaseExpiresAt: integer("lease_expires_at"),
    attemptCount: integer("attempt_count").notNull().default(0),
    renderedSubject: text("rendered_subject"),
    renderedBody: text("rendered_body"),
    stableMessageId: text("stable_message_id"),
    lastErrorCode: text("last_error_code"),
    createdAt: integer("created_at").notNull().default(nowMs),
    updatedAt: integer("updated_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("send_jobs_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("send_jobs_enrollment_step_uq").on(table.tenantId, table.enrollmentId, table.stepId),
    index("send_jobs_due_idx").on(table.status, table.dueAt, table.leaseExpiresAt),
    foreignKey({ name: "send_jobs_enrollment_fk", columns: [table.tenantId, table.enrollmentId], foreignColumns: [campaignEnrollments.tenantId, campaignEnrollments.id] }).onDelete("restrict"),
    foreignKey({ name: "send_jobs_step_fk", columns: [table.tenantId, table.stepId], foreignColumns: [sequenceSteps.tenantId, sequenceSteps.id] }).onDelete("restrict"),
    foreignKey({ name: "send_jobs_inbox_fk", columns: [table.tenantId, table.inboxId], foreignColumns: [sendingInboxes.tenantId, sendingInboxes.id] }).onDelete("restrict"),
    foreignKey({ name: "send_jobs_unsubscribe_fk", columns: [table.tenantId, table.unsubscribeTokenId], foreignColumns: [unsubscribeTokens.tenantId, unsubscribeTokens.id] }).onDelete("restrict"),
    check("send_jobs_status_ck", sql`${table.status} IN ('queued', 'leased', 'sending', 'sent', 'failed', 'unknown', 'cancelled')`),
    check("send_jobs_attempt_count_ck", sql`${table.attemptCount} >= 0`),
  ],
);

export const deliveryAttempts = sqliteTable(
  "delivery_attempts",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    jobId: text("job_id").notNull(),
    inboxId: text("inbox_id").notNull(),
    attemptNumber: integer("attempt_number").notNull(),
    status: text("status").notNull(),
    providerMessageId: text("provider_message_id"),
    errorCode: text("error_code"),
    startedAt: integer("started_at").notNull().default(nowMs),
    completedAt: integer("completed_at"),
  },
  (table) => [
    uniqueIndex("delivery_attempts_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("delivery_attempts_job_number_uq").on(table.tenantId, table.jobId, table.attemptNumber),
    index("delivery_attempts_job_idx").on(table.tenantId, table.jobId, table.status),
    foreignKey({ name: "delivery_attempts_job_fk", columns: [table.tenantId, table.jobId], foreignColumns: [sendJobs.tenantId, sendJobs.id] }).onDelete("restrict"),
    foreignKey({ name: "delivery_attempts_inbox_fk", columns: [table.tenantId, table.inboxId], foreignColumns: [sendingInboxes.tenantId, sendingInboxes.id] }).onDelete("restrict"),
    check("delivery_attempts_status_ck", sql`${table.status} IN ('reserved', 'sending', 'accepted', 'rejected', 'unknown')`),
  ],
);

export const outboundMessages = sqliteTable(
  "outbound_messages",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    jobId: text("job_id").notNull(),
    leadId: text("lead_id").notNull(),
    inboxId: text("inbox_id").notNull(),
    messageId: text("message_id").notNull(),
    subject: text("subject").notNull(),
    bodyText: text("body_text").notNull(),
    bodyHtml: text("body_html"),
    headersJson: text("headers_json").notNull().default("{}"),
    providerMessageId: text("provider_message_id"),
    status: text("status").notNull(),
    sentAt: integer("sent_at"),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("outbound_messages_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("outbound_messages_job_uq").on(table.tenantId, table.jobId),
    uniqueIndex("outbound_messages_message_id_uq").on(table.messageId),
    foreignKey({ name: "outbound_messages_job_fk", columns: [table.tenantId, table.jobId], foreignColumns: [sendJobs.tenantId, sendJobs.id] }).onDelete("restrict"),
    foreignKey({ name: "outbound_messages_lead_fk", columns: [table.tenantId, table.leadId], foreignColumns: [leads.tenantId, leads.id] }).onDelete("restrict"),
    foreignKey({ name: "outbound_messages_inbox_fk", columns: [table.tenantId, table.inboxId], foreignColumns: [sendingInboxes.tenantId, sendingInboxes.id] }).onDelete("restrict"),
    check("outbound_messages_status_ck", sql`${table.status} IN ('prepared', 'accepted', 'rejected', 'unknown')`),
  ],
);

export const inboxDailyUsage = sqliteTable(
  "inbox_daily_usage",
  {
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    inboxId: text("inbox_id").notNull(),
    usageDate: text("usage_date").notNull(),
    reservedCount: integer("reserved_count").notNull().default(0),
    sentCount: integer("sent_count").notNull().default(0),
    updatedAt: integer("updated_at").notNull().default(nowMs),
  },
  (table) => [
    primaryKey({ columns: [table.tenantId, table.inboxId, table.usageDate], name: "inbox_daily_usage_pk" }),
    foreignKey({ name: "inbox_daily_usage_inbox_fk", columns: [table.tenantId, table.inboxId], foreignColumns: [sendingInboxes.tenantId, sendingInboxes.id] }).onDelete("restrict"),
    check("inbox_daily_usage_reserved_ck", sql`${table.reservedCount} >= 0`),
    check("inbox_daily_usage_sent_ck", sql`${table.sentCount} >= 0`),
  ],
);

export const workerRuns = sqliteTable(
  "worker_runs",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    runType: text("run_type").notNull(),
    bucketKey: text("bucket_key").notNull(),
    status: text("status").notNull().default("running"),
    leaseExpiresAt: integer("lease_expires_at"),
    statsJson: text("stats_json").notNull().default("{}"),
    errorCode: text("error_code"),
    startedAt: integer("started_at").notNull().default(nowMs),
    finishedAt: integer("finished_at"),
  },
  (table) => [
    uniqueIndex("worker_runs_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("worker_runs_bucket_uq").on(table.tenantId, table.runType, table.bucketKey),
    check("worker_runs_type_ck", sql`${table.runType} IN ('dispatch', 'poll_inboxes', 'dns')`),
    check("worker_runs_status_ck", sql`${table.status} IN ('running', 'completed', 'failed')`),
  ],
);

export const imapCursors = sqliteTable(
  "imap_cursors",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    inboxId: text("inbox_id").notNull(),
    mailbox: text("mailbox").notNull().default("INBOX"),
    uidValidity: text("uid_validity"),
    lastUid: integer("last_uid").notNull().default(0),
    highestModseq: text("highest_modseq"),
    updatedAt: integer("updated_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("imap_cursors_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("imap_cursors_mailbox_uq").on(table.tenantId, table.inboxId, table.mailbox),
    foreignKey({ name: "imap_cursors_inbox_fk", columns: [table.tenantId, table.inboxId], foreignColumns: [sendingInboxes.tenantId, sendingInboxes.id] }).onDelete("restrict"),
  ],
);

export const inboundMessages = sqliteTable(
  "inbound_messages",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    inboxId: text("inbox_id").notNull(),
    uidValidity: text("uid_validity").notNull(),
    uid: integer("uid").notNull(),
    messageId: text("message_id"),
    inReplyTo: text("in_reply_to"),
    referencesJson: text("references_json").notNull().default("[]"),
    fromAddress: text("from_address").notNull(),
    subject: text("subject"),
    headersJson: text("headers_json").notNull().default("{}"),
    textSnippet: text("text_snippet"),
    classification: text("classification"),
    receivedAt: integer("received_at").notNull(),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("inbound_messages_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("inbound_messages_uid_uq").on(table.tenantId, table.inboxId, table.uidValidity, table.uid),
    index("inbound_messages_message_id_idx").on(table.tenantId, table.messageId),
    foreignKey({ name: "inbound_messages_inbox_fk", columns: [table.tenantId, table.inboxId], foreignColumns: [sendingInboxes.tenantId, sendingInboxes.id] }).onDelete("restrict"),
  ],
);

export const replyEvents = sqliteTable(
  "reply_events",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    inboundMessageId: text("inbound_message_id").notNull(),
    enrollmentId: text("enrollment_id"),
    leadId: text("lead_id"),
    classification: text("classification").notNull(),
    effectAppliedAt: integer("effect_applied_at"),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("reply_events_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("reply_events_inbound_uq").on(table.tenantId, table.inboundMessageId),
    foreignKey({ name: "reply_events_inbound_fk", columns: [table.tenantId, table.inboundMessageId], foreignColumns: [inboundMessages.tenantId, inboundMessages.id] }).onDelete("restrict"),
    foreignKey({ name: "reply_events_enrollment_fk", columns: [table.tenantId, table.enrollmentId], foreignColumns: [campaignEnrollments.tenantId, campaignEnrollments.id] }).onDelete("restrict"),
    foreignKey({ name: "reply_events_lead_fk", columns: [table.tenantId, table.leadId], foreignColumns: [leads.tenantId, leads.id] }).onDelete("restrict"),
    check("reply_events_classification_ck", sql`${table.classification} IN ('unsubscribe', 'out_of_office', 'interested', 'not_interested', 'bounce', 'other')`),
  ],
);

export const consentLogs = sqliteTable(
  "consent_logs",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    captureSiteId: text("capture_site_id"),
    subjectIdentifierHash: text("subject_identifier_hash").notNull(),
    controller: text("controller").notNull(),
    purpose: text("purpose").notNull(),
    disclosureVersion: text("disclosure_version").notNull(),
    affirmativeAction: text("affirmative_action").notNull(),
    canonicalPayload: text("canonical_payload").notNull(),
    payloadSha256: text("payload_sha256").notNull(),
    signatureHmac: text("signature_hmac").notNull(),
    signatureKeyVersion: integer("signature_key_version").notNull(),
    priorHash: text("prior_hash"),
    idempotencyKey: text("idempotency_key").notNull(),
    occurredAt: integer("occurred_at").notNull(),
    receivedAt: integer("received_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("consent_logs_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("consent_logs_idempotency_uq").on(table.tenantId, table.idempotencyKey),
    index("consent_logs_subject_idx").on(table.tenantId, table.subjectIdentifierHash, table.occurredAt),
    foreignKey({ name: "consent_logs_site_fk", columns: [table.tenantId, table.captureSiteId], foreignColumns: [captureSites.tenantId, captureSites.id] }).onDelete("restrict"),
  ],
);

export const consentCertificates = sqliteTable(
  "consent_certificates",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    consentLogId: text("consent_log_id").notNull(),
    shareTokenHash: text("share_token_hash"),
    shareExpiresAt: integer("share_expires_at"),
    revokedAt: integer("revoked_at"),
    lastDownloadedAt: integer("last_downloaded_at"),
    downloadCount: integer("download_count").notNull().default(0),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("consent_certificates_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("consent_certificates_consent_uq").on(table.tenantId, table.consentLogId),
    uniqueIndex("consent_certificates_share_hash_uq").on(table.shareTokenHash),
    foreignKey({ name: "consent_certificates_log_fk", columns: [table.tenantId, table.consentLogId], foreignColumns: [consentLogs.tenantId, consentLogs.id] }).onDelete("restrict"),
    check("consent_certificates_download_count_ck", sql`${table.downloadCount} >= 0`),
  ],
);

export const suppressions = sqliteTable(
  "suppressions",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    identifierType: text("identifier_type").notNull(),
    identifierHash: text("identifier_hash").notNull(),
    encryptedIdentifier: blob("encrypted_identifier", { mode: "buffer" }),
    reason: text("reason").notNull().default("unsubscribe"),
    source: text("source").notNull().default("manual"),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("suppressions_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("suppressions_identifier_uq").on(table.tenantId, table.identifierType, table.identifierHash),
    index("suppressions_lookup_idx").on(table.tenantId, table.identifierHash),
    check("suppressions_type_ck", sql`${table.identifierType} IN ('email', 'sms')`),
  ],
);

export const suppressionEvents = sqliteTable(
  "suppression_events",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    suppressionId: text("suppression_id").notNull(),
    action: text("action").notNull(),
    source: text("source").notNull(),
    metadataJson: text("metadata_json").notNull().default("{}"),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("suppression_events_tenant_id_id_uq").on(table.tenantId, table.id),
    index("suppression_events_suppression_idx").on(table.tenantId, table.suppressionId, table.createdAt),
    foreignKey({ name: "suppression_events_suppression_fk", columns: [table.tenantId, table.suppressionId], foreignColumns: [suppressions.tenantId, suppressions.id] }).onDelete("restrict"),
    check("suppression_events_action_ck", sql`${table.action} IN ('added', 'confirmed', 'imported')`),
  ],
);

export const notifications = sqliteTable(
  "notifications",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    type: text("type").notNull(),
    payloadJson: text("payload_json").notNull(),
    status: text("status").notNull().default("pending"),
    attempts: integer("attempts").notNull().default(0),
    nextAttemptAt: integer("next_attempt_at").notNull().default(0),
    lastErrorCode: text("last_error_code"),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("notifications_tenant_id_id_uq").on(table.tenantId, table.id),
    index("notifications_due_idx").on(table.status, table.nextAttemptAt),
    check("notifications_status_ck", sql`${table.status} IN ('pending', 'sent', 'failed')`),
    check("notifications_attempts_ck", sql`${table.attempts} >= 0`),
  ],
);

export const auditEvents = sqliteTable(
  "audit_events",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    actorType: text("actor_type").notNull(),
    actorIdHash: text("actor_id_hash"),
    action: text("action").notNull(),
    resourceType: text("resource_type").notNull(),
    resourceId: text("resource_id"),
    metadataJson: text("metadata_json").notNull().default("{}"),
    createdAt: integer("created_at").notNull().default(nowMs),
  },
  (table) => [
    uniqueIndex("audit_events_tenant_id_id_uq").on(table.tenantId, table.id),
    index("audit_events_resource_idx").on(table.tenantId, table.resourceType, table.resourceId, table.createdAt),
  ],
);

export const rateLimitBuckets = sqliteTable(
  "rate_limit_buckets",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "restrict" }),
    scope: text("scope").notNull(),
    bucketKeyHash: text("bucket_key_hash").notNull(),
    windowStartedAt: integer("window_started_at").notNull(),
    count: integer("count").notNull().default(0),
    expiresAt: integer("expires_at").notNull(),
  },
  (table) => [
    uniqueIndex("rate_limit_buckets_tenant_id_id_uq").on(table.tenantId, table.id),
    uniqueIndex("rate_limit_buckets_window_uq").on(table.tenantId, table.scope, table.bucketKeyHash, table.windowStartedAt),
    index("rate_limit_buckets_expiry_idx").on(table.expiresAt),
    check("rate_limit_buckets_count_ck", sql`${table.count} >= 0`),
  ],
);

export const schema = {
  tenants,
  tenantApiKeys,
  captureSites,
  sendingDomains,
  dnsChecks,
  sendingInboxes,
  campaigns,
  sequenceSteps,
  leads,
  campaignEnrollments,
  sendJobs,
  deliveryAttempts,
  outboundMessages,
  inboxDailyUsage,
  workerRuns,
  imapCursors,
  inboundMessages,
  replyEvents,
  consentLogs,
  consentCertificates,
  suppressions,
  suppressionEvents,
  unsubscribeTokens,
  notifications,
  auditEvents,
  rateLimitBuckets,
};

