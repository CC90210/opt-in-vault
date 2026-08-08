CREATE TABLE `audit_events` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`actor_type` text NOT NULL,
	`actor_id_hash` text,
	`action` text NOT NULL,
	`resource_type` text NOT NULL,
	`resource_id` text,
	`metadata_json` text DEFAULT '{}' NOT NULL,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "audit_events_metadata_json_ck" CHECK(json_valid("audit_events"."metadata_json"))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `audit_events_tenant_id_id_uq` ON `audit_events` (`tenant_id`,`id`);--> statement-breakpoint
CREATE INDEX `audit_events_resource_idx` ON `audit_events` (`tenant_id`,`resource_type`,`resource_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `campaign_enrollments` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`campaign_id` text NOT NULL,
	`lead_id` text NOT NULL,
	`inbox_id` text,
	`status` text DEFAULT 'pending' NOT NULL,
	`current_step` integer DEFAULT 1 NOT NULL,
	`next_send_at` integer,
	`pause_reason` text,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`campaign_id`) REFERENCES `campaigns`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`lead_id`) REFERENCES `leads`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`inbox_id`) REFERENCES `sending_inboxes`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "campaign_enrollments_status_ck" CHECK("campaign_enrollments"."status" IN ('pending', 'active', 'paused', 'completed', 'replied', 'unsubscribed', 'bounced', 'cancelled'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `campaign_enrollments_tenant_id_id_uq` ON `campaign_enrollments` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `campaign_enrollments_identity_uq` ON `campaign_enrollments` (`tenant_id`,`id`,`campaign_id`,`lead_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `campaign_enrollments_campaign_lead_uq` ON `campaign_enrollments` (`tenant_id`,`campaign_id`,`lead_id`);--> statement-breakpoint
CREATE INDEX `campaign_enrollments_due_idx` ON `campaign_enrollments` (`tenant_id`,`status`,`next_send_at`);--> statement-breakpoint
CREATE TABLE `campaigns` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`name` text NOT NULL,
	`status` text DEFAULT 'draft' NOT NULL,
	`schedule_json` text DEFAULT '{}' NOT NULL,
	`timezone` text DEFAULT 'UTC' NOT NULL,
	`jitter_min_seconds` integer DEFAULT 180 NOT NULL,
	`jitter_max_seconds` integer DEFAULT 450 NOT NULL,
	`dry_run` integer DEFAULT true NOT NULL,
	`approved_at` integer,
	`approved_by_hash` text,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "campaigns_status_ck" CHECK("campaigns"."status" IN ('draft', 'ready', 'active', 'paused', 'completed')),
	CONSTRAINT "campaigns_jitter_min_ck" CHECK("campaigns"."jitter_min_seconds" BETWEEN 0 AND 3600),
	CONSTRAINT "campaigns_jitter_max_ck" CHECK("campaigns"."jitter_max_seconds" >= "campaigns"."jitter_min_seconds" AND "campaigns"."jitter_max_seconds" <= 3600),
	CONSTRAINT "campaigns_schedule_json_ck" CHECK(json_valid("campaigns"."schedule_json"))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `campaigns_tenant_id_id_uq` ON `campaigns` (`tenant_id`,`id`);--> statement-breakpoint
CREATE INDEX `campaigns_tenant_status_idx` ON `campaigns` (`tenant_id`,`status`);--> statement-breakpoint
CREATE TABLE `capture_sites` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`name` text NOT NULL,
	`public_key_prefix` text NOT NULL,
	`public_key_hash` text NOT NULL,
	`allowed_origins_json` text DEFAULT '[]' NOT NULL,
	`form_url_pattern` text,
	`disclosure_version` text NOT NULL,
	`disclosure_text` text NOT NULL,
	`controller` text NOT NULL,
	`purpose` text NOT NULL,
	`channels_json` text DEFAULT '[]' NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "capture_sites_status_ck" CHECK("capture_sites"."status" IN ('active', 'paused', 'revoked')),
	CONSTRAINT "capture_sites_origins_json_ck" CHECK(json_valid("capture_sites"."allowed_origins_json")),
	CONSTRAINT "capture_sites_channels_json_ck" CHECK(json_valid("capture_sites"."channels_json"))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `capture_sites_public_hash_uq` ON `capture_sites` (`public_key_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `capture_sites_tenant_id_id_uq` ON `capture_sites` (`tenant_id`,`id`);--> statement-breakpoint
CREATE INDEX `capture_sites_tenant_idx` ON `capture_sites` (`tenant_id`,`status`);--> statement-breakpoint
CREATE TABLE `consent_certificates` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`consent_log_id` text NOT NULL,
	`share_token_hash` text,
	`share_expires_at` integer,
	`revoked_at` integer,
	`last_downloaded_at` integer,
	`download_count` integer DEFAULT 0 NOT NULL,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`consent_log_id`) REFERENCES `consent_logs`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "consent_certificates_download_count_ck" CHECK("consent_certificates"."download_count" >= 0)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `consent_certificates_tenant_id_id_uq` ON `consent_certificates` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `consent_certificates_consent_uq` ON `consent_certificates` (`tenant_id`,`consent_log_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `consent_certificates_share_hash_uq` ON `consent_certificates` (`share_token_hash`);--> statement-breakpoint
CREATE TABLE `consent_logs` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`capture_site_id` text,
	`subject_identifier_hash` text NOT NULL,
	`controller` text NOT NULL,
	`purpose` text NOT NULL,
	`disclosure_version` text NOT NULL,
	`affirmative_action` text NOT NULL,
	`canonical_payload_ciphertext` blob NOT NULL,
	`payload_key_version` integer NOT NULL,
	`payload_sha256` text NOT NULL,
	`signature_hmac` text NOT NULL,
	`signature_key_version` integer NOT NULL,
	`prior_hash` text,
	`idempotency_key` text NOT NULL,
	`occurred_at` integer NOT NULL,
	`retention_expires_at` integer NOT NULL,
	`received_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`capture_site_id`) REFERENCES `capture_sites`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "consent_logs_payload_key_version_ck" CHECK("consent_logs"."payload_key_version" >= 1),
	CONSTRAINT "consent_logs_signature_key_version_ck" CHECK("consent_logs"."signature_key_version" >= 1),
	CONSTRAINT "consent_logs_retention_ck" CHECK("consent_logs"."retention_expires_at" > "consent_logs"."received_at")
);
--> statement-breakpoint
CREATE UNIQUE INDEX `consent_logs_tenant_id_id_uq` ON `consent_logs` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `consent_logs_idempotency_uq` ON `consent_logs` (`tenant_id`,`idempotency_key`);--> statement-breakpoint
CREATE INDEX `consent_logs_subject_idx` ON `consent_logs` (`tenant_id`,`subject_identifier_hash`,`occurred_at`);--> statement-breakpoint
CREATE TABLE `delivery_attempts` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`job_id` text NOT NULL,
	`inbox_id` text NOT NULL,
	`attempt_number` integer NOT NULL,
	`status` text NOT NULL,
	`provider_message_id` text,
	`error_code` text,
	`started_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	`completed_at` integer,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`job_id`) REFERENCES `send_jobs`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`inbox_id`) REFERENCES `sending_inboxes`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "delivery_attempts_status_ck" CHECK("delivery_attempts"."status" IN ('reserved', 'sending', 'accepted', 'rejected', 'unknown'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `delivery_attempts_tenant_id_id_uq` ON `delivery_attempts` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `delivery_attempts_job_number_uq` ON `delivery_attempts` (`tenant_id`,`job_id`,`attempt_number`);--> statement-breakpoint
CREATE INDEX `delivery_attempts_job_idx` ON `delivery_attempts` (`tenant_id`,`job_id`,`status`);--> statement-breakpoint
CREATE TABLE `dns_checks` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`domain_id` text NOT NULL,
	`status` text NOT NULL,
	`spf_status` text NOT NULL,
	`dkim_status` text NOT NULL,
	`dmarc_status` text NOT NULL,
	`mx_status` text NOT NULL,
	`records_json` text DEFAULT '{}' NOT NULL,
	`error_code` text,
	`checked_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`domain_id`) REFERENCES `sending_domains`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "dns_checks_status_ck" CHECK("dns_checks"."status" IN ('healthy', 'degraded', 'blocked', 'error')),
	CONSTRAINT "dns_checks_records_json_ck" CHECK(json_valid("dns_checks"."records_json"))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `dns_checks_tenant_id_id_uq` ON `dns_checks` (`tenant_id`,`id`);--> statement-breakpoint
CREATE INDEX `dns_checks_domain_checked_idx` ON `dns_checks` (`tenant_id`,`domain_id`,`checked_at`);--> statement-breakpoint
CREATE TABLE `imap_cursors` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`inbox_id` text NOT NULL,
	`mailbox` text DEFAULT 'INBOX' NOT NULL,
	`uid_validity` text,
	`last_uid` integer DEFAULT 0 NOT NULL,
	`highest_modseq` text,
	`updated_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`inbox_id`) REFERENCES `sending_inboxes`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict
);
--> statement-breakpoint
CREATE UNIQUE INDEX `imap_cursors_tenant_id_id_uq` ON `imap_cursors` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `imap_cursors_mailbox_uq` ON `imap_cursors` (`tenant_id`,`inbox_id`,`mailbox`);--> statement-breakpoint
CREATE TABLE `inbound_messages` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`inbox_id` text NOT NULL,
	`uid_validity` text NOT NULL,
	`uid` integer NOT NULL,
	`message_id` text,
	`in_reply_to` text,
	`references_json` text DEFAULT '[]' NOT NULL,
	`from_address` text NOT NULL,
	`subject` text,
	`headers_json` text DEFAULT '{}' NOT NULL,
	`text_snippet` text,
	`classification` text,
	`received_at` integer NOT NULL,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`inbox_id`) REFERENCES `sending_inboxes`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "inbound_messages_references_json_ck" CHECK(json_valid("inbound_messages"."references_json")),
	CONSTRAINT "inbound_messages_headers_json_ck" CHECK(json_valid("inbound_messages"."headers_json"))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `inbound_messages_tenant_id_id_uq` ON `inbound_messages` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `inbound_messages_uid_uq` ON `inbound_messages` (`tenant_id`,`inbox_id`,`uid_validity`,`uid`);--> statement-breakpoint
CREATE INDEX `inbound_messages_message_id_idx` ON `inbound_messages` (`tenant_id`,`message_id`);--> statement-breakpoint
CREATE TABLE `inbox_daily_usage` (
	`tenant_id` text NOT NULL,
	`inbox_id` text NOT NULL,
	`usage_date` text NOT NULL,
	`reserved_count` integer DEFAULT 0 NOT NULL,
	`sent_count` integer DEFAULT 0 NOT NULL,
	`updated_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	PRIMARY KEY(`tenant_id`, `inbox_id`, `usage_date`),
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`inbox_id`) REFERENCES `sending_inboxes`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "inbox_daily_usage_reserved_ck" CHECK("inbox_daily_usage"."reserved_count" >= 0),
	CONSTRAINT "inbox_daily_usage_sent_ck" CHECK("inbox_daily_usage"."sent_count" >= 0)
);
--> statement-breakpoint
CREATE TABLE `leads` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`email_address` text,
	`normalized_email` text,
	`phone_number` text,
	`normalized_phone` text,
	`first_name` text,
	`last_name` text,
	`company_name` text,
	`status` text DEFAULT 'active' NOT NULL,
	`lawful_basis` text,
	`source` text,
	`jurisdiction` text,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "leads_status_ck" CHECK("leads"."status" IN ('active', 'replied', 'unsubscribed', 'bounced', 'complained', 'archived'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `leads_tenant_id_id_uq` ON `leads` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `leads_tenant_email_uq` ON `leads` (`tenant_id`,`normalized_email`);--> statement-breakpoint
CREATE UNIQUE INDEX `leads_tenant_phone_uq` ON `leads` (`tenant_id`,`normalized_phone`);--> statement-breakpoint
CREATE INDEX `leads_tenant_status_idx` ON `leads` (`tenant_id`,`status`);--> statement-breakpoint
CREATE TABLE `notifications` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`type` text NOT NULL,
	`payload_json` text NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`attempts` integer DEFAULT 0 NOT NULL,
	`next_attempt_at` integer DEFAULT 0 NOT NULL,
	`last_error_code` text,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "notifications_status_ck" CHECK("notifications"."status" IN ('pending', 'sent', 'failed')),
	CONSTRAINT "notifications_attempts_ck" CHECK("notifications"."attempts" >= 0),
	CONSTRAINT "notifications_payload_json_ck" CHECK(json_valid("notifications"."payload_json"))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `notifications_tenant_id_id_uq` ON `notifications` (`tenant_id`,`id`);--> statement-breakpoint
CREATE INDEX `notifications_due_idx` ON `notifications` (`status`,`next_attempt_at`);--> statement-breakpoint
CREATE TABLE `outbound_messages` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`job_id` text NOT NULL,
	`lead_id` text NOT NULL,
	`inbox_id` text NOT NULL,
	`message_id` text NOT NULL,
	`subject` text NOT NULL,
	`body_text` text NOT NULL,
	`body_html` text,
	`headers_json` text DEFAULT '{}' NOT NULL,
	`provider_message_id` text,
	`status` text NOT NULL,
	`sent_at` integer,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`job_id`,`lead_id`,`inbox_id`) REFERENCES `send_jobs`(`tenant_id`,`id`,`lead_id`,`inbox_id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`lead_id`) REFERENCES `leads`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`inbox_id`) REFERENCES `sending_inboxes`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "outbound_messages_status_ck" CHECK("outbound_messages"."status" IN ('prepared', 'accepted', 'rejected', 'unknown')),
	CONSTRAINT "outbound_messages_headers_json_ck" CHECK(json_valid("outbound_messages"."headers_json"))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `outbound_messages_tenant_id_id_uq` ON `outbound_messages` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `outbound_messages_job_uq` ON `outbound_messages` (`tenant_id`,`job_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `outbound_messages_message_id_uq` ON `outbound_messages` (`message_id`);--> statement-breakpoint
CREATE TABLE `rate_limit_buckets` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`scope` text NOT NULL,
	`bucket_key_hash` text NOT NULL,
	`window_started_at` integer NOT NULL,
	`count` integer DEFAULT 0 NOT NULL,
	`expires_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "rate_limit_buckets_count_ck" CHECK("rate_limit_buckets"."count" >= 0)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `rate_limit_buckets_tenant_id_id_uq` ON `rate_limit_buckets` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `rate_limit_buckets_window_uq` ON `rate_limit_buckets` (`tenant_id`,`scope`,`bucket_key_hash`,`window_started_at`);--> statement-breakpoint
CREATE INDEX `rate_limit_buckets_expiry_idx` ON `rate_limit_buckets` (`expires_at`);--> statement-breakpoint
CREATE TABLE `reply_events` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`inbound_message_id` text NOT NULL,
	`enrollment_id` text,
	`lead_id` text,
	`classification` text NOT NULL,
	`effect_applied_at` integer,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`inbound_message_id`) REFERENCES `inbound_messages`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`enrollment_id`) REFERENCES `campaign_enrollments`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`lead_id`) REFERENCES `leads`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "reply_events_classification_ck" CHECK("reply_events"."classification" IN ('unsubscribe', 'out_of_office', 'interested', 'not_interested', 'bounce', 'other'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `reply_events_tenant_id_id_uq` ON `reply_events` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `reply_events_inbound_uq` ON `reply_events` (`tenant_id`,`inbound_message_id`);--> statement-breakpoint
CREATE TABLE `send_jobs` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`enrollment_id` text NOT NULL,
	`campaign_id` text NOT NULL,
	`lead_id` text NOT NULL,
	`step_id` text NOT NULL,
	`inbox_id` text,
	`unsubscribe_token_id` text,
	`status` text DEFAULT 'queued' NOT NULL,
	`due_at` integer NOT NULL,
	`lease_token_hash` text,
	`lease_expires_at` integer,
	`attempt_count` integer DEFAULT 0 NOT NULL,
	`rendered_subject` text,
	`rendered_body` text,
	`stable_message_id` text,
	`last_error_code` text,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`enrollment_id`,`campaign_id`,`lead_id`) REFERENCES `campaign_enrollments`(`tenant_id`,`id`,`campaign_id`,`lead_id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`step_id`,`campaign_id`) REFERENCES `sequence_steps`(`tenant_id`,`id`,`campaign_id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`inbox_id`) REFERENCES `sending_inboxes`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`unsubscribe_token_id`,`lead_id`) REFERENCES `unsubscribe_tokens`(`tenant_id`,`id`,`lead_id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "send_jobs_status_ck" CHECK("send_jobs"."status" IN ('queued', 'leased', 'sending', 'sent', 'failed', 'unknown', 'cancelled')),
	CONSTRAINT "send_jobs_attempt_count_ck" CHECK("send_jobs"."attempt_count" >= 0)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `send_jobs_tenant_id_id_uq` ON `send_jobs` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `send_jobs_delivery_identity_uq` ON `send_jobs` (`tenant_id`,`id`,`lead_id`,`inbox_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `send_jobs_enrollment_step_uq` ON `send_jobs` (`tenant_id`,`enrollment_id`,`step_id`);--> statement-breakpoint
CREATE INDEX `send_jobs_queued_due_idx` ON `send_jobs` (`due_at`) WHERE "send_jobs"."status" = 'queued';--> statement-breakpoint
CREATE INDEX `send_jobs_expired_lease_idx` ON `send_jobs` (`lease_expires_at`) WHERE "send_jobs"."status" = 'leased';--> statement-breakpoint
CREATE TABLE `sending_domains` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`domain` text NOT NULL,
	`dkim_selector` text,
	`dkim_mode` text DEFAULT 'provider' NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`last_dns_check_at` integer,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "sending_domains_dkim_mode_ck" CHECK("sending_domains"."dkim_mode" IN ('provider', 'local')),
	CONSTRAINT "sending_domains_status_ck" CHECK("sending_domains"."status" IN ('pending', 'healthy', 'degraded', 'blocked'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sending_domains_tenant_domain_uq` ON `sending_domains` (`tenant_id`,`domain`);--> statement-breakpoint
CREATE UNIQUE INDEX `sending_domains_tenant_id_id_uq` ON `sending_domains` (`tenant_id`,`id`);--> statement-breakpoint
CREATE INDEX `sending_domains_tenant_status_idx` ON `sending_domains` (`tenant_id`,`status`);--> statement-breakpoint
CREATE TABLE `sending_inboxes` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`domain_id` text NOT NULL,
	`email_address` text NOT NULL,
	`display_name` text NOT NULL,
	`provider` text NOT NULL,
	`smtp_host` text,
	`smtp_port` integer,
	`smtp_secure` integer DEFAULT true NOT NULL,
	`imap_host` text,
	`imap_port` integer,
	`imap_secure` integer DEFAULT true NOT NULL,
	`encrypted_credentials` blob NOT NULL,
	`credential_key_version` integer NOT NULL,
	`credential_binding` text,
	`daily_limit` integer DEFAULT 40 NOT NULL,
	`status` text DEFAULT 'paused' NOT NULL,
	`next_available_at` integer DEFAULT 0 NOT NULL,
	`last_used_at` integer,
	`last_poll_at` integer,
	`auth_error_at` integer,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`domain_id`) REFERENCES `sending_domains`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "sending_inboxes_provider_ck" CHECK("sending_inboxes"."provider" IN ('smtp', 'google', 'microsoft')),
	CONSTRAINT "sending_inboxes_limit_ck" CHECK("sending_inboxes"."daily_limit" BETWEEN 1 AND 50),
	CONSTRAINT "sending_inboxes_status_ck" CHECK("sending_inboxes"."status" IN ('active', 'paused', 'warmup', 'error'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sending_inboxes_tenant_email_uq` ON `sending_inboxes` (`tenant_id`,`email_address`);--> statement-breakpoint
CREATE UNIQUE INDEX `sending_inboxes_tenant_id_id_uq` ON `sending_inboxes` (`tenant_id`,`id`);--> statement-breakpoint
CREATE INDEX `sending_inboxes_available_idx` ON `sending_inboxes` (`tenant_id`,`status`,`next_available_at`);--> statement-breakpoint
CREATE TABLE `sequence_steps` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`campaign_id` text NOT NULL,
	`step_order` integer NOT NULL,
	`delay_days` integer DEFAULT 0 NOT NULL,
	`subject_template` text NOT NULL,
	`body_template` text NOT NULL,
	`version` integer DEFAULT 1 NOT NULL,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`campaign_id`) REFERENCES `campaigns`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "sequence_steps_order_ck" CHECK("sequence_steps"."step_order" >= 1),
	CONSTRAINT "sequence_steps_delay_ck" CHECK("sequence_steps"."delay_days" >= 0)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sequence_steps_tenant_id_id_uq` ON `sequence_steps` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `sequence_steps_campaign_identity_uq` ON `sequence_steps` (`tenant_id`,`id`,`campaign_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `sequence_steps_campaign_order_uq` ON `sequence_steps` (`tenant_id`,`campaign_id`,`step_order`);--> statement-breakpoint
CREATE TABLE `suppression_events` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`suppression_id` text NOT NULL,
	`action` text NOT NULL,
	`source` text NOT NULL,
	`metadata_json` text DEFAULT '{}' NOT NULL,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`suppression_id`) REFERENCES `suppressions`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "suppression_events_action_ck" CHECK("suppression_events"."action" IN ('added', 'confirmed', 'imported')),
	CONSTRAINT "suppression_events_metadata_json_ck" CHECK(json_valid("suppression_events"."metadata_json"))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `suppression_events_tenant_id_id_uq` ON `suppression_events` (`tenant_id`,`id`);--> statement-breakpoint
CREATE INDEX `suppression_events_suppression_idx` ON `suppression_events` (`tenant_id`,`suppression_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `suppressions` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`identifier_type` text NOT NULL,
	`identifier_hash` text NOT NULL,
	`encrypted_identifier` blob,
	`reason` text DEFAULT 'unsubscribe' NOT NULL,
	`source` text DEFAULT 'manual' NOT NULL,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "suppressions_type_ck" CHECK("suppressions"."identifier_type" IN ('email', 'sms'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `suppressions_tenant_id_id_uq` ON `suppressions` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `suppressions_identifier_uq` ON `suppressions` (`tenant_id`,`identifier_type`,`identifier_hash`);--> statement-breakpoint
CREATE INDEX `suppressions_lookup_idx` ON `suppressions` (`tenant_id`,`identifier_hash`);--> statement-breakpoint
CREATE TABLE `tenant_api_keys` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`prefix` text NOT NULL,
	`key_hash` text NOT NULL,
	`hash_key_version` integer DEFAULT 1 NOT NULL,
	`scopes_json` text DEFAULT '[]' NOT NULL,
	`expires_at` integer,
	`revoked_at` integer,
	`last_used_at` integer,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "tenant_api_keys_hash_key_version_ck" CHECK("tenant_api_keys"."hash_key_version" >= 1),
	CONSTRAINT "tenant_api_keys_scopes_json_ck" CHECK(json_valid("tenant_api_keys"."scopes_json"))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `tenant_api_keys_prefix_uq` ON `tenant_api_keys` (`prefix`);--> statement-breakpoint
CREATE UNIQUE INDEX `tenant_api_keys_hash_uq` ON `tenant_api_keys` (`key_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `tenant_api_keys_tenant_id_id_uq` ON `tenant_api_keys` (`tenant_id`,`id`);--> statement-breakpoint
CREATE INDEX `tenant_api_keys_tenant_idx` ON `tenant_api_keys` (`tenant_id`,`revoked_at`);--> statement-breakpoint
CREATE TABLE `tenants` (
	`id` text PRIMARY KEY NOT NULL,
	`slug` text NOT NULL,
	`name` text NOT NULL,
	`owner_email` text,
	`controller` text,
	`jurisdiction` text,
	`tier` text DEFAULT 'enterprise' NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`daily_limit` integer DEFAULT 500 NOT NULL,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	CONSTRAINT "tenants_status_ck" CHECK("tenants"."status" IN ('active', 'paused', 'archived')),
	CONSTRAINT "tenants_daily_limit_ck" CHECK("tenants"."daily_limit" BETWEEN 1 AND 10000)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `tenants_slug_uq` ON `tenants` (`slug`);--> statement-breakpoint
CREATE TABLE `unsubscribe_tokens` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`lead_id` text NOT NULL,
	`token_hash` text NOT NULL,
	`expires_at` integer,
	`used_at` integer,
	`revoked_at` integer,
	`created_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`tenant_id`,`lead_id`) REFERENCES `leads`(`tenant_id`,`id`) ON UPDATE no action ON DELETE restrict
);
--> statement-breakpoint
CREATE UNIQUE INDEX `unsubscribe_tokens_hash_uq` ON `unsubscribe_tokens` (`token_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `unsubscribe_tokens_tenant_id_id_uq` ON `unsubscribe_tokens` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `unsubscribe_tokens_lead_identity_uq` ON `unsubscribe_tokens` (`tenant_id`,`id`,`lead_id`);--> statement-breakpoint
CREATE INDEX `unsubscribe_tokens_expiry_idx` ON `unsubscribe_tokens` (`tenant_id`,`expires_at`,`revoked_at`);--> statement-breakpoint
CREATE TABLE `worker_runs` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`run_type` text NOT NULL,
	`bucket_key` text NOT NULL,
	`status` text DEFAULT 'running' NOT NULL,
	`lease_expires_at` integer,
	`stats_json` text DEFAULT '{}' NOT NULL,
	`error_code` text,
	`started_at` integer DEFAULT (unixepoch('subsec') * 1000) NOT NULL,
	`finished_at` integer,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "worker_runs_type_ck" CHECK("worker_runs"."run_type" IN ('dispatch', 'poll_inboxes', 'dns')),
	CONSTRAINT "worker_runs_status_ck" CHECK("worker_runs"."status" IN ('running', 'completed', 'failed')),
	CONSTRAINT "worker_runs_stats_json_ck" CHECK(json_valid("worker_runs"."stats_json"))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `worker_runs_tenant_id_id_uq` ON `worker_runs` (`tenant_id`,`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `worker_runs_bucket_uq` ON `worker_runs` (`tenant_id`,`run_type`,`bucket_key`);--> statement-breakpoint
CREATE TRIGGER `consent_logs_immutable_update`
BEFORE UPDATE ON `consent_logs`
BEGIN
	SELECT RAISE(ABORT, 'consent_logs are immutable');
END;--> statement-breakpoint
CREATE TRIGGER `consent_logs_immutable_delete`
BEFORE DELETE ON `consent_logs`
BEGIN
	SELECT RAISE(ABORT, 'consent_logs are immutable');
END;
