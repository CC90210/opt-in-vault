import { randomUUID } from "node:crypto";
import { join } from "node:path";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";

import {
  createDispatchRepository,
  DISPATCH_SEND_DEADLINE_MS,
  DNS_FRESHNESS_MS,
  hashDispatchLeaseToken,
  StaleDispatchLeaseError,
} from "./repository";

const LEASE_PEPPER = "test-only-dispatch-lease-pepper-with-32-bytes";

type Fixture = {
  tenantId: string;
  domainId: string;
  inboxId: string;
  campaignId: string;
  leadId: string;
  enrollmentId: string;
  firstStepId: string;
  secondStepId: string;
  jobId: string;
};

describe("dispatch repository", () => {
  let client: Client;

  beforeEach(async () => {
    client = createClient({ url: "file::memory:?cache=shared" });
    await migrate(drizzle(client), {
      migrationsFolder: join(process.cwd(), "drizzle"),
    });
    await client.execute("PRAGMA foreign_keys = ON");
  });

  afterEach(async () => {
    await client.execute(
      "UPDATE send_jobs SET status = 'cancelled' WHERE status IN ('queued', 'leased', 'sending')",
    );
    client.close();
  });

  it("atomically claims due and expired work while storing only a peppered lease hash", async () => {
    const fixture = await seedDispatchFixture(client, { dueAt: 1_000 });
    const expired = await seedDispatchFixture(client, {
      dueAt: 500,
      status: "leased",
      leaseExpiresAt: 999,
    });
    const future = await seedDispatchFixture(client, { dueAt: 5_000 });
    const tokens = ["raw-lease-token-one", "raw-lease-token-two"];
    const repository = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseDurationMs: 60_000,
      leaseTokenFactory: () => tokens.shift() ?? "unexpected-token",
    });

    const first = await repository.claimNext(1_000);
    const second = await repository.claimNext(1_000);
    const none = await repository.claimNext(1_000);

    expect([first?.jobId, second?.jobId]).toEqual(
      expect.arrayContaining([fixture.jobId, expired.jobId]),
    );
    expect(none).toBeNull();
    const rows = await client.execute({
      sql: "SELECT id, status, lease_token_hash FROM send_jobs WHERE id IN (?, ?, ?) ORDER BY id",
      args: [fixture.jobId, expired.jobId, future.jobId],
    });
    for (const claim of [first, second]) {
      expect(claim).not.toBeNull();
      const stored = rows.rows.find((row) => row.id === claim?.jobId);
      expect(stored?.lease_token_hash).toBe(
        hashDispatchLeaseToken(claim!.leaseToken, LEASE_PEPPER),
      );
      expect(stored?.lease_token_hash).not.toBe(claim?.leaseToken);
    }
    expect(rows.rows.find((row) => row.id === future.jobId)?.status).toBe(
      "queued",
    );
  });

  it("refuses expired lease ownership and renews a live lease beyond the send deadline", async () => {
    const fixture = await seedDispatchFixture(client, { dueAt: 1_000 });
    const tokens = ["expiring-lease", "renewed-lease"];
    const repository = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseDurationMs: 1_000,
      leaseTokenFactory: () => tokens.shift() ?? "unexpected-lease",
    });
    const expiredClaim = await repository.claimNext(1_000);

    await expect(
      repository.prepareDelivery(
        deliveryInput(expiredClaim!, fixture, "expired", 2_000),
      ),
    ).rejects.toBeInstanceOf(StaleDispatchLeaseError);
    const untouched = await client.execute({
      sql: `
        SELECT status, attempt_count,
               (SELECT COUNT(*) FROM delivery_attempts WHERE job_id = send_jobs.id) AS attempts,
               (SELECT COUNT(*) FROM inbox_daily_usage WHERE tenant_id = send_jobs.tenant_id) AS usage_rows
        FROM send_jobs WHERE tenant_id = ? AND id = ?
      `,
      args: [fixture.tenantId, fixture.jobId],
    });
    expect(untouched.rows[0]).toMatchObject({
      status: "leased",
      attempt_count: 0,
      attempts: 0,
      usage_rows: 0,
    });

    const liveClaim = await repository.claimNext(2_000);
    expect(liveClaim?.jobId).toBe(fixture.jobId);
    await expect(
      repository.prepareDelivery(
        deliveryInput(liveClaim!, fixture, "renewed", 2_999),
      ),
    ).resolves.toEqual(expect.objectContaining({ status: "ready" }));

    const renewed = await client.execute({
      sql: "SELECT status, lease_expires_at FROM send_jobs WHERE tenant_id = ? AND id = ?",
      args: [fixture.tenantId, fixture.jobId],
    });
    expect(renewed.rows[0]?.status).toBe("sending");
    expect(Number(renewed.rows[0]?.lease_expires_at)).toBeGreaterThan(
      2_999 + DISPATCH_SEND_DEADLINE_MS,
    );
  });

  it("materializes initial work, selects an eligible least-recently-used inbox, and pins the thread", async () => {
    const fixture = await seedDispatchFixture(client, { dueAt: 1_000 });
    const alternateInboxId = `inbox-alternate-${fixture.jobId}`;
    await client.batch(
      [
        {
          sql: "DELETE FROM send_jobs WHERE tenant_id = ? AND id = ?",
          args: [fixture.tenantId, fixture.jobId],
        },
        {
          sql: "UPDATE campaign_enrollments SET status = 'pending', inbox_id = NULL, next_send_at = 1000 WHERE tenant_id = ? AND id = ?",
          args: [fixture.tenantId, fixture.enrollmentId],
        },
        {
          sql: "UPDATE sending_inboxes SET next_available_at = 500, last_used_at = 400 WHERE tenant_id = ? AND id = ?",
          args: [fixture.tenantId, fixture.inboxId],
        },
        {
          sql: "INSERT INTO sending_inboxes (id, tenant_id, domain_id, email_address, display_name, provider, smtp_host, smtp_port, smtp_secure, imap_host, imap_port, imap_secure, encrypted_credentials, credential_key_version, credential_binding, daily_limit, status, next_available_at) VALUES (?, ?, ?, 'alternate@example.test', 'Alternate', 'smtp', 'smtp.example.test', 465, 1, 'imap.example.test', 993, 1, ?, 1, 'oiv-inbox-v1|smtp=smtp.example.test|imap=imap.example.test', 1, 'active', 0)",
          args: [
            alternateInboxId,
            fixture.tenantId,
            fixture.domainId,
            Buffer.from("encrypted"),
          ],
        },
      ],
      "write",
    );
    const repository = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseTokenFactory: () => "allocator-lease",
    });

    await expect(repository.materializeDueEnrollments(1_000, 10)).resolves.toBe(1);
    const claim = await repository.claimNext(1_000);
    const context = await repository.loadContext(claim!);

    expect(context?.inboxId).toBe(alternateInboxId);
    const pinned = await client.execute({
      sql: "SELECT inbox_id, status FROM campaign_enrollments WHERE tenant_id = ? AND id = ?",
      args: [fixture.tenantId, fixture.enrollmentId],
    });
    expect(pinned.rows[0]).toMatchObject({
      inbox_id: alternateInboxId,
      status: "active",
    });
    await expect(repository.materializeDueEnrollments(1_000, 10)).resolves.toBe(0);
  });

  it("distributes overlapping unpinned claims across inbox capacity before quota reservation", async () => {
    const fixture = await seedDispatchFixture(client, { dueAt: 1_000 });
    const alternateInboxId = `zz-inbox-${fixture.jobId}`;
    const extraRows = [2, 3].flatMap((index) => {
      const leadId = `lead-${index}-${fixture.jobId}`;
      const enrollmentId = `enrollment-${index}-${fixture.jobId}`;
      const jobId = `job-${index}-${fixture.jobId}`;
      return [
        {
          sql: "INSERT INTO leads (id, tenant_id, email_address, normalized_email) VALUES (?, ?, ?, ?)",
          args: [
            leadId,
            fixture.tenantId,
            `lead-${index}@example.net`,
            `lead-${index}@example.net`,
          ],
        },
        {
          sql: "INSERT INTO campaign_enrollments (id, tenant_id, campaign_id, lead_id, inbox_id, status, current_step) VALUES (?, ?, ?, ?, NULL, 'active', 1)",
          args: [
            enrollmentId,
            fixture.tenantId,
            fixture.campaignId,
            leadId,
          ],
        },
        {
          sql: "INSERT INTO send_jobs (id, tenant_id, enrollment_id, campaign_id, lead_id, step_id, inbox_id, due_at) VALUES (?, ?, ?, ?, ?, ?, NULL, 1000)",
          args: [
            jobId,
            fixture.tenantId,
            enrollmentId,
            fixture.campaignId,
            leadId,
            fixture.firstStepId,
          ],
        },
      ];
    });
    await client.batch(
      [
        {
          sql: "UPDATE campaign_enrollments SET inbox_id = NULL WHERE tenant_id = ? AND id = ?",
          args: [fixture.tenantId, fixture.enrollmentId],
        },
        {
          sql: "UPDATE send_jobs SET inbox_id = NULL WHERE tenant_id = ? AND id = ?",
          args: [fixture.tenantId, fixture.jobId],
        },
        {
          sql: "INSERT INTO sending_inboxes (id, tenant_id, domain_id, email_address, display_name, provider, smtp_host, smtp_port, smtp_secure, imap_host, imap_port, imap_secure, encrypted_credentials, credential_key_version, credential_binding, daily_limit, status, next_available_at) VALUES (?, ?, ?, 'alternate@example.test', 'Alternate', 'smtp', 'smtp.example.test', 465, 1, 'imap.example.test', 993, 1, ?, 1, 'oiv-inbox-v1|smtp=smtp.example.test|imap=imap.example.test', 1, 'active', 0)",
          args: [
            alternateInboxId,
            fixture.tenantId,
            fixture.domainId,
            Buffer.from("encrypted"),
          ],
        },
        ...extraRows,
      ],
      "write",
    );
    const firstWorker = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseTokenFactory: () => `concurrent-a-${randomUUID()}`,
    });
    const secondWorker = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseTokenFactory: () => `concurrent-b-${randomUUID()}`,
    });

    const claims = [
      await firstWorker.claimNext(1_000),
      await secondWorker.claimNext(1_000),
    ];
    expect(claims.every(Boolean)).toBe(true);
    const contexts = [
      await firstWorker.loadContext(claims[0]!),
      await secondWorker.loadContext(claims[1]!),
    ];
    expect(new Set(contexts.map((context) => context?.inboxId))).toEqual(
      new Set([fixture.inboxId, alternateInboxId]),
    );
    await expect(firstWorker.claimNext(1_000)).resolves.toBeNull();

    const pending = await client.execute({
      sql: `
        SELECT inbox_id, COUNT(*) AS claims
        FROM send_jobs
        WHERE tenant_id = ? AND status = 'leased'
        GROUP BY inbox_id ORDER BY inbox_id
      `,
      args: [fixture.tenantId],
    });
    expect(pending.rows).toEqual([
      expect.objectContaining({ inbox_id: fixture.inboxId, claims: 1 }),
      expect.objectContaining({ inbox_id: alternateInboxId, claims: 1 }),
    ]);
    const usage = await client.execute({
      sql: "SELECT COUNT(*) AS count FROM inbox_daily_usage WHERE tenant_id = ?",
      args: [fixture.tenantId],
    });
    expect(usage.rows[0]?.count).toBe(0);
  });

  it("rechecks gates and reserves quota in the same transaction that persists immutable send material", async () => {
    const fixture = await seedDispatchFixture(client, { dueAt: 1_000 });
    const repository = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseTokenFactory: () => "raw-lease-token",
    });
    const claim = await repository.claimNext(1_000);
    expect(claim).not.toBeNull();

    const context = await repository.loadContext(claim!);
    expect(context).toMatchObject({
      tenantId: fixture.tenantId,
      campaignStatus: "active",
      campaignApprovedAt: 900,
      inboxStatus: "active",
      domainStatus: "healthy",
      normalizedEmail: "ada@example.net",
    });

    const prepared = await repository.prepareDelivery({
      claim: claim!,
      now: 1_000,
      usageDate: "1970-01-01",
      jitterSeconds: 300,
      suppressionIdentifierHash: "not-suppressed",
      renderedSubject: "Hello Ada",
      renderedBody: "Useful body",
      stableMessageId: "<stable-message@example.test>",
      unsubscribeTokenId: `unsubscribe-${fixture.jobId}`,
      unsubscribeTokenHash: "stored-unsubscribe-hash",
      outboundMessageId: `outbound-${fixture.jobId}`,
      attemptId: `attempt-${fixture.jobId}-1`,
    });

    expect(prepared).toEqual(
      expect.objectContaining({ status: "ready", attemptNumber: 1 }),
    );
    const state = await client.execute({
      sql: `
        SELECT
          job.status,
          job.rendered_subject,
          job.rendered_body,
          job.stable_message_id,
          token.token_hash,
          usage.reserved_count,
          usage.sent_count,
          attempt.status AS attempt_status,
          message.status AS message_status
        FROM send_jobs AS job
        JOIN unsubscribe_tokens AS token
          ON token.tenant_id = job.tenant_id AND token.id = job.unsubscribe_token_id
        JOIN inbox_daily_usage AS usage
          ON usage.tenant_id = job.tenant_id AND usage.inbox_id = job.inbox_id
        JOIN delivery_attempts AS attempt
          ON attempt.tenant_id = job.tenant_id AND attempt.job_id = job.id
        JOIN outbound_messages AS message
          ON message.tenant_id = job.tenant_id AND message.job_id = job.id
        WHERE job.id = ?
      `,
      args: [fixture.jobId],
    });
    expect(state.rows[0]).toMatchObject({
      status: "sending",
      rendered_subject: "Hello Ada",
      rendered_body: "Useful body",
      stable_message_id: "<stable-message@example.test>",
      token_hash: "stored-unsubscribe-hash",
      reserved_count: 1,
      sent_count: 0,
      attempt_status: "sending",
      message_status: "prepared",
    });
    const pacing = await client.execute({
      sql: "SELECT next_available_at FROM sending_inboxes WHERE tenant_id = ? AND id = ?",
      args: [fixture.tenantId, fixture.inboxId],
    });
    expect(pacing.rows[0]?.next_available_at).toBe(301_000);

    const parallelLeadId = `lead-parallel-${fixture.jobId}`;
    const parallelEnrollmentId = `enrollment-parallel-${fixture.jobId}`;
    const parallelJobId = `job-parallel-${fixture.jobId}`;
    await client.batch(
      [
        {
          sql: "INSERT INTO leads (id, tenant_id, email_address, normalized_email) VALUES (?, ?, 'parallel@example.net', 'parallel@example.net')",
          args: [parallelLeadId, fixture.tenantId],
        },
        {
          sql: "INSERT INTO campaign_enrollments (id, tenant_id, campaign_id, lead_id, inbox_id, status, current_step) VALUES (?, ?, ?, ?, ?, 'active', 1)",
          args: [
            parallelEnrollmentId,
            fixture.tenantId,
            fixture.campaignId,
            parallelLeadId,
            fixture.inboxId,
          ],
        },
        {
          sql: "INSERT INTO send_jobs (id, tenant_id, enrollment_id, campaign_id, lead_id, step_id, inbox_id, due_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1000)",
          args: [
            parallelJobId,
            fixture.tenantId,
            parallelEnrollmentId,
            fixture.campaignId,
            parallelLeadId,
            fixture.firstStepId,
            fixture.inboxId,
          ],
        },
      ],
      "write",
    );
    const parallelClaim = await repository.claimNext(1_000);
    const parallelResult = await repository.prepareDelivery({
      claim: parallelClaim!,
      now: 1_000,
      usageDate: "1970-01-01",
      jitterSeconds: 300,
      suppressionIdentifierHash: "parallel-clear",
      renderedSubject: "Parallel subject",
      renderedBody: "Parallel body",
      stableMessageId: "<parallel@example.test>",
      unsubscribeTokenId: `unsubscribe-${parallelJobId}`,
      unsubscribeTokenHash: "parallel-token-hash",
      outboundMessageId: `outbound-${parallelJobId}`,
      attemptId: `attempt-${parallelJobId}`,
    });
    expect(parallelResult).toEqual({
      status: "deferred",
      code: "inbox_not_available",
    });
  });

  it("persists a dry-run preview without quota, attempts, or sequence advancement", async () => {
    const fixture = await seedDispatchFixture(client, { dueAt: 1_000 });
    const repository = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseTokenFactory: () => "raw-dry-run-lease",
    });
    const claim = await repository.claimNext(1_000);
    const preview = await repository.prepareDelivery({
      claim: claim!,
      now: 1_000,
      usageDate: "1970-01-01",
      jitterSeconds: 300,
      dryRun: true,
      dryRunRetryAt: 86_400_000,
      suppressionIdentifierHash: "clear-preview",
      renderedSubject: "Preview subject",
      renderedBody: "Preview body",
      stableMessageId: "<preview@example.test>",
      unsubscribeTokenId: `unsubscribe-${fixture.jobId}`,
      unsubscribeTokenHash: "preview-token-hash",
      outboundMessageId: `outbound-${fixture.jobId}`,
      attemptId: `attempt-${fixture.jobId}`,
    });

    expect(preview).toEqual({ status: "dry_run" });
    const state = await client.execute({
      sql: `
        SELECT job.status, job.due_at, job.attempt_count, job.lease_token_hash,
               job.rendered_subject, enrollment.current_step, enrollment.next_send_at,
               message.status AS message_status,
               (SELECT COUNT(*) FROM delivery_attempts WHERE job_id = job.id) AS attempts,
               (SELECT COUNT(*) FROM inbox_daily_usage WHERE tenant_id = job.tenant_id) AS usage_rows
        FROM send_jobs AS job
        JOIN campaign_enrollments AS enrollment
          ON enrollment.tenant_id = job.tenant_id AND enrollment.id = job.enrollment_id
        JOIN outbound_messages AS message
          ON message.tenant_id = job.tenant_id AND message.job_id = job.id
        WHERE job.id = ?
      `,
      args: [fixture.jobId],
    });
    expect(state.rows[0]).toMatchObject({
      status: "queued",
      due_at: 86_400_000,
      attempt_count: 0,
      lease_token_hash: null,
      rendered_subject: "Preview subject",
      current_step: 1,
      next_send_at: null,
      message_status: "prepared",
      attempts: 0,
      usage_rows: 0,
    });
    await expect(repository.claimNext(86_399_999)).resolves.toBeNull();
  });

  it("fails closed for suppression and exhausted inbox or tenant capacity", async () => {
    const suppressed = await seedDispatchFixture(client, { dueAt: 1_000 });
    await client.execute({
      sql: "INSERT INTO suppressions (id, tenant_id, identifier_type, identifier_hash, reason) VALUES (?, ?, 'email', 'suppressed-hash', 'manual')",
      args: [`suppression-${suppressed.jobId}`, suppressed.tenantId],
    });
    const repository = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseTokenFactory: () => "raw-lease-token",
    });
    const suppressedClaim = await repository.claimNext(1_000);
    const suppressedResult = await repository.prepareDelivery({
      claim: suppressedClaim!,
      now: 1_000,
      usageDate: "1970-01-01",
      jitterSeconds: 300,
      suppressionIdentifierHash: "suppressed-hash",
      renderedSubject: "Subject",
      renderedBody: "Body",
      stableMessageId: "<suppressed@example.test>",
      unsubscribeTokenId: `unsubscribe-${suppressed.jobId}`,
      unsubscribeTokenHash: "unsubscribe-hash",
      outboundMessageId: `outbound-${suppressed.jobId}`,
      attemptId: `attempt-${suppressed.jobId}`,
    });
    expect(suppressedResult).toEqual({
      status: "blocked",
      code: "suppressed",
    });

    const capped = await seedDispatchFixture(client, { dueAt: 1_000 });
    await client.execute({
      sql: "UPDATE sending_inboxes SET daily_limit = 1 WHERE tenant_id = ? AND id = ?",
      args: [capped.tenantId, capped.inboxId],
    });
    await client.execute({
      sql: "INSERT INTO inbox_daily_usage (tenant_id, inbox_id, usage_date, reserved_count, sent_count) VALUES (?, ?, '1970-01-01', 0, 1)",
      args: [capped.tenantId, capped.inboxId],
    });
    const cappedClaim = await repository.claimNext(1_000);
    const cappedResult = await repository.prepareDelivery({
      claim: cappedClaim!,
      now: 1_000,
      usageDate: "1970-01-01",
      jitterSeconds: 300,
      suppressionIdentifierHash: "clear-hash",
      renderedSubject: "Subject",
      renderedBody: "Body",
      stableMessageId: "<capped@example.test>",
      unsubscribeTokenId: `unsubscribe-${capped.jobId}`,
      unsubscribeTokenHash: "unsubscribe-hash-2",
      outboundMessageId: `outbound-${capped.jobId}`,
      attemptId: `attempt-${capped.jobId}`,
    });
    expect(cappedResult).toEqual({
      status: "deferred",
      code: "daily_quota_exhausted",
    });
  });

  it("defers reversible campaign and domain gates instead of destroying queued work", async () => {
    const fixture = await seedDispatchFixture(client, { dueAt: 1_000 });
    await client.execute({
      sql: "UPDATE campaigns SET status = 'paused' WHERE tenant_id = ? AND id = ?",
      args: [fixture.tenantId, fixture.campaignId],
    });
    const repository = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseTokenFactory: () => "paused-campaign-lease",
    });
    const claim = await repository.claimNext(1_000);
    const result = await repository.prepareDelivery({
      claim: claim!,
      now: 1_000,
      usageDate: "1970-01-01",
      jitterSeconds: 300,
      suppressionIdentifierHash: "clear-paused",
      renderedSubject: "Subject",
      renderedBody: "Body",
      stableMessageId: "<paused@example.test>",
      unsubscribeTokenId: `unsubscribe-${fixture.jobId}`,
      unsubscribeTokenHash: "paused-token-hash",
      outboundMessageId: `outbound-${fixture.jobId}`,
      attemptId: `attempt-${fixture.jobId}`,
    });

    expect(result).toEqual({ status: "deferred", code: "campaign_inactive" });
    const job = await client.execute({
      sql: "SELECT status, due_at, last_error_code FROM send_jobs WHERE tenant_id = ? AND id = ?",
      args: [fixture.tenantId, fixture.jobId],
    });
    expect(job.rows[0]).toMatchObject({
      status: "queued",
      due_at: 301_000,
      last_error_code: "campaign_inactive",
    });
  });

  it("allows a technically send-ready degraded domain while retaining its warning state", async () => {
    const fixture = await seedDispatchFixture(client, {
      dueAt: 1_000,
      domainStatus: "degraded",
    });
    const repository = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseTokenFactory: () => "degraded-domain-lease",
    });

    const claim = await repository.claimNext(1_000);
    expect(claim).not.toBeNull();
    const result = await repository.prepareDelivery({
      claim: claim!,
      now: 1_000,
      usageDate: "1970-01-01",
      jitterSeconds: 300,
      suppressionIdentifierHash: "clear-degraded",
      renderedSubject: "Subject",
      renderedBody: "Body",
      stableMessageId: "<degraded@example.test>",
      unsubscribeTokenId: `unsubscribe-${fixture.jobId}`,
      unsubscribeTokenHash: "degraded-token-hash",
      outboundMessageId: `outbound-${fixture.jobId}`,
      attemptId: `attempt-${fixture.jobId}`,
    });

    expect(result).toEqual(expect.objectContaining({ status: "ready" }));
  });

  it.each([
    { label: "missing", lastDnsCheckAt: null, code: "domain_dns_stale" },
    { label: "stale", lastDnsCheckAt: 999, code: "domain_dns_stale" },
    {
      label: "future-dated",
      lastDnsCheckAt: DNS_FRESHNESS_MS + 1_001,
      code: "domain_dns_invalid",
    },
  ])(
    "defers delivery when DNS evidence is $label",
    async ({ label, lastDnsCheckAt, code }) => {
      const now = DNS_FRESHNESS_MS + 1_000;
      const fixture = await seedDispatchFixture(client, { dueAt: 1_000 });
      await client.execute({
        sql: "UPDATE sending_domains SET last_dns_check_at = ? WHERE tenant_id = ? AND id = ?",
        args: [lastDnsCheckAt, fixture.tenantId, fixture.domainId],
      });
      const repository = createDispatchRepository(client, {
        leasePepper: LEASE_PEPPER,
        leaseTokenFactory: () => `dns-${label}-lease`,
      });
      const claim = await repository.claimNext(now);

      await expect(
        repository.prepareDelivery({
          ...deliveryInput(claim!, fixture, `dns-${label}`, now),
          usageDate: "1970-01-02",
        }),
      ).resolves.toEqual({ status: "deferred", code });
      const job = await client.execute({
        sql: "SELECT status, due_at, last_error_code FROM send_jobs WHERE tenant_id = ? AND id = ?",
        args: [fixture.tenantId, fixture.jobId],
      });
      expect(job.rows[0]).toMatchObject({
        status: "queued",
        due_at: now + 5 * 60_000,
        last_error_code: code,
      });
    },
  );

  it("advances accepted work with persisted bounded jitter and quarantines uncertain outcomes", async () => {
    const accepted = await seedDispatchFixture(client, { dueAt: 1_000 });
    const repository = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseTokenFactory: () => `lease-${randomUUID()}`,
    });
    const acceptedClaim = await repository.claimNext(1_000);
    await prepareFixture(repository, acceptedClaim!, accepted, "accepted");
    await repository.recordAccepted({
      claim: acceptedClaim!,
      now: 2_000,
      providerMessageId: "provider-message",
      jitterSeconds: 300,
    });

    const acceptedState = await client.execute({
      sql: `
        SELECT job.status, enrollment.current_step, enrollment.next_send_at,
               usage.reserved_count, usage.sent_count, inbox.next_available_at,
               next_job.status AS next_status, next_job.due_at AS next_due_at
        FROM send_jobs AS job
        JOIN campaign_enrollments AS enrollment
          ON enrollment.tenant_id = job.tenant_id AND enrollment.id = job.enrollment_id
        JOIN inbox_daily_usage AS usage
          ON usage.tenant_id = job.tenant_id AND usage.inbox_id = job.inbox_id
        JOIN sending_inboxes AS inbox
          ON inbox.tenant_id = job.tenant_id AND inbox.id = job.inbox_id
        LEFT JOIN send_jobs AS next_job
          ON next_job.tenant_id = job.tenant_id
         AND next_job.enrollment_id = job.enrollment_id
         AND next_job.step_id = ?
        WHERE job.id = ?
      `,
      args: [accepted.secondStepId, accepted.jobId],
    });
    const expectedDueAt = 2_000 + 86_400_000 + 300_000;
    expect(acceptedState.rows[0]).toMatchObject({
      status: "sent",
      current_step: 2,
      next_send_at: expectedDueAt,
      reserved_count: 0,
      sent_count: 1,
      next_available_at: 302_000,
      next_status: "queued",
      next_due_at: expectedDueAt,
    });

    const uncertain = await seedDispatchFixture(client, { dueAt: 1_000 });
    const uncertainClaim = await repository.claimNext(1_000);
    await prepareFixture(repository, uncertainClaim!, uncertain, "uncertain");
    await repository.recordUncertain({
      claim: uncertainClaim!,
      now: 2_000,
      errorCode: "ECONNRESET",
    });
    const uncertainState = await client.execute({
      sql: "SELECT status, lease_token_hash, lease_expires_at FROM send_jobs WHERE id = ?",
      args: [uncertain.jobId],
    });
    expect(uncertainState.rows[0]).toMatchObject({
      status: "unknown",
      lease_token_hash: null,
      lease_expires_at: null,
    });
    const uncertainJobs = await client.execute({
      sql: "SELECT status FROM send_jobs WHERE tenant_id = ? AND enrollment_id = ?",
      args: [uncertain.tenantId, uncertain.enrollmentId],
    });
    expect(uncertainJobs.rows).toEqual([
      expect.objectContaining({ status: "unknown" }),
    ]);
  });

  it("quarantines expired sending leases as unknown instead of ever resending them", async () => {
    const fixture = await seedDispatchFixture(client, { dueAt: 1_000 });
    const repository = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseDurationMs: 1_000,
      leaseTokenFactory: () => "crashed-worker-lease",
    });
    const claim = await repository.claimNext(1_000);
    await prepareFixture(repository, claim!, fixture, "crashed");

    const lease = await client.execute({
      sql: "SELECT lease_expires_at FROM send_jobs WHERE tenant_id = ? AND id = ?",
      args: [fixture.tenantId, fixture.jobId],
    });
    const leaseExpiresAt = Number(lease.rows[0]?.lease_expires_at);

    await expect(repository.claimNext(leaseExpiresAt)).resolves.toBeNull();

    const state = await client.execute({
      sql: `
        SELECT job.status, job.lease_token_hash, attempt.status AS attempt_status,
               message.status AS message_status, usage.reserved_count, usage.sent_count
        FROM send_jobs AS job
        JOIN delivery_attempts AS attempt
          ON attempt.tenant_id = job.tenant_id AND attempt.job_id = job.id
        JOIN outbound_messages AS message
          ON message.tenant_id = job.tenant_id AND message.job_id = job.id
        JOIN inbox_daily_usage AS usage
          ON usage.tenant_id = job.tenant_id AND usage.inbox_id = job.inbox_id
        WHERE job.id = ?
      `,
      args: [fixture.jobId],
    });
    expect(state.rows[0]).toMatchObject({
      status: "unknown",
      lease_token_hash: null,
      attempt_status: "unknown",
      message_status: "unknown",
      reserved_count: 0,
      sent_count: 1,
    });
  });

  it("quarantines a bounded batch of expired sending leases before claiming new work", async () => {
    const crashedA = await seedDispatchFixture(client, { dueAt: 1_000 });
    const crashedB = await seedDispatchFixture(client, { dueAt: 1_000 });
    const due = await seedDispatchFixture(client, { dueAt: 2_000 });
    const fixtures = new Map(
      [crashedA, crashedB].map((fixture) => [fixture.jobId, fixture]),
    );
    const repository = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseDurationMs: 1_000,
      leaseTokenFactory: () => `sweep-${randomUUID()}`,
    });
    const claims = [
      await repository.claimNext(1_000),
      await repository.claimNext(1_000),
    ];
    for (const [index, claim] of claims.entries()) {
      expect(claim).not.toBeNull();
      await prepareFixture(
        repository,
        claim!,
        fixtures.get(claim!.jobId)!,
        `sweep-${index}`,
      );
    }
    await client.execute({
      sql: "UPDATE send_jobs SET lease_expires_at = ? WHERE id IN (?, ?)",
      args: [1_999, claims[0]!.jobId, claims[1]!.jobId],
    });

    await expect(repository.claimNext(2_000)).resolves.toEqual(
      expect.objectContaining({ jobId: due.jobId }),
    );
    const repaired = await client.execute({
      sql: `
        SELECT job.status, attempt.status AS attempt_status,
               message.status AS message_status, usage.reserved_count,
               usage.sent_count
        FROM send_jobs AS job
        JOIN delivery_attempts AS attempt
          ON attempt.tenant_id = job.tenant_id AND attempt.job_id = job.id
        JOIN outbound_messages AS message
          ON message.tenant_id = job.tenant_id AND message.job_id = job.id
        JOIN inbox_daily_usage AS usage
          ON usage.tenant_id = job.tenant_id AND usage.inbox_id = job.inbox_id
        WHERE job.id IN (?, ?)
        ORDER BY job.id
      `,
      args: [claims[0]!.jobId, claims[1]!.jobId],
    });
    expect(repaired.rows).toHaveLength(2);
    for (const row of repaired.rows) {
      expect(row).toMatchObject({
        status: "unknown",
        attempt_status: "unknown",
        message_status: "unknown",
        reserved_count: 0,
        sent_count: 1,
      });
    }
  });

  it("releases quota and applies durable backoff after a definitive rejection", async () => {
    const fixture = await seedDispatchFixture(client, { dueAt: 1_000 });
    const repository = createDispatchRepository(client, {
      leasePepper: LEASE_PEPPER,
      leaseTokenFactory: () => `lease-${randomUUID()}`,
    });
    const claim = await repository.claimNext(1_000);
    await prepareFixture(repository, claim!, fixture, "rejected");
    await repository.recordDefinitiveRejection({
      claim: claim!,
      now: 2_000,
      retryAt: 62_000,
      errorCode: "mailbox_unavailable",
      maxAttempts: 3,
    });

    const state = await client.execute({
      sql: `
        SELECT job.status, job.due_at, job.last_error_code,
               usage.reserved_count, usage.sent_count,
               attempt.status AS attempt_status,
               message.status AS message_status
        FROM send_jobs AS job
        JOIN inbox_daily_usage AS usage
          ON usage.tenant_id = job.tenant_id AND usage.inbox_id = job.inbox_id
        JOIN delivery_attempts AS attempt
          ON attempt.tenant_id = job.tenant_id AND attempt.job_id = job.id
        JOIN outbound_messages AS message
          ON message.tenant_id = job.tenant_id AND message.job_id = job.id
        WHERE job.id = ?
      `,
      args: [fixture.jobId],
    });
    expect(state.rows[0]).toMatchObject({
      status: "queued",
      due_at: 62_000,
      last_error_code: "mailbox_unavailable",
      reserved_count: 0,
      sent_count: 0,
      attempt_status: "rejected",
      message_status: "rejected",
    });
    await expect(repository.claimNext(61_999)).resolves.toBeNull();
    await expect(repository.claimNext(62_000)).resolves.toEqual(
      expect.objectContaining({ jobId: fixture.jobId }),
    );
  });
});

async function seedDispatchFixture(
  client: Client,
  options: {
    dueAt: number;
    status?: "queued" | "leased";
    leaseExpiresAt?: number;
    dryRun?: boolean;
    domainStatus?: "healthy" | "degraded";
  },
): Promise<Fixture> {
  const suffix = randomUUID();
  const fixture: Fixture = {
    tenantId: `tenant-${suffix}`,
    domainId: `domain-${suffix}`,
    inboxId: `inbox-${suffix}`,
    campaignId: `campaign-${suffix}`,
    leadId: `lead-${suffix}`,
    enrollmentId: `enrollment-${suffix}`,
    firstStepId: `step-1-${suffix}`,
    secondStepId: `step-2-${suffix}`,
    jobId: `job-${suffix}`,
  };
  await client.batch(
    [
      {
        sql: "INSERT INTO tenants (id, slug, name, daily_limit) VALUES (?, ?, 'Tenant', 2)",
        args: [fixture.tenantId, fixture.tenantId],
      },
      {
        sql: "INSERT INTO sending_domains (id, tenant_id, domain, status, last_dns_check_at) VALUES (?, ?, 'example.test', ?, 900)",
        args: [
          fixture.domainId,
          fixture.tenantId,
          options.domainStatus ?? "healthy",
        ],
      },
      {
        sql: "INSERT INTO sending_inboxes (id, tenant_id, domain_id, email_address, display_name, provider, smtp_host, smtp_port, smtp_secure, imap_host, imap_port, imap_secure, encrypted_credentials, credential_key_version, credential_binding, daily_limit, status, next_available_at) VALUES (?, ?, ?, 'sender@example.test', 'Sender', 'smtp', 'smtp.example.test', 465, 1, 'imap.example.test', 993, 1, ?, 1, 'oiv-inbox-v1|smtp=smtp.example.test|imap=imap.example.test', 1, 'active', 0)",
        args: [
          fixture.inboxId,
          fixture.tenantId,
          fixture.domainId,
          Buffer.from("encrypted"),
        ],
      },
      {
        sql: "INSERT INTO campaigns (id, tenant_id, name, status, dry_run, approved_at, jitter_min_seconds, jitter_max_seconds) VALUES (?, ?, 'Campaign', 'active', ?, 900, 180, 450)",
        args: [fixture.campaignId, fixture.tenantId, options.dryRun === false ? 0 : 1],
      },
      {
        sql: "INSERT INTO sequence_steps (id, tenant_id, campaign_id, step_order, delay_days, subject_template, body_template) VALUES (?, ?, ?, 1, 0, 'Hello {{first_name}}', 'Body for {{company_name}}')",
        args: [fixture.firstStepId, fixture.tenantId, fixture.campaignId],
      },
      {
        sql: "INSERT INTO sequence_steps (id, tenant_id, campaign_id, step_order, delay_days, subject_template, body_template) VALUES (?, ?, ?, 2, 1, 'Follow up', 'Second body')",
        args: [fixture.secondStepId, fixture.tenantId, fixture.campaignId],
      },
      {
        sql: "INSERT INTO leads (id, tenant_id, email_address, normalized_email, first_name, company_name) VALUES (?, ?, 'ada@example.net', 'ada@example.net', 'Ada', 'Analytical Engines')",
        args: [fixture.leadId, fixture.tenantId],
      },
      {
        sql: "INSERT INTO campaign_enrollments (id, tenant_id, campaign_id, lead_id, inbox_id, status, current_step) VALUES (?, ?, ?, ?, ?, 'active', 1)",
        args: [
          fixture.enrollmentId,
          fixture.tenantId,
          fixture.campaignId,
          fixture.leadId,
          fixture.inboxId,
        ],
      },
      {
        sql: "INSERT INTO send_jobs (id, tenant_id, enrollment_id, campaign_id, lead_id, step_id, inbox_id, status, due_at, lease_token_hash, lease_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        args: [
          fixture.jobId,
          fixture.tenantId,
          fixture.enrollmentId,
          fixture.campaignId,
          fixture.leadId,
          fixture.firstStepId,
          fixture.inboxId,
          options.status ?? "queued",
          options.dueAt,
          options.status === "leased" ? "old-hash" : null,
          options.leaseExpiresAt ?? null,
        ],
      },
    ],
    "write",
  );
  return fixture;
}

async function prepareFixture(
  repository: ReturnType<typeof createDispatchRepository>,
  claim: NonNullable<Awaited<ReturnType<ReturnType<typeof createDispatchRepository>["claimNext"]>>>,
  fixture: Fixture,
  suffix: string,
) {
  const result = await repository.prepareDelivery({
    claim,
    now: 1_000,
    usageDate: "1970-01-01",
    jitterSeconds: 300,
    suppressionIdentifierHash: `clear-${suffix}`,
    renderedSubject: "Rendered subject",
    renderedBody: "Rendered body",
    stableMessageId: `<${suffix}@example.test>`,
    unsubscribeTokenId: `unsubscribe-${fixture.jobId}`,
    unsubscribeTokenHash: `unsubscribe-hash-${suffix}`,
    outboundMessageId: `outbound-${fixture.jobId}`,
    attemptId: `attempt-${fixture.jobId}`,
  });
  expect(result.status).toBe("ready");
}

function deliveryInput(
  claim: NonNullable<Awaited<ReturnType<ReturnType<typeof createDispatchRepository>["claimNext"]>>>,
  fixture: Fixture,
  suffix: string,
  now: number,
) {
  return {
    claim,
    now,
    usageDate: "1970-01-01",
    jitterSeconds: 300,
    suppressionIdentifierHash: `clear-${suffix}`,
    renderedSubject: "Rendered subject",
    renderedBody: "Rendered body",
    stableMessageId: `<${suffix}@example.test>`,
    unsubscribeTokenId: `unsubscribe-${fixture.jobId}`,
    unsubscribeTokenHash: `unsubscribe-hash-${suffix}`,
    outboundMessageId: `outbound-${fixture.jobId}`,
    attemptId: `attempt-${fixture.jobId}-${suffix}`,
  };
}
