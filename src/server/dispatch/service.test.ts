import type { GatewayTransport } from "@/server/email/gateway";

import type {
  ClaimedDispatchJob,
  DispatchContext,
  DispatchRepository,
} from "./repository";
import {
  createDispatchService,
  deriveStableMessageId,
  deriveUnsubscribeToken,
} from "./service";

const UNSUBSCRIBE_SECRET =
  "test-only-unsubscribe-token-secret-with-enough-entropy";
const SUPPRESSION_HASH_KEY =
  "test-only-suppression-hash-key-with-enough-entropy";

describe("dispatch service", () => {
  it("derives stable delivery identifiers without persisting a raw unsubscribe token", () => {
    const token = deriveUnsubscribeToken(
      "tenant-1",
      "job-1",
      UNSUBSCRIBE_SECRET,
    );

    expect(token).toMatch(/^ouv_unsub_[A-Za-z0-9_-]{43}$/);
    expect(
      deriveUnsubscribeToken("tenant-1", "job-1", UNSUBSCRIBE_SECRET),
    ).toBe(token);
    expect(
      deriveUnsubscribeToken("tenant-1", "job-2", UNSUBSCRIBE_SECRET),
    ).not.toBe(token);
    expect(deriveStableMessageId("tenant-1", "job-1", "example.test")).toBe(
      deriveStableMessageId("tenant-1", "job-1", "example.test"),
    );
    expect(deriveStableMessageId("tenant-1", "job-1", "example.test")).toMatch(
      /^<[a-f0-9]{48}@example\.test>$/,
    );
  });

  it("keeps dry-runs away from transport without consuming or advancing the sequence", async () => {
    const { repository, methods } = fakeRepository({ dryRun: true });
    const transportFactory = vi.fn();
    const service = createDispatchService({
      repository,
      liveSendsEnabled: true,
      transportFactory,
      appBaseUrl: "https://vault.example",
      unsubscribeTokenSecret: UNSUBSCRIBE_SECRET,
      suppressionHashKey: SUPPRESSION_HASH_KEY,
      now: () => 1_000,
      randomInt: () => 300,
      maxBatchSize: 2,
    });

    const summary = await service.runCycle({ limit: 100 });

    expect(summary).toMatchObject({
      claimed: 1,
      dryRun: 1,
      accepted: 0,
      unknown: 0,
    });
    expect(methods.claimNext).toHaveBeenCalledTimes(2);
    expect(transportFactory).not.toHaveBeenCalled();
    const preparation = methods.prepareDelivery.mock.calls[0]?.[0];
    expect(preparation?.dryRun).toBe(true);
    expect(preparation?.dryRunRetryAt).toBe(86_400_000);
    expect(preparation?.renderedSubject).toBe("Hello Ada");
    expect(preparation?.renderedBody).toBe("A note for Analytical Engines");
    expect(preparation?.unsubscribeTokenHash).not.toContain("ouv_unsub_");
  });

  it("uses persisted render material and sends once outside repository transactions", async () => {
    const { repository, methods, context } = fakeRepository({ dryRun: false });
    context.renderedSubject = "Frozen subject";
    context.renderedBody = "Frozen body";
    context.stableMessageId = "<frozen@example.test>";
    const sendMail = vi.fn().mockResolvedValue({
      messageId: "provider-id",
      accepted: ["ada@example.net"],
      rejected: [],
      response: "250 accepted",
    });
    const transportFactory = vi
      .fn<() => Promise<GatewayTransport>>()
      .mockResolvedValue({ sendMail });
    const service = createDispatchService({
      repository,
      liveSendsEnabled: true,
      transportFactory,
      appBaseUrl: "https://vault.example",
      unsubscribeTokenSecret: UNSUBSCRIBE_SECRET,
      suppressionHashKey: SUPPRESSION_HASH_KEY,
      now: () => 1_000,
      randomInt: () => 300,
    });

    const summary = await service.runCycle({ limit: 1 });

    expect(summary.accepted).toBe(1);
    expect(transportFactory).toHaveBeenCalledBefore(
      methods.prepareDelivery as never,
    );
    expect(sendMail).toHaveBeenCalledOnce();
    expect(sendMail).toHaveBeenCalledWith(
      expect.objectContaining({
        subject: "Frozen subject",
        text: expect.stringContaining("Frozen body"),
        messageId: "<frozen@example.test>",
        headers: {
          "List-Unsubscribe": expect.stringMatching(
            /^<https:\/\/vault\.example\/api\/v1\/unsubscribe\?token=ouv_unsub_/,
          ),
          "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        },
      }),
    );
    expect(methods.recordAccepted).toHaveBeenCalledWith(
      expect.objectContaining({
        providerMessageId: "provider-id",
        jitterSeconds: 300,
      }),
    );
  });

  it("retries definitive rejection with backoff but quarantines uncertain delivery", async () => {
    const rejectedFixture = fakeRepository({ dryRun: false });
    const definitive = Object.assign(new Error("Mailbox unavailable"), {
      responseCode: 550,
      code: "EENVELOPE",
    });
    const rejectedService = createDispatchService({
      repository: rejectedFixture.repository,
      liveSendsEnabled: true,
      transportFactory: async () => ({
        sendMail: vi.fn().mockRejectedValue(definitive),
      }),
      appBaseUrl: "https://vault.example",
      unsubscribeTokenSecret: UNSUBSCRIBE_SECRET,
      suppressionHashKey: SUPPRESSION_HASH_KEY,
      now: () => 1_000,
      retryBaseMs: 60_000,
    });

    const rejected = await rejectedService.runCycle({ limit: 1 });
    expect(rejected.rejected).toBe(1);
    expect(rejectedFixture.methods.recordDefinitiveRejection).toHaveBeenCalledWith(
      expect.objectContaining({
        now: 1_000,
        retryAt: 61_000,
        errorCode: "EENVELOPE",
      }),
    );
    expect(rejectedFixture.methods.recordUncertain).not.toHaveBeenCalled();

    const uncertainFixture = fakeRepository({ dryRun: false });
    const uncertainService = createDispatchService({
      repository: uncertainFixture.repository,
      liveSendsEnabled: true,
      transportFactory: async () => ({
        sendMail: vi
          .fn()
          .mockRejectedValue(Object.assign(new Error("reset"), { code: "ECONNRESET" })),
      }),
      appBaseUrl: "https://vault.example",
      unsubscribeTokenSecret: UNSUBSCRIBE_SECRET,
      suppressionHashKey: SUPPRESSION_HASH_KEY,
      now: () => 1_000,
    });

    const uncertain = await uncertainService.runCycle({ limit: 1 });
    expect(uncertain.unknown).toBe(1);
    expect(uncertainFixture.methods.recordUncertain).toHaveBeenCalledWith(
      expect.objectContaining({ errorCode: "ECONNRESET" }),
    );
    expect(
      uncertainFixture.methods.recordDefinitiveRejection,
    ).not.toHaveBeenCalled();
  });

  it("fails closed on preflight database errors and never reaches transport", async () => {
    const { repository, methods } = fakeRepository({ dryRun: false });
    methods.prepareDelivery.mockRejectedValueOnce(new Error("database offline"));
    const sendMail = vi.fn();
    const transportFactory = vi.fn().mockResolvedValue({ sendMail });
    const service = createDispatchService({
      repository,
      liveSendsEnabled: true,
      transportFactory,
      appBaseUrl: "https://vault.example",
      unsubscribeTokenSecret: UNSUBSCRIBE_SECRET,
      suppressionHashKey: SUPPRESSION_HASH_KEY,
      now: () => 1_000,
    });

    const summary = await service.runCycle({ limit: 1 });

    expect(summary.deferred).toBe(1);
    expect(summary.errors).toEqual(["preflight_database_error"]);
    expect(methods.deferClaim).toHaveBeenCalledWith(
      expect.objectContaining({
        code: "preflight_database_error",
        retryAt: expect.any(Number),
      }),
    );
    expect(transportFactory).toHaveBeenCalledOnce();
    expect(sendMail).not.toHaveBeenCalled();
  });

  it("defers outside the tenant campaign window before credentials or transport", async () => {
    const { repository, methods } = fakeRepository({ dryRun: false });
    const transportFactory = vi.fn();
    const service = createDispatchService({
      repository,
      liveSendsEnabled: true,
      transportFactory,
      appBaseUrl: "https://vault.example",
      unsubscribeTokenSecret: UNSUBSCRIBE_SECRET,
      suppressionHashKey: SUPPRESSION_HASH_KEY,
      now: () => 1_000,
      scheduleEvaluator: () => ({ allowed: false, nextAllowedAt: 5_000 }),
    });

    const summary = await service.runCycle({ limit: 1 });

    expect(summary.deferred).toBe(1);
    expect(methods.deferClaim).toHaveBeenCalledWith(
      expect.objectContaining({
        code: "outside_sending_window",
        retryAt: 5_000,
      }),
    );
    expect(methods.prepareDelivery).not.toHaveBeenCalled();
    expect(transportFactory).not.toHaveBeenCalled();
  });

  it("rechecks the campaign window with a fresh clock after live transport setup", async () => {
    const { repository, methods } = fakeRepository({ dryRun: false });
    let clock = 1_000;
    const sendMail = vi.fn();
    const transportFactory = vi.fn().mockImplementation(async () => {
      clock = 2_000;
      return { sendMail };
    });
    const scheduleEvaluator = vi.fn(
      ({ now }: { now: number }) =>
        now < 2_000
          ? { allowed: true as const, nextAllowedAt: null }
          : { allowed: false as const, nextAllowedAt: 5_000 },
    );
    const service = createDispatchService({
      repository,
      liveSendsEnabled: true,
      transportFactory,
      appBaseUrl: "https://vault.example",
      unsubscribeTokenSecret: UNSUBSCRIBE_SECRET,
      suppressionHashKey: SUPPRESSION_HASH_KEY,
      now: () => clock,
      scheduleEvaluator,
    });

    const summary = await service.runCycle({ limit: 1 });

    expect(scheduleEvaluator).toHaveBeenCalledTimes(2);
    expect(methods.deferClaim).toHaveBeenCalledWith({
      claim: expect.any(Object),
      now: 2_000,
      retryAt: 5_000,
      code: "outside_sending_window",
    });
    expect(methods.prepareDelivery).not.toHaveBeenCalled();
    expect(sendMail).not.toHaveBeenCalled();
    expect(summary.deferred).toBe(1);
  });

  it("attempts durable quarantine when SMTP accepted but acceptance persistence fails", async () => {
    const { repository, methods } = fakeRepository({ dryRun: false });
    methods.recordAccepted.mockRejectedValueOnce(new Error("database offline"));
    const service = createDispatchService({
      repository,
      liveSendsEnabled: true,
      transportFactory: async () => ({
        sendMail: vi.fn().mockResolvedValue({
          messageId: "provider-id",
          accepted: ["ada@example.net"],
          rejected: [],
        }),
      }),
      appBaseUrl: "https://vault.example",
      unsubscribeTokenSecret: UNSUBSCRIBE_SECRET,
      suppressionHashKey: SUPPRESSION_HASH_KEY,
      now: () => 1_000,
      randomInt: () => 300,
    });

    const summary = await service.runCycle({ limit: 1 });

    expect(summary.unknown).toBe(1);
    expect(summary.errors).toContain("post_send_persistence_error");
    expect(methods.recordUncertain).toHaveBeenCalledWith(
      expect.objectContaining({
        errorCode: "post_send_persistence_error",
      }),
    );
  });
});

function fakeRepository(options: { dryRun: boolean }) {
  const claim: ClaimedDispatchJob = {
    jobId: "job-1",
    tenantId: "tenant-1",
    leaseToken: "raw-lease-token",
    leaseExpiresAt: 61_000,
  };
  const context: DispatchContext = {
    jobId: "job-1",
    tenantId: "tenant-1",
    enrollmentId: "enrollment-1",
    campaignId: "campaign-1",
    leadId: "lead-1",
    stepId: "step-1",
    inboxId: "inbox-1",
    attemptCount: 0,
    campaignStatus: "active",
    enrollmentStatus: "active",
    leadStatus: "active",
    campaignApprovedAt: 900,
    campaignDryRun: options.dryRun,
    scheduleJson: "{}",
    timezone: "UTC",
    jitterMinSeconds: 180,
    jitterMaxSeconds: 450,
    tenantStatus: "active",
    inboxStatus: "active",
    inboxNextAvailableAt: 0,
    fromAddress: "sender@example.test",
    fromName: "Sender",
    provider: "smtp",
    smtpHost: "smtp.example.test",
    smtpPort: 465,
    smtpSecure: true,
    imapHost: "imap.example.test",
    encryptedCredentials: Buffer.from("encrypted"),
    credentialKeyVersion: 1,
    credentialBinding:
      "oiv-inbox-v1|smtp=smtp.example.test|imap=imap.example.test",
    sendingDomain: "example.test",
    domainStatus: "healthy",
    domainLastDnsCheckAt: 900,
    dkimSelector: null,
    dkimMode: "provider",
    normalizedEmail: "ada@example.net",
    firstName: "Ada",
    lastName: null,
    companyName: "Analytical Engines",
    phoneNumber: null,
    subjectTemplate: "Hello {{first_name}}",
    bodyTemplate: "A note for {{company_name}}",
    stepOrder: 1,
    stepVersion: 1,
    renderedSubject: null,
    renderedBody: null,
    stableMessageId: null,
  };
  const methods = {
    materializeDueEnrollments: vi.fn().mockResolvedValue(0),
    claimNext: vi
      .fn()
      .mockResolvedValueOnce(claim)
      .mockResolvedValueOnce(null),
    loadContext: vi.fn().mockResolvedValue(context),
    prepareDelivery: vi.fn().mockImplementation(async (input) =>
      input.dryRun
        ? { status: "dry_run" as const }
        : { status: "ready" as const, attemptNumber: 1 },
    ),
    recordAccepted: vi.fn().mockResolvedValue(undefined),
    recordDefinitiveRejection: vi.fn().mockResolvedValue(undefined),
    recordUncertain: vi.fn().mockResolvedValue(undefined),
    deferClaim: vi.fn().mockResolvedValue(undefined),
    failClaim: vi.fn().mockResolvedValue(undefined),
  };

  return {
    claim,
    context,
    methods,
    repository: methods as unknown as DispatchRepository,
  };
}
