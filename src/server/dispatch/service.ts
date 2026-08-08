import "server-only";

import { createHash, createHmac, randomInt as cryptoRandomInt } from "node:crypto";

import {
  DeliveryRejectedError,
  DeliveryUncertainError,
  sendViaGateway,
  type GatewayMail,
  type GatewayTransport,
} from "@/server/email/gateway";
import {
  hashSuppressionIdentifier,
  normalizeEmail,
} from "@/server/suppression/service";
import { renderTemplate } from "@/server/templates/render";
import { hashUnsubscribeToken } from "@/server/unsubscribe/tokens";

import {
  DISPATCH_SEND_DEADLINE_MS,
  type ClaimedDispatchJob,
  type DispatchContext,
  type DispatchRepository,
} from "./repository";
import { evaluateCampaignSchedule } from "./schedule";

const DEFAULT_MAX_BATCH_SIZE = 25;
const ABSOLUTE_MAX_BATCH_SIZE = 50;
const DEFAULT_RETRY_BASE_MS = 60_000;
const DEFAULT_MAX_ATTEMPTS = 3;
const MAX_RETRY_MS = 24 * 60 * 60 * 1_000;

export type DispatchSummary = {
  claimed: number;
  accepted: number;
  dryRun: number;
  rejected: number;
  unknown: number;
  blocked: number;
  deferred: number;
  errors: string[];
};

export type DispatchService = {
  runCycle(input?: { limit?: number }): Promise<DispatchSummary>;
};

type TransportFactory = (
  context: DispatchContext,
) => GatewayTransport | Promise<GatewayTransport>;

type Gateway = typeof sendViaGateway;
type Renderer = typeof renderTemplate;
type ScheduleEvaluator = typeof evaluateCampaignSchedule;

function requireSecret(secret: string, label: string): void {
  if (Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error(`${label} must contain at least 32 bytes`);
  }
}

function deterministicId(namespace: string, ...parts: string[]): string {
  return `${namespace}_${createHash("sha256")
    .update(`opt-in-vault:${namespace}:v1\0`)
    .update(parts.join("\0"))
    .digest("hex")
    .slice(0, 40)}`;
}

export function deriveUnsubscribeToken(
  tenantId: string,
  jobId: string,
  secret: string,
): string {
  requireSecret(secret, "Unsubscribe token secret");
  if (!tenantId.trim() || !jobId.trim()) {
    throw new Error("Tenant and job identity are required for unsubscribe tokens");
  }
  const token = createHmac("sha256", secret)
    .update("opt-in-vault:dispatch-unsubscribe:v1\0")
    .update(tenantId)
    .update("\0")
    .update(jobId)
    .digest("base64url");
  return `ouv_unsub_${token}`;
}

export function deriveStableMessageId(
  tenantId: string,
  jobId: string,
  sendingDomain: string,
): string {
  const domain = sendingDomain.trim().toLowerCase();
  if (
    !tenantId.trim() ||
    !jobId.trim() ||
    domain.length > 253 ||
    !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
      domain,
    )
  ) {
    throw new Error("Invalid stable Message-ID input");
  }
  const localPart = createHash("sha256")
    .update("opt-in-vault:message-id:v1\0")
    .update(tenantId)
    .update("\0")
    .update(jobId)
    .digest("hex")
    .slice(0, 48);
  return `<${localPart}@${domain}>`;
}

function validateAppBaseUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("Dispatch application URL is invalid");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error("Dispatch application URL must be a clean HTTPS URL");
  }
  return url.toString().replace(/\/$/, "");
}

function utcDate(timestamp: number): string {
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

function boundedLimit(requested: number | undefined, maximum: number): number {
  if (requested === undefined) return maximum;
  if (!Number.isFinite(requested)) return maximum;
  return Math.max(1, Math.min(maximum, Math.trunc(requested)));
}

function safeTransportCode(error: unknown, fallback: string): string {
  if (!error || typeof error !== "object" || !("code" in error)) {
    return fallback;
  }
  const code = String(error.code);
  return /^[A-Za-z0-9_.-]{1,64}$/.test(code) ? code : fallback;
}

function retryAtFor(
  now: number,
  attemptCount: number,
  retryBaseMs: number,
): number {
  const exponent = Math.max(0, Math.min(attemptCount, 10));
  return now + Math.min(retryBaseMs * 2 ** exponent, MAX_RETRY_MS);
}

function variablesFor(
  context: DispatchContext,
): Readonly<Record<string, string | number | null>> {
  return {
    first_name: context.firstName,
    last_name: context.lastName,
    company: context.companyName,
    company_name: context.companyName,
    email: context.normalizedEmail,
    phone: context.phoneNumber,
  };
}

function jitterFor(
  context: DispatchContext,
  randomInt: (minimum: number, maximumExclusive: number) => number,
): number {
  if (
    !Number.isInteger(context.jitterMinSeconds) ||
    !Number.isInteger(context.jitterMaxSeconds) ||
    context.jitterMinSeconds < 180 ||
    context.jitterMaxSeconds > 450 ||
    context.jitterMinSeconds > context.jitterMaxSeconds
  ) {
    throw new Error("Campaign jitter must stay within 180-450 seconds");
  }
  const value = randomInt(
    context.jitterMinSeconds,
    context.jitterMaxSeconds + 1,
  );
  if (
    !Number.isInteger(value) ||
    value < context.jitterMinSeconds ||
    value > context.jitterMaxSeconds
  ) {
    throw new Error("Jitter source returned an out-of-range value");
  }
  return value;
}

function emptySummary(): DispatchSummary {
  return {
    claimed: 0,
    accepted: 0,
    dryRun: 0,
    rejected: 0,
    unknown: 0,
    blocked: 0,
    deferred: 0,
    errors: [],
  };
}

export function createDispatchService(options: {
  repository: DispatchRepository;
  liveSendsEnabled: boolean;
  transportFactory: TransportFactory;
  appBaseUrl: string;
  unsubscribeTokenSecret: string;
  suppressionHashKey: string;
  now?: () => number;
  randomInt?: (minimum: number, maximumExclusive: number) => number;
  gateway?: Gateway;
  renderer?: Renderer;
  scheduleEvaluator?: ScheduleEvaluator;
  maxBatchSize?: number;
  retryBaseMs?: number;
  maxAttempts?: number;
}): DispatchService {
  const appBaseUrl = validateAppBaseUrl(options.appBaseUrl);
  requireSecret(options.unsubscribeTokenSecret, "Unsubscribe token secret");
  requireSecret(options.suppressionHashKey, "Suppression hash key");
  const now = options.now ?? Date.now;
  const randomInt = options.randomInt ?? cryptoRandomInt;
  const gateway = options.gateway ?? sendViaGateway;
  const renderer = options.renderer ?? renderTemplate;
  const scheduleEvaluator = options.scheduleEvaluator ?? evaluateCampaignSchedule;
  const maxBatchSize = options.maxBatchSize ?? DEFAULT_MAX_BATCH_SIZE;
  const retryBaseMs = options.retryBaseMs ?? DEFAULT_RETRY_BASE_MS;
  const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  if (
    !Number.isInteger(maxBatchSize) ||
    maxBatchSize < 1 ||
    maxBatchSize > ABSOLUTE_MAX_BATCH_SIZE
  ) {
    throw new Error("Dispatch batch size must be between 1 and 50");
  }
  if (!Number.isSafeInteger(retryBaseMs) || retryBaseMs < 1_000) {
    throw new Error("Dispatch retry base must be at least one second");
  }
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 20) {
    throw new Error("Dispatch maximum attempts must be between 1 and 20");
  }

  return {
    async runCycle(input = {}) {
      const summary = emptySummary();
      const limit = boundedLimit(input.limit, maxBatchSize);

      try {
        await options.repository.materializeDueEnrollments(now(), limit);
      } catch {
        summary.errors.push("materialization_database_error");
      }

      for (let index = 0; index < limit; index += 1) {
        const claimTime = now();
        let claim: ClaimedDispatchJob | null;
        try {
          claim = await options.repository.claimNext(claimTime);
        } catch {
          summary.errors.push("claim_database_error");
          break;
        }
        if (!claim) break;
        summary.claimed += 1;

        let context: DispatchContext | null;
        try {
          context = await options.repository.loadContext(claim);
        } catch {
          await deferAfterPreflightFailure(
            options.repository,
            claim,
            claimTime,
            retryBaseMs,
            "context_database_error",
            summary,
          );
          continue;
        }
        if (!context) {
          try {
            await options.repository.failClaim({
              claim,
              now: claimTime,
              code: "dispatch_context_missing",
            });
          } catch {
            summary.errors.push("claim_failure_persistence_error");
          }
          summary.blocked += 1;
          summary.errors.push("dispatch_context_missing");
          continue;
        }

        try {
          const schedule = scheduleEvaluator({
            scheduleJson: context.scheduleJson,
            timeZone: context.timezone,
            now: claimTime,
          });
          if (!schedule.allowed) {
            if (
              schedule.nextAllowedAt === null ||
              schedule.nextAllowedAt <= claimTime
            ) {
              throw new Error("Invalid campaign schedule result");
            }
            await options.repository.deferClaim({
              claim,
              now: claimTime,
              retryAt: schedule.nextAllowedAt,
              code: "outside_sending_window",
            });
            summary.deferred += 1;
            summary.errors.push("outside_sending_window");
            continue;
          }
        } catch {
          try {
            await options.repository.failClaim({
              claim,
              now: claimTime,
              code: "dispatch_schedule_invalid",
            });
          } catch {
            summary.errors.push("claim_failure_persistence_error");
          }
          summary.blocked += 1;
          summary.errors.push("dispatch_schedule_invalid");
          continue;
        }

        let message: GatewayMail;
        let unsubscribeTokenHash: string;
        let suppressionIdentifierHash: string;
        let jitterSeconds: number;
        try {
          const variables = variablesFor(context);
          const renderSeed = `${context.jobId}:v${context.stepVersion}`;
          const renderedSubject =
            context.renderedSubject ??
            renderer(context.subjectTemplate, variables, {
              seed: `${renderSeed}:subject`,
              format: "text",
            });
          const renderedBody =
            context.renderedBody ??
            renderer(context.bodyTemplate, variables, {
              seed: `${renderSeed}:body`,
              format: "text",
            });
          const stableMessageId =
            context.stableMessageId ??
            deriveStableMessageId(
              context.tenantId,
              context.jobId,
              context.sendingDomain,
            );
          const unsubscribeToken = deriveUnsubscribeToken(
            context.tenantId,
            context.jobId,
            options.unsubscribeTokenSecret,
          );
          unsubscribeTokenHash = hashUnsubscribeToken(
            unsubscribeToken,
            options.unsubscribeTokenSecret,
          );
          suppressionIdentifierHash = hashSuppressionIdentifier(
            "email",
            normalizeEmail(context.normalizedEmail),
            options.suppressionHashKey,
          );
          jitterSeconds = jitterFor(context, randomInt);
          message = {
            from: { address: context.fromAddress, name: context.fromName },
            to: context.normalizedEmail,
            subject: renderedSubject,
            text: renderedBody,
            messageId: stableMessageId,
            unsubscribeUrl: `${appBaseUrl}/api/v1/unsubscribe?token=${encodeURIComponent(
              unsubscribeToken,
            )}`,
          };
        } catch {
          try {
            await options.repository.failClaim({
              claim,
              now: claimTime,
              code: "dispatch_material_invalid",
            });
          } catch {
            summary.errors.push("claim_failure_persistence_error");
          }
          summary.blocked += 1;
          summary.errors.push("dispatch_material_invalid");
          continue;
        }

        const liveForCampaign =
          options.liveSendsEnabled && !context.campaignDryRun;
        let transport: GatewayTransport | null = null;
        if (liveForCampaign) {
          try {
            transport = await options.transportFactory(context);
          } catch (error) {
            await deferAfterPreflightFailure(
              options.repository,
              claim,
              now(),
              retryBaseMs,
              safeTransportCode(error, "transport_configuration_error"),
              summary,
            );
            continue;
          }
        }
        const preparationTime = now();
        if (liveForCampaign) {
          try {
            const schedule = scheduleEvaluator({
              scheduleJson: context.scheduleJson,
              timeZone: context.timezone,
              now: preparationTime,
            });
            if (!schedule.allowed) {
              if (
                schedule.nextAllowedAt === null ||
                schedule.nextAllowedAt <= preparationTime
              ) {
                throw new Error("Invalid campaign schedule result");
              }
              await options.repository.deferClaim({
                claim,
                now: preparationTime,
                retryAt: schedule.nextAllowedAt,
                code: "outside_sending_window",
              });
              summary.deferred += 1;
              summary.errors.push("outside_sending_window");
              continue;
            }
          } catch {
            try {
              await options.repository.failClaim({
                claim,
                now: preparationTime,
                code: "dispatch_schedule_invalid",
              });
            } catch {
              summary.errors.push("claim_failure_persistence_error");
            }
            summary.blocked += 1;
            summary.errors.push("dispatch_schedule_invalid");
            continue;
          }
        }
        let preparation;
        try {
          preparation = await options.repository.prepareDelivery({
            claim,
            now: preparationTime,
            usageDate: utcDate(preparationTime),
            jitterSeconds,
            dryRun: !liveForCampaign,
            dryRunRetryAt: nextUtcDay(preparationTime),
            quotaRetryAt: nextUtcDay(preparationTime),
            suppressionIdentifierHash,
            renderedSubject: message.subject,
            renderedBody: message.text,
            stableMessageId: message.messageId,
            unsubscribeTokenId: deterministicId(
              "unsubscribe",
              context.tenantId,
              context.jobId,
            ),
            unsubscribeTokenHash,
            outboundMessageId: deterministicId(
              "outbound",
              context.tenantId,
              context.jobId,
            ),
            attemptId: deterministicId(
              "attempt",
              context.tenantId,
              context.jobId,
              String(context.attemptCount + 1),
            ),
            headersJson: JSON.stringify({
              "List-Unsubscribe": "derived_from_hashed_token",
              "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
            }),
          });
        } catch {
          await deferAfterPreflightFailure(
            options.repository,
            claim,
            preparationTime,
            retryBaseMs,
            "preflight_database_error",
            summary,
          );
          continue;
        }
        if (preparation.status === "blocked") {
          summary.blocked += 1;
          summary.errors.push(preparation.code);
          continue;
        }
        if (preparation.status === "deferred") {
          summary.deferred += 1;
          summary.errors.push(preparation.code);
          continue;
        }
        if (preparation.status === "dry_run") {
          summary.dryRun += 1;
          continue;
        }

        if (!transport) {
          await recordPreTransportRejection(
            options.repository,
            claim,
            context,
            now(),
            retryBaseMs,
            maxAttempts,
            "transport_live_mode_invariant",
            summary,
          );
          continue;
        }

        let deliveryResult;
        try {
          deliveryResult = await gateway(message, {
            liveSendsEnabled: true,
            transport,
            deadlineMs: DISPATCH_SEND_DEADLINE_MS,
          });
        } catch (error) {
          if (error instanceof DeliveryUncertainError) {
            const outcomeTime = now();
            try {
              await options.repository.recordUncertain({
                claim,
                now: outcomeTime,
                errorCode: error.code,
              });
            } catch {
              summary.errors.push("uncertain_persistence_error");
            }
            summary.unknown += 1;
            continue;
          }
          const code =
            error instanceof DeliveryRejectedError
              ? error.code
              : safeTransportCode(error, "message_validation_error");
          await recordPreTransportRejection(
            options.repository,
            claim,
            context,
            now(),
            retryBaseMs,
            maxAttempts,
            code,
            summary,
          );
          continue;
        }

        const completionTime = now();
        try {
          if (deliveryResult.status === "dry_run") {
            throw Object.assign(new Error("Live gateway returned a dry-run result"), {
              code: "gateway_live_mode_violation",
            });
          }
          await options.repository.recordAccepted({
            claim,
            now: completionTime,
            providerMessageId: deliveryResult.providerMessageId,
            jitterSeconds,
          });
          summary.accepted += 1;
        } catch {
          // SMTP may already have accepted the message. Never return it to the
          // retry queue when post-send persistence is uncertain.
          try {
            await options.repository.recordUncertain({
              claim,
              now: completionTime,
              errorCode: "post_send_persistence_error",
            });
          } catch {
            summary.errors.push("uncertain_persistence_error");
          }
          summary.unknown += 1;
          summary.errors.push("post_send_persistence_error");
        }
      }

      return summary;
    },
  };
}

async function deferAfterPreflightFailure(
  repository: DispatchRepository,
  claim: ClaimedDispatchJob,
  now: number,
  retryBaseMs: number,
  code: string,
  summary: DispatchSummary,
): Promise<void> {
  try {
    await repository.deferClaim({
      claim,
      now,
      retryAt: now + retryBaseMs,
      code,
    });
  } catch {
    summary.errors.push("deferral_persistence_error");
  }
  summary.deferred += 1;
  summary.errors.push(code);
}

async function recordPreTransportRejection(
  repository: DispatchRepository,
  claim: ClaimedDispatchJob,
  context: DispatchContext,
  now: number,
  retryBaseMs: number,
  maxAttempts: number,
  code: string,
  summary: DispatchSummary,
): Promise<void> {
  try {
    await repository.recordDefinitiveRejection({
      claim,
      now,
      retryAt: retryAtFor(now, context.attemptCount, retryBaseMs),
      errorCode: code,
      maxAttempts,
    });
  } catch {
    summary.errors.push("rejection_persistence_error");
  }
  summary.rejected += 1;
}
