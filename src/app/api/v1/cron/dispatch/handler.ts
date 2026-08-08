import "server-only";

import { isCronAuthorized } from "@/server/auth/cron";
import type { DispatchSummary } from "@/server/dispatch/service";

const DEFAULT_BATCH_SIZE = 25;
const ABSOLUTE_MAX_BATCH_SIZE = 50;
const RESPONSE_HEADERS = {
  "cache-control": "no-store",
  "content-type": "application/json; charset=utf-8",
  "x-content-type-options": "nosniff",
};

type CycleRunner = (input: { limit: number }) => Promise<DispatchSummary>;

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: RESPONSE_HEADERS,
  });
}

function requestedLimit(request: Request, maximum: number): number {
  const raw = new URL(request.url).searchParams.get("limit");
  if (!raw || !/^\d{1,3}$/.test(raw)) return maximum;
  return Math.max(1, Math.min(maximum, Number(raw)));
}

export function createDispatchHandler(options: {
  configuredSecret: () => string | undefined;
  runCycle: CycleRunner;
  maxBatchSize?: number;
}) {
  const maxBatchSize = options.maxBatchSize ?? DEFAULT_BATCH_SIZE;
  if (
    !Number.isInteger(maxBatchSize) ||
    maxBatchSize < 1 ||
    maxBatchSize > ABSOLUTE_MAX_BATCH_SIZE
  ) {
    throw new Error("Dispatch route batch size must be between 1 and 50");
  }

  return async function dispatch(request: Request): Promise<Response> {
    if (
      !isCronAuthorized(
        request.headers.get("authorization"),
        options.configuredSecret(),
      )
    ) {
      return json({ error: "unauthorized" }, 401);
    }

    try {
      const summary = await options.runCycle({
        limit: requestedLimit(request, maxBatchSize),
      });
      return json(summary, 200);
    } catch (error) {
      const errorName = error instanceof Error ? error.name : "UnknownError";
      console.error("Dispatch cycle failed", errorName);
      return json({ error: "dispatch_unavailable" }, 503);
    }
  };
}

export const createDispatchRoute = createDispatchHandler;

async function runProductionCycle(input: {
  limit: number;
}): Promise<DispatchSummary> {
  const leasePepper = process.env.DISPATCH_LEASE_PEPPER;
  const unsubscribeTokenSecret = process.env.UNSUBSCRIBE_TOKEN_SECRET;
  const suppressionHashKey = process.env.SUPPRESSION_HASH_KEY;
  const appBaseUrl = process.env.NEXT_PUBLIC_APP_URL;
  if (
    !leasePepper ||
    !unsubscribeTokenSecret ||
    !suppressionHashKey ||
    !appBaseUrl
  ) {
    throw new Error("Dispatch runtime configuration is incomplete");
  }

  const [
    { getDatabase },
    { createDispatchRepository },
    { createDispatchService },
    { createConfiguredGatewayTransport },
    { parseCredentialEncryptionKeyRing },
  ] =
    await Promise.all([
      import("@/db/client"),
      import("@/server/dispatch/repository"),
      import("@/server/dispatch/service"),
      import("@/server/email/configured-transport"),
      import("@/server/security/credential-keyring"),
    ]);
  const database = await getDatabase();
  const repository = createDispatchRepository(database.client, {
    leasePepper,
  });
  const service = createDispatchService({
    repository,
    liveSendsEnabled: process.env.LIVE_SENDS_ENABLED === "true",
    transportFactory: async (context) =>
      createConfiguredGatewayTransport(context, {
        credentialKeys: parseCredentialEncryptionKeyRing(process.env),
      }),
    appBaseUrl,
    unsubscribeTokenSecret,
    suppressionHashKey,
  });
  return service.runCycle(input);
}

const productionHandler = createDispatchHandler({
  configuredSecret: () => process.env.CRON_SECRET,
  runCycle: runProductionCycle,
});

export async function POST(request: Request): Promise<Response> {
  return productionHandler(request);
}
