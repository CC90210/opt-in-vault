import "server-only";

import { isCronAuthorized } from "@/server/auth/cron";

type PollResult = {
  inboxesPolled: number;
  messagesProcessed: number;
  failures: number;
};

export function createPollInboxesHandler(dependencies: {
  configuredSecret: string | null | undefined;
  poll(): Promise<PollResult>;
}) {
  return async function POST(request: Request): Promise<Response> {
    if (
      !isCronAuthorized(
        request.headers.get("authorization"),
        dependencies.configuredSecret,
      )
    ) {
      return Response.json(
        { error: "unauthorized" },
        { status: 401, headers: { "cache-control": "no-store" } },
      );
    }
    const result = await dependencies.poll();
    return Response.json(result, {
      status: result.failures > 0 ? 207 : 200,
      headers: { "cache-control": "no-store" },
    });
  };
}

export async function POST(request: Request): Promise<Response> {
  const [{ getDatabase }, { parseCredentialEncryptionKeyRing }, { pollConfiguredInboxes }] =
    await Promise.all([
      import("@/db/client"),
      import("@/server/security/credential-keyring"),
      import("@/server/inbound/poll"),
    ]);
  const handler = createPollInboxesHandler({
    configuredSecret: process.env.CRON_SECRET,
    poll: async () => {
      const suppressionHashKey = process.env.SUPPRESSION_HASH_KEY;
      if (!suppressionHashKey) {
        throw new Error("Inbox worker secrets are not configured");
      }
      const database = await getDatabase();
      return pollConfiguredInboxes(database.client, {
        credentialKeys: parseCredentialEncryptionKeyRing(process.env),
        suppressionHashKey,
        maxInboxes: 10,
        maxMessagesPerInbox: 25,
        maxCycleMs: 45_000,
      });
    },
  });
  return handler(request);
}
