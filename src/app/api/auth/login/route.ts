import { getDatabase } from "@/db/client";
import {
  authenticateRequest,
  parseApiKeyPepperRing,
} from "@/server/auth/request";
import {
  createSessionToken,
  MAX_SESSION_TTL_MS,
  serializeSessionCookie,
} from "@/server/auth/session";

import { createLoginHandler } from "./handler";

async function exchangeApiKey(apiKey: string): Promise<string | null> {
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    throw new Error("SESSION_SECRET is required for dashboard login");
  }
  const database = await getDatabase();
  const principal = await authenticateRequest(
    database.client,
    new Request("https://internal.opt-in-vault.invalid/login", {
      headers: { authorization: `Bearer ${apiKey}` },
    }),
    {
      apiKeyPeppers: parseApiKeyPepperRing(process.env),
      sessionSecret,
      requiredScope: "dashboard:read",
    },
  );
  if (!principal) return null;

  const now = Date.now();
  const token = createSessionToken(
    {
      tenantId: principal.tenantId,
      scopes: principal.scopes,
      expiresAt: now + MAX_SESSION_TTL_MS,
    },
    sessionSecret,
    { now },
  );
  return serializeSessionCookie(token, sessionSecret, { now });
}

const handler = createLoginHandler({ exchangeApiKey });

export async function POST(request: Request): Promise<Response> {
  return handler(request);
}
