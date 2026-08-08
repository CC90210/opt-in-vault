import { cache } from "react";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { getDatabase } from "@/db/client";
import {
  authenticateRequest,
  parseApiKeyPepperRing,
} from "@/server/auth/request";
import { getDashboardSnapshot } from "@/server/dashboard/queries";

export const requireDashboardContext = cache(async () => {
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    throw new Error("SESSION_SECRET is required for dashboard access");
  }
  const incoming = await headers();
  const requestHeaders = new Headers();
  const cookie = incoming.get("cookie");
  const authorization = incoming.get("authorization");
  if (cookie) requestHeaders.set("cookie", cookie);
  if (authorization) requestHeaders.set("authorization", authorization);

  const database = await getDatabase();
  const principal = await authenticateRequest(
    database.client,
    new Request("https://internal.opt-in-vault.invalid/dashboard", {
      headers: requestHeaders,
    }),
    {
      apiKeyPeppers: parseApiKeyPepperRing(process.env),
      sessionSecret,
      requiredScope: "dashboard:read",
    },
  );
  if (!principal) redirect("/login");
  return { client: database.client, principal };
});

export const loadDashboardSnapshot = cache(async () => {
  const { client, principal } = await requireDashboardContext();
  return getDashboardSnapshot(client, principal.tenantId);
});
