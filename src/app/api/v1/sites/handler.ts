import "server-only";

import type { RequestPrincipal } from "@/server/auth/request";
import {
  CaptureSiteValidationError,
  type CaptureSiteSummary,
} from "@/server/consent/sites";

const RESPONSE_HEADERS = { "cache-control": "no-store" };

export type CreatedCaptureSiteResponse = {
  site: CaptureSiteSummary;
  site_key: string;
  snippet: string;
};

function json(body: unknown, status: number): Response {
  return Response.json(body, { status, headers: RESPONSE_HEADERS });
}

export function createSiteCreateHandler(dependencies: {
  authorize(request: Request): Promise<Pick<RequestPrincipal, "tenantId"> | null>;
  createSite(input: {
    tenantId: string;
    body: unknown;
  }): Promise<CreatedCaptureSiteResponse>;
}) {
  return async function POST(request: Request): Promise<Response> {
    const principal = await dependencies.authorize(request);
    if (!principal) return json({ error: "unauthorized" }, 401);
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ error: "invalid_request" }, 400);
    }
    try {
      const result = await dependencies.createSite({
        tenantId: principal.tenantId,
        body,
      });
      return json(result, 201);
    } catch (error) {
      if (error instanceof CaptureSiteValidationError) {
        return json({ error: "invalid_request", detail: error.detail }, 400);
      }
      throw error;
    }
  };
}

export async function POST(request: Request): Promise<Response> {
  const [databaseModule, authModule, sitesModule] = await Promise.all([
    import("@/db/client"),
    import("@/server/auth/request"),
    import("@/server/consent/sites"),
  ]);
  const database = await databaseModule.getDatabase();
  const sessionSecret = process.env.SESSION_SECRET;
  const siteKeyPepper = process.env.CAPTURE_SITE_KEY_PEPPER;
  const appBaseUrl = process.env.NEXT_PUBLIC_APP_URL;
  if (!sessionSecret || !siteKeyPepper || !appBaseUrl) {
    throw new Error("Capture-site administration is not configured");
  }
  const handler = createSiteCreateHandler({
    authorize: (incoming) =>
      authModule.authenticateRequest(database.client, incoming, {
        apiKeyPeppers: authModule.parseApiKeyPepperRing(process.env),
        sessionSecret,
        requiredScope: "admin",
      }),
    createSite: async ({ tenantId, body }) => {
      const { site, rawKey } = await sitesModule.createCaptureSite(
        database.client,
        tenantId,
        body,
        { siteKeyPepper },
      );
      return {
        site,
        site_key: rawKey,
        snippet: sitesModule.buildCaptureSnippet({
          appBaseUrl,
          siteKey: rawKey,
          disclosureVersion: site.disclosureVersion,
        }),
      };
    },
  });
  return handler(request);
}
