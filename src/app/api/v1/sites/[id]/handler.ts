import "server-only";

import type { RequestPrincipal } from "@/server/auth/request";
import {
  CaptureSiteNotFoundError,
  CaptureSiteTransitionError,
  CaptureSiteValidationError,
  type CaptureSiteSummary,
} from "@/server/consent/sites";

const RESPONSE_HEADERS = { "cache-control": "no-store" };
const SITE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

type RouteContext = { params: Promise<{ id: string }> };

function json(body: unknown, status: number): Response {
  return Response.json(body, { status, headers: RESPONSE_HEADERS });
}

export function createSiteStatusHandler(dependencies: {
  authorize(request: Request): Promise<Pick<RequestPrincipal, "tenantId"> | null>;
  setStatus(input: {
    tenantId: string;
    siteId: string;
    status: unknown;
  }): Promise<CaptureSiteSummary>;
}) {
  return async function PATCH(
    request: Request,
    context: RouteContext,
  ): Promise<Response> {
    const principal = await dependencies.authorize(request);
    if (!principal) return json({ error: "unauthorized" }, 401);
    const { id } = await context.params;
    if (!SITE_ID_PATTERN.test(id)) return json({ error: "not_found" }, 404);
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ error: "invalid_request" }, 400);
    }
    const status =
      body && typeof body === "object" && !Array.isArray(body)
        ? (body as { status?: unknown }).status
        : undefined;
    try {
      const site = await dependencies.setStatus({
        tenantId: principal.tenantId,
        siteId: id,
        status,
      });
      return json({ site }, 200);
    } catch (error) {
      if (error instanceof CaptureSiteValidationError) {
        return json({ error: "invalid_request", detail: error.detail }, 400);
      }
      if (error instanceof CaptureSiteNotFoundError) {
        return json({ error: "not_found" }, 404);
      }
      if (error instanceof CaptureSiteTransitionError) {
        return json({ error: "invalid_transition" }, 409);
      }
      throw error;
    }
  };
}

export async function PATCH(
  request: Request,
  context: RouteContext,
): Promise<Response> {
  const [databaseModule, authModule, sitesModule] = await Promise.all([
    import("@/db/client"),
    import("@/server/auth/request"),
    import("@/server/consent/sites"),
  ]);
  const database = await databaseModule.getDatabase();
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    throw new Error("Capture-site administration is not configured");
  }
  const handler = createSiteStatusHandler({
    authorize: (incoming) =>
      authModule.authenticateRequest(database.client, incoming, {
        apiKeyPeppers: authModule.parseApiKeyPepperRing(process.env),
        sessionSecret,
        requiredScope: "admin",
      }),
    setStatus: ({ tenantId, siteId, status }) =>
      sitesModule.updateCaptureSiteStatus(
        database.client,
        tenantId,
        siteId,
        status,
      ),
  });
  return handler(request, context);
}
