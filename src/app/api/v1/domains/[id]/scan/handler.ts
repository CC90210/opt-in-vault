import "server-only";

import type { RequestPrincipal } from "@/server/auth/request";
import { SendingDomainNotFoundError } from "@/server/dns/service";

type RouteContext = { params: Promise<{ id: string }> };

export function createDomainScanHandler(dependencies: {
  authorize(request: Request): Promise<Pick<RequestPrincipal, "tenantId"> | null>;
  scan(identity: { tenantId: string; domainId: string }): Promise<unknown>;
}) {
  return async function POST(
    request: Request,
    context: RouteContext,
  ): Promise<Response> {
    const principal = await dependencies.authorize(request);
    if (!principal) {
      return Response.json(
        { error: "unauthorized" },
        { status: 401, headers: { "cache-control": "no-store" } },
      );
    }
    const { id } = await context.params;
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(id)) {
      return Response.json(
        { error: "not_found" },
        { status: 404, headers: { "cache-control": "no-store" } },
      );
    }
    try {
      const result = await dependencies.scan({
        tenantId: principal.tenantId,
        domainId: id,
      });
      return Response.json(result, {
        status: 200,
        headers: { "cache-control": "no-store" },
      });
    } catch (error) {
      if (error instanceof SendingDomainNotFoundError) {
        return Response.json(
          { error: "not_found" },
          { status: 404, headers: { "cache-control": "no-store" } },
        );
      }
      throw error;
    }
  };
}

export async function POST(
  request: Request,
  context: RouteContext,
): Promise<Response> {
  const [databaseModule, authModule, dnsModule] = await Promise.all([
    import("@/db/client"),
    import("@/server/auth/request"),
    import("@/server/dns/service"),
  ]);
  const database = await databaseModule.getDatabase();
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) throw new Error("Session authentication is not configured");
  const handler = createDomainScanHandler({
    authorize: (incoming) =>
      authModule.authenticateRequest(database.client, incoming, {
        apiKeyPeppers: authModule.parseApiKeyPepperRing(process.env),
        sessionSecret,
        requiredScope: "domains:write",
      }),
    scan: (identity) => dnsModule.scanSendingDomain(database.client, identity),
  });
  return handler(request, context);
}
