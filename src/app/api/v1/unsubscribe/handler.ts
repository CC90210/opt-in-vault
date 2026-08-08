import "server-only";

import type { UnsubscribeStatus } from "@/server/unsubscribe/service";
import { isUnsubscribeTokenShape } from "@/server/unsubscribe/tokens";

type UnsubscribeService = {
  preview(token: string): Promise<{ status: UnsubscribeStatus }>;
  apply(token: string): Promise<{ status: UnsubscribeStatus }>;
};

const RESPONSE_HEADERS = {
  "cache-control": "no-store, max-age=0",
  "x-content-type-options": "nosniff",
  "x-robots-tag": "noindex, nofollow, noarchive",
};
const MAX_ONE_CLICK_BODY_BYTES = 64;

function tokenFrom(request: Request): string | null {
  const token = new URL(request.url).searchParams.get("token") ?? "";
  return isUnsubscribeTokenShape(token) ? token : null;
}

function htmlResponse(body: string, status = 200): Response {
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>Unsubscribe</title></head><body><main><h1>${body}</h1></main></body></html>`,
    {
      status,
      headers: { ...RESPONSE_HEADERS, "content-type": "text/html; charset=utf-8" },
    },
  );
}

async function readOneClickBody(request: Request): Promise<string | null> {
  const declaredLength = request.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^\d+$/.test(declaredLength) || Number(declaredLength) > MAX_ONE_CLICK_BODY_BYTES)
  ) {
    return null;
  }
  if (!request.body) return "";

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > MAX_ONE_CLICK_BODY_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

export function createUnsubscribeHandlers(service: UnsubscribeService) {
  return {
    async GET(request: Request): Promise<Response> {
      const token = tokenFrom(request);
      if (!token) return htmlResponse("Unsubscribe link not found", 404);
      const result = await service.preview(token);
      if (result.status === "active") {
        return htmlResponse("Confirm unsubscribe");
      }
      if (result.status === "unsubscribed") {
        return htmlResponse("Already unsubscribed");
      }
      return htmlResponse("Unsubscribe link not found", 404);
    },

    async POST(request: Request): Promise<Response> {
      const token = tokenFrom(request);
      if (!token) return new Response("Not found", { status: 404, headers: RESPONSE_HEADERS });
      const contentType = request.headers.get("content-type") ?? "";
      const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase();
      if (mediaType !== "application/x-www-form-urlencoded") {
        return new Response("Invalid one-click request", {
          status: 400,
          headers: RESPONSE_HEADERS,
        });
      }
      const body = await readOneClickBody(request);
      if (body !== "List-Unsubscribe=One-Click") {
        return new Response("Invalid one-click request", {
          status: 400,
          headers: RESPONSE_HEADERS,
        });
      }
      const result = await service.apply(token);
      if (result.status === "invalid" || result.status === "expired") {
        return new Response("Not found", { status: 404, headers: RESPONSE_HEADERS });
      }
      return new Response("Unsubscribed", {
        status: 200,
        headers: { ...RESPONSE_HEADERS, "content-type": "text/plain; charset=utf-8" },
      });
    },
  };
}

async function productionService(): Promise<UnsubscribeService> {
  const tokenSecret = process.env.UNSUBSCRIBE_TOKEN_SECRET;
  const suppressionHashKey = process.env.SUPPRESSION_HASH_KEY;
  if (!tokenSecret || !suppressionHashKey) {
    throw new Error("Unsubscribe service secrets are not configured");
  }
  const [{ getDatabase }, { createUnsubscribeService }] = await Promise.all([
    import("@/db/client"),
    import("@/server/unsubscribe/service"),
  ]);
  const database = await getDatabase();
  return createUnsubscribeService(database.client, {
    tokenSecret,
    suppressionHashKey,
  });
}

export async function GET(request: Request): Promise<Response> {
  return createUnsubscribeHandlers(await productionService()).GET(request);
}

export async function POST(request: Request): Promise<Response> {
  return createUnsubscribeHandlers(await productionService()).POST(request);
}
