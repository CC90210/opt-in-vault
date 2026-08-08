type LoginDependencies = {
  exchangeApiKey(apiKey: string): Promise<string | null>;
};

const API_KEY_PATTERN = /^oiv_sk_[A-Za-z0-9_-]{43}$/;
const MAX_FORM_BYTES = 2_048;
const FORM_CONTENT_TYPE =
  /^application\/x-www-form-urlencoded(?:\s*;\s*charset=utf-8)?$/i;
const RESPONSE_HEADERS = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
};

function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

function redirectTo(path: string, cookie?: string): Response {
  if (!path.startsWith("/") || path.startsWith("//")) {
    throw new Error("Login redirect must be application-relative");
  }
  const headers = new Headers(RESPONSE_HEADERS);
  headers.set("location", path);
  if (cookie) headers.set("set-cookie", cookie);
  return new Response(null, { status: 303, headers });
}

class FormBodyTooLargeError extends Error {}

async function readBoundedFormBody(request: Request): Promise<string> {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_FORM_BYTES) {
        await reader.cancel();
        throw new FormBodyTooLargeError();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(
    Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))),
  );
}

export function createLoginHandler(dependencies: LoginDependencies) {
  return async function login(request: Request): Promise<Response> {
    if (!sameOrigin(request)) {
      return new Response("Forbidden", { status: 403, headers: RESPONSE_HEADERS });
    }
    const declaredLength = request.headers.get("content-length");
    if (
      declaredLength !== null &&
      (!/^\d+$/.test(declaredLength) ||
        !Number.isSafeInteger(Number(declaredLength)))
    ) {
      return new Response("Invalid Content-Length", {
        status: 400,
        headers: RESPONSE_HEADERS,
      });
    }
    if (declaredLength !== null && Number(declaredLength) > MAX_FORM_BYTES) {
      return new Response("Request too large", {
        status: 413,
        headers: RESPONSE_HEADERS,
      });
    }
    const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
    if (!FORM_CONTENT_TYPE.test(contentType.trim())) {
      return new Response("Unsupported form encoding", {
        status: 415,
        headers: RESPONSE_HEADERS,
      });
    }

    let apiKey: string;
    try {
      const form = new URLSearchParams(await readBoundedFormBody(request));
      const keys = [...form.keys()];
      const values = form.getAll("apiKey");
      apiKey =
        keys.length === 1 && keys[0] === "apiKey" && values.length === 1
          ? values[0].trim()
          : "";
    } catch (error) {
      if (error instanceof FormBodyTooLargeError) {
        return new Response("Request too large", {
          status: 413,
          headers: RESPONSE_HEADERS,
        });
      }
      return redirectTo("/login?error=invalid");
    }
    if (!API_KEY_PATTERN.test(apiKey)) {
      return redirectTo("/login?error=invalid");
    }

    try {
      const cookie = await dependencies.exchangeApiKey(apiKey);
      return cookie
        ? redirectTo("/dashboard", cookie)
        : redirectTo("/login?error=invalid");
    } catch (error) {
      console.error("Dashboard API-key exchange failed", error);
      return redirectTo("/login?error=configuration");
    }
  };
}
