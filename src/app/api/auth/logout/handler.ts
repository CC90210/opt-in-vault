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

export function createLogoutHandler(
  cookieName = "__Host-opt_in_vault_session",
) {
  if (!/^__Host-[A-Za-z0-9_]+$/.test(cookieName)) {
    throw new Error("Invalid session cookie name");
  }
  return async function logout(request: Request): Promise<Response> {
    if (!sameOrigin(request)) {
      return new Response("Forbidden", { status: 403, headers: RESPONSE_HEADERS });
    }
    const headers = new Headers(RESPONSE_HEADERS);
    headers.set("location", "/login");
    headers.set(
      "set-cookie",
      `${cookieName}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
    );
    return new Response(null, { status: 303, headers });
  };
}
