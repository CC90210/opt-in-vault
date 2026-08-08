import "server-only";

const MAX_OAUTH_REFRESH_TIMEOUT_MS = 10_000;
const MAX_OAUTH_RESPONSE_BYTES = 65_536;
const MAX_ACCESS_TOKEN_BYTES = 16_384;
const MAX_OAUTH_CREDENTIAL_BYTES = 16_384;

const OAUTH_TOKEN_ENDPOINTS = Object.freeze({
  google: "https://oauth2.googleapis.com/token",
  microsoft: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
});

const PROVIDER_MAIL_HOSTS = Object.freeze({
  google: Object.freeze({
    smtp: "smtp.gmail.com",
    imap: "imap.gmail.com",
  }),
  microsoft: Object.freeze({
    smtp: "smtp.office365.com",
    imap: "outlook.office365.com",
  }),
});

const MICROSOFT_SCOPES = Object.freeze({
  smtp: "https://outlook.office.com/SMTP.Send offline_access",
  imap: "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
});

export type OAuthProvider = keyof typeof OAUTH_TOKEN_ENDPOINTS;
export type OAuthPurpose = "smtp" | "imap";
export type OAuthFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export type OAuthCredentials = Readonly<{
  clientId?: string;
  clientSecret?: string;
  refreshToken?: string;
  accessToken?: string;
}>;

export type OAuthAccessTokenErrorCode =
  | "oauth_credentials_missing"
  | "oauth_provider_host_invalid"
  | "oauth_refresh_failed";

export class OAuthAccessTokenError extends Error {
  constructor(readonly code: OAuthAccessTokenErrorCode) {
    super("OAuth access token is unavailable");
    this.name = "OAuthAccessTokenError";
  }
}

function normalizedHost(host: string): string {
  return host.trim().replace(/\.$/, "").toLowerCase();
}

export function assertOAuthProviderHost(
  provider: OAuthProvider,
  purpose: OAuthPurpose,
  host: string,
): void {
  if (normalizedHost(host) !== PROVIDER_MAIL_HOSTS[provider][purpose]) {
    throw new OAuthAccessTokenError("oauth_provider_host_invalid");
  }
}

function isBoundedCredential(value: string | undefined): value is string {
  return Boolean(
    value &&
      !value.includes("\u0000") &&
      Buffer.byteLength(value, "utf8") <= MAX_OAUTH_CREDENTIAL_BYTES,
  );
}

function requireBoundedAccessToken(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\u0000") ||
    Buffer.byteLength(value, "utf8") > MAX_ACCESS_TOKEN_BYTES
  ) {
    throw new OAuthAccessTokenError("oauth_refresh_failed");
  }
  return value;
}

async function readBoundedResponse(response: Response): Promise<string> {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^\d+$/.test(declaredLength) ||
      Number(declaredLength) > MAX_OAUTH_RESPONSE_BYTES)
  ) {
    throw new OAuthAccessTokenError("oauth_refresh_failed");
  }
  if (!response.body) {
    throw new OAuthAccessTokenError("oauth_refresh_failed");
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_OAUTH_RESPONSE_BYTES) {
        await reader.cancel();
        throw new OAuthAccessTokenError("oauth_refresh_failed");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString(
    "utf8",
  );
}

function boundedTimeout(requestedTimeoutMs: number | undefined): number {
  const timeoutMs = requestedTimeoutMs ?? MAX_OAUTH_REFRESH_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new OAuthAccessTokenError("oauth_refresh_failed");
  }
  return Math.max(
    1,
    Math.min(MAX_OAUTH_REFRESH_TIMEOUT_MS, Math.floor(timeoutMs)),
  );
}

export async function resolveOAuthAccessToken(input: {
  provider: OAuthProvider;
  purpose: OAuthPurpose;
  credentials: OAuthCredentials;
  fetchImpl?: OAuthFetch;
  timeoutMs?: number;
}): Promise<string> {
  const { credentials } = input;
  const completeRefreshGrant = Boolean(
    isBoundedCredential(credentials.clientId) &&
      isBoundedCredential(credentials.clientSecret) &&
      isBoundedCredential(credentials.refreshToken),
  );

  if (!completeRefreshGrant) {
    if (!isBoundedCredential(credentials.accessToken)) {
      throw new OAuthAccessTokenError("oauth_credentials_missing");
    }
    return credentials.accessToken;
  }

  const body = new URLSearchParams({
    client_id: credentials.clientId!,
    client_secret: credentials.clientSecret!,
    refresh_token: credentials.refreshToken!,
    grant_type: "refresh_token",
  });
  if (input.provider === "microsoft") {
    body.set("scope", MICROSOFT_SCOPES[input.purpose]);
  }

  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    boundedTimeout(input.timeoutMs),
  );
  try {
    const response = await (input.fetchImpl ?? fetch)(
      OAUTH_TOKEN_ENDPOINTS[input.provider],
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json",
        },
        body: body.toString(),
        redirect: "error",
        signal: controller.signal,
      },
    );
    if (!response.ok || response.redirected) {
      throw new OAuthAccessTokenError("oauth_refresh_failed");
    }
    const raw = await readBoundedResponse(response);
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new OAuthAccessTokenError("oauth_refresh_failed");
    }
    return requireBoundedAccessToken(
      (parsed as Record<string, unknown>).access_token,
    );
  } catch (error) {
    if (error instanceof OAuthAccessTokenError) throw error;
    throw new OAuthAccessTokenError("oauth_refresh_failed");
  } finally {
    clearTimeout(timeout);
  }
}
