import "server-only";

import { createHmac, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE_NAME = "__Host-opt_in_vault_session";
export const MAX_SESSION_TTL_MS = 60 * 60 * 1_000;
export const MAX_SESSION_TOKEN_CHARS = 3_800;

const TOKEN_VERSION = "oivs2";
const SESSION_SECRET_MIN_BYTES = 32;
const MAX_CLOCK_SKEW_MS = 60_000;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const SCOPE_PATTERN = /^[a-z0-9][a-z0-9:_-]{0,99}$/;

export type SessionClaims = {
  tenantId: string;
  scopes: string[];
  issuedAt: number;
  expiresAt: number;
};

export type NewSessionClaims = Omit<SessionClaims, "issuedAt">;

type SessionWirePayload = {
  v: 2;
  tenant_id: string;
  scopes: string[];
  iat: number;
  exp: number;
};

function requireSecret(secret: string): void {
  if (Buffer.byteLength(secret, "utf8") < SESSION_SECRET_MIN_BYTES) {
    throw new Error("Session secret must be at least 32 bytes.");
  }
}

function isValidTimestamp(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function requireNow(value: number): number {
  if (!isValidTimestamp(value)) {
    throw new Error("Session time must be a non-negative safe integer.");
  }
  return value;
}

function hasValidIdentityClaims(claims: {
  tenantId: string;
  scopes: readonly string[];
  expiresAt: number;
}): boolean {
  return (
    ID_PATTERN.test(claims.tenantId) &&
    claims.scopes.length <= 64 &&
    new Set(claims.scopes).size === claims.scopes.length &&
    claims.scopes.every((scope) => SCOPE_PATTERN.test(scope)) &&
    isValidTimestamp(claims.expiresAt) &&
    claims.expiresAt > 0
  );
}

function signatureFor(unsignedToken: string, secret: string): Buffer {
  return createHmac("sha256", secret).update(unsignedToken, "utf8").digest();
}

export function createSessionToken(
  claims: NewSessionClaims,
  secret: string,
  options: { now?: number } = {},
): string {
  requireSecret(secret);
  const now = requireNow(options.now ?? Date.now());
  if (!hasValidIdentityClaims(claims) || claims.expiresAt <= now) {
    throw new Error("Invalid session claims.");
  }
  if (claims.expiresAt - now > MAX_SESSION_TTL_MS) {
    throw new Error("Session lifetime exceeds the maximum allowed lifetime.");
  }

  const payload: SessionWirePayload = {
    v: 2,
    tenant_id: claims.tenantId,
    scopes: [...claims.scopes],
    iat: now,
    exp: claims.expiresAt,
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const unsignedToken = `${TOKEN_VERSION}.${encodedPayload}`;
  const signature = signatureFor(unsignedToken, secret).toString("base64url");
  const token = `${unsignedToken}.${signature}`;
  if (token.length > MAX_SESSION_TOKEN_CHARS) {
    throw new Error("Session token is too large for a secure cookie.");
  }

  return token;
}

export function verifySessionToken(
  token: string,
  secret: string,
  options: { now?: number } = {},
): SessionClaims | null {
  try {
    requireSecret(secret);
    const now = requireNow(options.now ?? Date.now());
    if (token.length === 0 || token.length > MAX_SESSION_TOKEN_CHARS) {
      return null;
    }
    const parts = token.split(".");
    if (
      parts.length !== 3 ||
      parts[0] !== TOKEN_VERSION ||
      !/^[A-Za-z0-9_-]{1,3600}$/.test(parts[1]) ||
      !SIGNATURE_PATTERN.test(parts[2])
    ) {
      return null;
    }

    const unsignedToken = `${parts[0]}.${parts[1]}`;
    const actualSignature = Buffer.from(parts[2], "base64url");
    const expectedSignature = signatureFor(unsignedToken, secret);
    if (
      actualSignature.length !== expectedSignature.length ||
      actualSignature.toString("base64url") !== parts[2] ||
      !timingSafeEqual(actualSignature, expectedSignature)
    ) {
      return null;
    }

    const rawPayload: unknown = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8"),
    );
    if (!rawPayload || typeof rawPayload !== "object" || Array.isArray(rawPayload)) {
      return null;
    }

    const payload = rawPayload as Partial<SessionWirePayload>;
    if (
      Object.keys(payload).length !== 5 ||
      payload.v !== 2 ||
      typeof payload.tenant_id !== "string" ||
      !Array.isArray(payload.scopes) ||
      !payload.scopes.every((scope) => typeof scope === "string") ||
      typeof payload.iat !== "number" ||
      typeof payload.exp !== "number"
    ) {
      return null;
    }

    const claims: SessionClaims = {
      tenantId: payload.tenant_id,
      scopes: payload.scopes,
      issuedAt: payload.iat,
      expiresAt: payload.exp,
    };
    if (
      !hasValidIdentityClaims(claims) ||
      !isValidTimestamp(claims.issuedAt) ||
      claims.expiresAt <= claims.issuedAt ||
      claims.expiresAt - claims.issuedAt > MAX_SESSION_TTL_MS ||
      claims.issuedAt > now + MAX_CLOCK_SKEW_MS ||
      now >= claims.expiresAt
    ) {
      return null;
    }

    return claims;
  } catch {
    return null;
  }
}

export function serializeSessionCookie(
  token: string,
  secret: string,
  options: { now?: number } = {},
): string {
  const now = requireNow(options.now ?? Date.now());
  const claims = verifySessionToken(token, secret, { now });
  if (!claims) {
    throw new Error("Session token is invalid or expired.");
  }

  const maxAgeSeconds = Math.max(1, Math.floor((claims.expiresAt - now) / 1_000));
  return [
    `${SESSION_COOKIE_NAME}=${token}`,
    "Path=/",
    `Max-Age=${maxAgeSeconds}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ].join("; ");
}
