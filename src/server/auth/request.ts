import "server-only";

import type { Client } from "@libsql/client";

import {
  authenticateApiKey,
  extractApiKeyLookupPrefix,
  MAX_API_KEY_HASH_VERSIONS,
  type ApiKeyPepperRing,
  type ApiKeyRecord,
} from "./api-keys";
import { SESSION_COOKIE_NAME, verifySessionToken } from "./session";

export type RequestPrincipal = {
  tenantId: string;
  scopes: string[];
  authType: "api_key" | "session";
  apiKeyId?: string;
};

type RequestAuthOptions = {
  apiKeyPeppers: ApiKeyPepperRing;
  sessionSecret: string;
  requiredScope?: string;
  now?: () => number;
};

function cookieValue(header: string | null, name: string): string | null {
  if (!header || header.length > 16_384 || /[\r\n\u0000]/.test(header)) return null;
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim() || null;
    }
  }
  return null;
}

function scopesFromJson(raw: unknown): string[] | null {
  if (typeof raw !== "string" || raw.length > 16_384) return null;
  try {
    const value: unknown = JSON.parse(raw);
    if (
      !Array.isArray(value) ||
      value.length > 64 ||
      !value.every(
        (scope) =>
          typeof scope === "string" &&
          /^[a-z0-9][a-z0-9:_-]{0,99}$/.test(scope),
      ) ||
      new Set(value).size !== value.length
    ) {
      return null;
    }
    return value;
  } catch {
    return null;
  }
}

async function tenantIsActive(client: Client, tenantId: string): Promise<boolean> {
  const result = await client.execute({
    sql: "SELECT 1 FROM tenants WHERE id = ? AND status = 'active' LIMIT 1",
    args: [tenantId],
  });
  return result.rows.length === 1;
}

export async function authenticateRequest(
  client: Client,
  request: Request,
  options: RequestAuthOptions,
): Promise<RequestPrincipal | null> {
  const now = (options.now ?? Date.now)();
  if (!Number.isSafeInteger(now) || now < 0) return null;
  const authorization = request.headers.get("authorization");

  if (authorization !== null) {
    const match = /^Bearer (oiv_sk_[A-Za-z0-9_-]{43})$/.exec(authorization);
    if (!match) return null;
    const rawKey = match[1];
    const prefix = extractApiKeyLookupPrefix(rawKey);
    if (!prefix) return null;
    const result = await client.execute({
      sql: `
        SELECT api_key.id, api_key.tenant_id, api_key.prefix, api_key.key_hash,
               api_key.hash_key_version, api_key.scopes_json, api_key.expires_at,
               api_key.revoked_at
        FROM tenant_api_keys AS api_key
        JOIN tenants AS tenant ON tenant.id = api_key.tenant_id
        WHERE api_key.prefix = ? AND tenant.status = 'active'
        LIMIT 2
      `,
      args: [prefix],
    });
    if (result.rows.length !== 1) return null;
    const row = result.rows[0];
    const scopes = scopesFromJson(row.scopes_json);
    if (!scopes) return null;
    const record: ApiKeyRecord = {
      id: String(row.id),
      tenantId: String(row.tenant_id),
      prefix: String(row.prefix),
      hash: String(row.key_hash),
      hashKeyVersion: Number(row.hash_key_version),
      scopes,
      expiresAt: row.expires_at == null ? null : Number(row.expires_at),
      revokedAt: row.revoked_at == null ? null : Number(row.revoked_at),
    };
    const principal = authenticateApiKey(rawKey, record, options.apiKeyPeppers, {
      now,
      requiredScope: options.requiredScope,
    });
    return principal
      ? {
          tenantId: principal.tenantId,
          scopes: principal.scopes,
          authType: "api_key",
          apiKeyId: principal.apiKeyId,
        }
      : null;
  }

  const token = cookieValue(request.headers.get("cookie"), SESSION_COOKIE_NAME);
  if (!token) return null;
  const claims = verifySessionToken(token, options.sessionSecret, { now });
  if (
    !claims ||
    (options.requiredScope && !claims.scopes.includes(options.requiredScope)) ||
    !(await tenantIsActive(client, claims.tenantId))
  ) {
    return null;
  }
  return {
    tenantId: claims.tenantId,
    scopes: [...claims.scopes],
    authType: "session",
  };
}

export function parseApiKeyPepperRing(
  environment: Readonly<Record<string, string | undefined>>,
): ReadonlyMap<number, string> {
  try {
    const peppers = new Map<number, string>();
    const historical = environment.API_KEY_PEPPERS_JSON;
    if (historical) {
      if (historical.length > 16_384) return new Map();
      const parsed: unknown = JSON.parse(historical);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return new Map();
      }
      for (const [rawVersion, rawPepper] of Object.entries(parsed)) {
        const version = Number(rawVersion);
        if (
          !/^[1-9]\d*$/.test(rawVersion) ||
          !Number.isSafeInteger(version) ||
          version > 2_147_483_647 ||
          typeof rawPepper !== "string" ||
          Buffer.byteLength(rawPepper, "utf8") < 32
        ) {
          return new Map();
        }
        peppers.set(version, rawPepper);
      }
    }

    const current = environment.API_KEY_PEPPER;
    if (current) {
      const version = Number(environment.API_KEY_PEPPER_VERSION ?? "1");
      if (
        !Number.isSafeInteger(version) ||
        version < 1 ||
        version > 2_147_483_647 ||
        Buffer.byteLength(current, "utf8") < 32
      ) {
        return new Map();
      }
      peppers.set(version, current);
    }
    return peppers.size > 0 && peppers.size <= MAX_API_KEY_HASH_VERSIONS
      ? peppers
      : new Map();
  } catch {
    return new Map();
  }
}
