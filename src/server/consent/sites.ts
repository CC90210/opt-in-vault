import "server-only";

import { randomBytes, randomUUID } from "node:crypto";
import { isIP } from "node:net";

import type { Client } from "@libsql/client";
import { z } from "zod";

import { webUrlSchema } from "@/server/validation/primitives";

import { hashCaptureSiteKey } from "./service";

export const CAPTURE_SITE_KEY_PREFIX_LENGTH = 18;
export const MAX_CAPTURE_SITE_ORIGINS = 100;

const SITE_KEY_SECRET_BYTES = 32;
const SITE_KEY_PATTERN = /^oiv_pk_[A-Za-z0-9_-]{43}$/;
const NULL_BYTE = String.fromCharCode(0);

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (normalized === "localhost") return true;
  const bare = normalized.replace(/^\[|\]$/g, "");
  if (bare === "::1") return true;
  return isIP(bare) === 4 && bare.startsWith("127.");
}

function cappedText(max: number) {
  return z
    .string()
    .trim()
    .min(1)
    .max(max)
    .refine((value) => !value.includes(NULL_BYTE), "Text cannot contain null bytes.");
}

const originSchema = z
  .string()
  .max(512)
  .refine((value) => {
    try {
      const url = new URL(value);
      if (url.origin !== value) return false;
      if (url.protocol === "https:") return true;
      return url.protocol === "http:" && isLoopbackHostname(url.hostname);
    } catch {
      return false;
    }
  }, "Allowed origins must be exact HTTPS origins; plain HTTP is accepted only for loopback development.");

const formUrlPatternSchema = z
  .string()
  .trim()
  .max(2_048)
  .refine((value) => {
    const wildcardCount = [...value].filter((character) => character === "*").length;
    if (wildcardCount === 0) return webUrlSchema.safeParse(value).success;
    if (wildcardCount !== 1 || !value.endsWith("*")) return false;
    const prefix = value.slice(0, -1);
    return prefix.length > 0 && webUrlSchema.safeParse(prefix).success;
  }, "Form URL rule must be an exact URL or a single trailing-* prefix rule.")
  .nullable()
  .optional()
  .transform((value) => (value ? value : null));

const channelsSchema = z
  .array(z.enum(["email", "sms"]))
  .min(1)
  .max(2)
  .refine((value) => new Set(value).size === value.length, "Channels must not repeat.")
  .transform((value) => [...value].sort());

export const createCaptureSiteSchema = z
  .object({
    name: cappedText(128),
    allowedOrigins: z
      .array(originSchema)
      .min(1)
      .max(MAX_CAPTURE_SITE_ORIGINS)
      .refine(
        (value) => new Set(value).size === value.length,
        "Allowed origins must not repeat.",
      ),
    formUrlPattern: formUrlPatternSchema,
    disclosureVersion: cappedText(128),
    disclosureText: cappedText(8_000),
    controller: cappedText(200),
    purpose: cappedText(500),
    channels: channelsSchema,
  })
  .strict();

export type CreateCaptureSiteInput = z.infer<typeof createCaptureSiteSchema>;

export const captureSiteStatusSchema = z.enum(["active", "paused", "revoked"]);
export type CaptureSiteStatus = z.infer<typeof captureSiteStatusSchema>;

const ALLOWED_TRANSITIONS: Readonly<
  Record<CaptureSiteStatus, ReadonlySet<CaptureSiteStatus>>
> = {
  active: new Set(["paused", "revoked"]),
  paused: new Set(["active", "revoked"]),
  revoked: new Set(),
};

export class CaptureSiteValidationError extends Error {
  readonly detail: string | null;

  constructor(detail?: string) {
    super("invalid_request");
    this.name = "CaptureSiteValidationError";
    this.detail = detail ?? null;
  }
}

export class CaptureSiteNotFoundError extends Error {
  constructor() {
    super("not_found");
    this.name = "CaptureSiteNotFoundError";
  }
}

export class CaptureSiteTransitionError extends Error {
  constructor() {
    super("invalid_transition");
    this.name = "CaptureSiteTransitionError";
  }
}

export type CaptureSiteSummary = {
  id: string;
  name: string;
  publicKeyPrefix: string;
  allowedOrigins: string[];
  formUrlPattern: string | null;
  disclosureVersion: string;
  controller: string;
  purpose: string;
  channels: string[];
  status: CaptureSiteStatus;
  createdAt: number;
};

export function generateCaptureSiteKey(pepper: string): {
  rawKey: string;
  prefix: string;
  hash: string;
} {
  const rawKey = `oiv_pk_${randomBytes(SITE_KEY_SECRET_BYTES).toString("base64url")}`;
  return {
    rawKey,
    prefix: rawKey.slice(0, CAPTURE_SITE_KEY_PREFIX_LENGTH),
    hash: hashCaptureSiteKey(rawKey, pepper),
  };
}

function stringArrayFromJson(value: unknown, field: string): string[] {
  if (typeof value !== "string") throw new Error(`Stored capture site ${field} is invalid.`);
  try {
    const parsed: unknown = JSON.parse(value);
    if (
      !Array.isArray(parsed) ||
      !parsed.every((entry) => typeof entry === "string")
    ) {
      throw new Error();
    }
    return parsed;
  } catch {
    throw new Error(`Stored capture site ${field} is invalid.`);
  }
}

function mapSiteRow(row: Record<string, unknown>): CaptureSiteSummary {
  const status = captureSiteStatusSchema.safeParse(row.status);
  if (!row.id || !status.success) {
    throw new Error("Stored capture site record is invalid.");
  }
  return {
    id: String(row.id),
    name: String(row.name),
    publicKeyPrefix: String(row.public_key_prefix),
    allowedOrigins: stringArrayFromJson(row.allowed_origins_json, "allowed origins"),
    formUrlPattern: row.form_url_pattern == null ? null : String(row.form_url_pattern),
    disclosureVersion: String(row.disclosure_version),
    controller: String(row.controller),
    purpose: String(row.purpose),
    channels: stringArrayFromJson(row.channels_json, "channels"),
    status: status.data,
    createdAt: Number(row.created_at),
  };
}

export async function createCaptureSite(
  client: Client,
  tenantId: string,
  rawInput: unknown,
  options: {
    siteKeyPepper: string;
    now?: () => number;
    createId?: () => string;
  },
): Promise<{ site: CaptureSiteSummary; rawKey: string }> {
  const parsed = createCaptureSiteSchema.safeParse(rawInput);
  if (!parsed.success) {
    throw new CaptureSiteValidationError(parsed.error.issues[0]?.message);
  }
  const input = parsed.data;
  const now = (options.now ?? Date.now)();
  if (!Number.isSafeInteger(now) || now <= 0) {
    throw new Error("Capture-site clock returned an invalid timestamp.");
  }
  const id = (options.createId ?? (() => `site_${randomUUID()}`))();
  const key = generateCaptureSiteKey(options.siteKeyPepper);

  await client.execute({
    sql: `INSERT INTO capture_sites
            (id, tenant_id, name, public_key_prefix, public_key_hash,
             allowed_origins_json, form_url_pattern, disclosure_version,
             disclosure_text, controller, purpose, channels_json,
             status, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
    args: [
      id,
      tenantId,
      input.name,
      key.prefix,
      key.hash,
      JSON.stringify(input.allowedOrigins),
      input.formUrlPattern,
      input.disclosureVersion,
      input.disclosureText,
      input.controller,
      input.purpose,
      JSON.stringify(input.channels),
      now,
    ],
  });

  return {
    site: {
      id,
      name: input.name,
      publicKeyPrefix: key.prefix,
      allowedOrigins: input.allowedOrigins,
      formUrlPattern: input.formUrlPattern,
      disclosureVersion: input.disclosureVersion,
      controller: input.controller,
      purpose: input.purpose,
      channels: input.channels,
      status: "active",
      createdAt: now,
    },
    rawKey: key.rawKey,
  };
}

export async function updateCaptureSiteStatus(
  client: Client,
  tenantId: string,
  siteId: string,
  rawStatus: unknown,
): Promise<CaptureSiteSummary> {
  const parsed = captureSiteStatusSchema.safeParse(rawStatus);
  if (!parsed.success) {
    throw new CaptureSiteValidationError(parsed.error.issues[0]?.message);
  }
  const next = parsed.data;
  const result = await client.execute({
    sql: `SELECT id, name, public_key_prefix, allowed_origins_json,
                 form_url_pattern, disclosure_version, controller, purpose,
                 channels_json, status, created_at
          FROM capture_sites
          WHERE tenant_id = ? AND id = ?
          LIMIT 1`,
    args: [tenantId, siteId],
  });
  const row = result.rows[0];
  if (!row) throw new CaptureSiteNotFoundError();
  const site = mapSiteRow(row as unknown as Record<string, unknown>);
  if (!ALLOWED_TRANSITIONS[site.status].has(next)) {
    throw new CaptureSiteTransitionError();
  }
  const updated = await client.execute({
    sql: `UPDATE capture_sites
          SET status = ?
          WHERE tenant_id = ? AND id = ? AND status = ?`,
    args: [next, tenantId, siteId, site.status],
  });
  if (updated.rowsAffected !== 1) {
    throw new CaptureSiteTransitionError();
  }
  return { ...site, status: next };
}

function scriptStringLiteral(value: string): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

export function buildCaptureSnippet(options: {
  appBaseUrl: string;
  siteKey: string;
  disclosureVersion: string;
}): string {
  if (!SITE_KEY_PATTERN.test(options.siteKey)) {
    throw new Error("Invalid capture-site key.");
  }
  let origin: string;
  try {
    const url = new URL(options.appBaseUrl.trim());
    const https = url.protocol === "https:";
    const loopbackHttp =
      url.protocol === "http:" && isLoopbackHostname(url.hostname);
    if (!https && !loopbackHttp) throw new Error();
    if (url.pathname !== "/" && url.pathname !== "") throw new Error();
    if (url.search || url.hash) throw new Error();
    origin = url.origin;
  } catch {
    throw new Error(
      "NEXT_PUBLIC_APP_URL must be a clean HTTPS origin; loopback HTTP is accepted for local development.",
    );
  }
  const endpoint = `${origin}/api/v1/consent/log`;
  return [
    `<script src="${origin}/v1/optinvault.js"></script>`,
    "<script>",
    "  async function recordConsent(form) {",
    "    return window.OptInVault.capture({",
    `      endpoint: ${scriptStringLiteral(endpoint)},`,
    `      siteKey: ${scriptStringLiteral(options.siteKey)},`,
    `      disclosureVersion: ${scriptStringLiteral(options.disclosureVersion)},`,
    '      affirmativeAction: "form_submit",',
    "      formUrl: window.location.href,",
    "      idempotencyKey: crypto.randomUUID()",
    "    });",
    "  }",
    "</script>",
  ].join("\n");
}
