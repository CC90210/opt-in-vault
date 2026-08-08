import "server-only";

import { isIP } from "node:net";
import { domainToASCII } from "node:url";

const MAX_SECRET_BYTES = 16_384;
const MAX_DKIM_KEY_BYTES = 65_536;

export type InboxOAuthCredentials = {
  clientId?: string;
  clientSecret?: string;
  refreshToken?: string;
  accessToken?: string;
};

export type InboxCredentialPayload = {
  username: string;
  password?: string;
  accessToken?: string;
  oauth2?: InboxOAuthCredentials;
  dkimPrivateKey?: string;
};

function normalizeMailHost(rawHost: string | null): string {
  if (rawHost === null) return "-";
  const trimmed = rawHost.trim().replace(/\.$/, "").toLowerCase();
  if (
    !trimmed ||
    trimmed.length > 253 ||
    /[\s\u0000-\u001f\u007f/%\\]/.test(trimmed)
  ) {
    throw new Error("Inbox credential host is invalid");
  }
  if (isIP(trimmed)) return trimmed;
  const ascii = domainToASCII(trimmed);
  if (
    !ascii ||
    !ascii.split(".").every(
      (label) =>
        label.length >= 1 &&
        label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  ) {
    throw new Error("Inbox credential host is invalid");
  }
  return ascii;
}

export function createInboxCredentialBinding(input: {
  smtpHost: string;
  imapHost: string | null;
}): string {
  return `oiv-inbox-v1|smtp=${normalizeMailHost(input.smtpHost)}|imap=${normalizeMailHost(input.imapHost)}`;
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function boundedSecret(
  value: unknown,
  maximumBytes = MAX_SECRET_BYTES,
): string | undefined {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") > maximumBytes ||
    value.includes("\u0000")
  ) {
    return undefined;
  }
  return value;
}

export function parseInboxCredentialPayload(raw: string): InboxCredentialPayload {
  try {
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("invalid");
    }
    const record = value as Record<string, unknown>;
    if (
      !exactKeys(record, [
        "username",
        "password",
        "accessToken",
        "oauth2",
        "dkimPrivateKey",
      ])
    ) {
      throw new Error("invalid");
    }
    const username =
      typeof record.username === "string" ? record.username.trim() : "";
    if (
      !username ||
      username.length > 320 ||
      /[\r\n\u0000]/.test(username)
    ) {
      throw new Error("invalid");
    }
    const password =
      record.password === undefined ? undefined : boundedSecret(record.password);
    const accessToken =
      record.accessToken === undefined
        ? undefined
        : boundedSecret(record.accessToken);
    if (
      (record.password !== undefined && !password) ||
      (record.accessToken !== undefined && !accessToken)
    ) {
      throw new Error("invalid");
    }

    let oauth2: InboxOAuthCredentials | undefined;
    if (record.oauth2 !== undefined) {
      if (
        !record.oauth2 ||
        typeof record.oauth2 !== "object" ||
        Array.isArray(record.oauth2)
      ) {
        throw new Error("invalid");
      }
      const oauthRecord = record.oauth2 as Record<string, unknown>;
      if (
        !exactKeys(oauthRecord, [
          "clientId",
          "clientSecret",
          "refreshToken",
          "accessToken",
        ])
      ) {
        throw new Error("invalid");
      }
      oauth2 = {};
      for (const field of [
        "clientId",
        "clientSecret",
        "refreshToken",
        "accessToken",
      ] as const) {
        if (oauthRecord[field] !== undefined) {
          const secret = boundedSecret(oauthRecord[field]);
          if (!secret) throw new Error("invalid");
          oauth2[field] = secret;
        }
      }
      const hasRefreshGrant = Boolean(
        oauth2.clientId && oauth2.clientSecret && oauth2.refreshToken,
      );
      if (!oauth2.accessToken && !hasRefreshGrant) throw new Error("invalid");
    }

    const dkimPrivateKey =
      record.dkimPrivateKey === undefined
        ? undefined
        : boundedSecret(record.dkimPrivateKey, MAX_DKIM_KEY_BYTES);
    if (
      record.dkimPrivateKey !== undefined &&
      (!dkimPrivateKey ||
        !/^-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+-----END (?:RSA )?PRIVATE KEY-----\s*$/.test(
          dkimPrivateKey,
        ))
    ) {
      throw new Error("invalid");
    }
    if (!password && !accessToken && !oauth2) throw new Error("invalid");
    return { username, password, accessToken, oauth2, dkimPrivateKey };
  } catch {
    throw new Error("Inbox credentials are invalid");
  }
}
