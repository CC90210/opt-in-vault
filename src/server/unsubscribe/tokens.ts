import "server-only";

import { createHmac, randomBytes } from "node:crypto";

const TOKEN_PREFIX = "ouv_unsub_";
const TOKEN_PATTERN = /^ouv_unsub_[A-Za-z0-9_-]{43}$/;

function requireSecret(secret: string): void {
  if (Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error("Unsubscribe token secret must contain at least 32 bytes");
  }
}

export function createUnsubscribeToken(): string {
  return `${TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;
}

export function isUnsubscribeTokenShape(token: string): boolean {
  return TOKEN_PATTERN.test(token);
}

export function hashUnsubscribeToken(token: string, secret: string): string {
  requireSecret(secret);
  if (!isUnsubscribeTokenShape(token)) {
    throw new Error("Invalid unsubscribe token");
  }
  return createHmac("sha256", secret)
    .update("opt-in-vault:unsubscribe:v1\0")
    .update(token)
    .digest("hex");
}
