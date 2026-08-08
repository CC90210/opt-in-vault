import "server-only";

import { createHash, timingSafeEqual } from "node:crypto";

const CRON_SECRET_MIN_BYTES = 32;

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

export function isCronAuthorized(
  authorizationHeader: string | null | undefined,
  configuredSecret: string | null | undefined,
): boolean {
  if (
    !configuredSecret ||
    Buffer.byteLength(configuredSecret, "utf8") < CRON_SECRET_MIN_BYTES ||
    !authorizationHeader ||
    /[\r\n]/.test(authorizationHeader)
  ) {
    return false;
  }

  const match = /^Bearer ([^\s]+)$/i.exec(authorizationHeader);
  if (!match) {
    return false;
  }

  return timingSafeEqual(digest(match[1]), digest(configuredSecret));
}
