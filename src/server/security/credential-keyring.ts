import "server-only";

import {
  MAX_ENCRYPTION_KEY_VERSIONS,
  parseEncryptionKey,
} from "./encryption";

const MAX_KEY_RING_JSON_LENGTH = 32_768;
const VERSION_PATTERN = /^[1-9]\d{0,9}$/;

function requireVersion(raw: string): string {
  if (!VERSION_PATTERN.test(raw)) {
    throw new Error("Invalid version");
  }
  const version = Number(raw);
  if (!Number.isSafeInteger(version) || version > 2_147_483_647) {
    throw new Error("Invalid version");
  }
  return String(version);
}

/**
 * Parses the bounded credential decryption key ring used by HTTP and CLI workers.
 * Any malformed member invalidates the entire ring so rotation never silently
 * drops a historical key and strands stored credentials.
 */
export function parseCredentialEncryptionKeyRing(
  environment: Readonly<Record<string, string | undefined>>,
): ReadonlyMap<string, Buffer> {
  try {
    const currentValue = environment.CREDENTIAL_ENCRYPTION_KEY;
    if (!currentValue) throw new Error("Missing current key");

    const keys = new Map<string, Buffer>();
    const historical = environment.CREDENTIAL_ENCRYPTION_KEYS_JSON;
    if (historical !== undefined) {
      if (historical.length === 0 || historical.length > MAX_KEY_RING_JSON_LENGTH) {
        throw new Error("Invalid historical keys");
      }
      const parsed: unknown = JSON.parse(historical);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Invalid historical keys");
      }
      for (const [rawVersion, rawKey] of Object.entries(parsed)) {
        if (typeof rawKey !== "string") throw new Error("Invalid historical key");
        keys.set(requireVersion(rawVersion), parseEncryptionKey(rawKey));
      }
    }

    const currentVersion = requireVersion(
      environment.CREDENTIAL_ENCRYPTION_KEY_VERSION ?? "1",
    );
    keys.set(currentVersion, parseEncryptionKey(currentValue));
    if (keys.size === 0 || keys.size > MAX_ENCRYPTION_KEY_VERSIONS) {
      throw new Error("Credential key ring is outside its bound");
    }
    return keys;
  } catch {
    throw new Error("Credential encryption key configuration is invalid");
  }
}
