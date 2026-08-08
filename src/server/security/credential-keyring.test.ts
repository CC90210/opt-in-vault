import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { parseCredentialEncryptionKeyRing } from "./credential-keyring";

const key = (byte: number) => Buffer.alloc(32, byte).toString("base64");

describe("credential encryption key-ring configuration", () => {
  it("merges historical keys with the current key and defaults its version to 1", () => {
    const ring = parseCredentialEncryptionKeyRing({
      CREDENTIAL_ENCRYPTION_KEYS_JSON: JSON.stringify({ 2: key(2), 3: key(3) }),
      CREDENTIAL_ENCRYPTION_KEY: key(1),
    });

    expect([...ring.keys()]).toEqual(["2", "3", "1"]);
    expect(ring.get("1")).toEqual(Buffer.alloc(32, 1));
  });

  it("lets the current value replace the same historical version", () => {
    const ring = parseCredentialEncryptionKeyRing({
      CREDENTIAL_ENCRYPTION_KEYS_JSON: JSON.stringify({ 7: key(6) }),
      CREDENTIAL_ENCRYPTION_KEY: key(7),
      CREDENTIAL_ENCRYPTION_KEY_VERSION: "7",
    });
    expect(ring.get("7")).toEqual(Buffer.alloc(32, 7));
  });

  it.each([
    {},
    { CREDENTIAL_ENCRYPTION_KEYS_JSON: "[]" },
    { CREDENTIAL_ENCRYPTION_KEYS_JSON: "not-json" },
    { CREDENTIAL_ENCRYPTION_KEYS_JSON: JSON.stringify({ 0: key(1) }) },
    { CREDENTIAL_ENCRYPTION_KEYS_JSON: JSON.stringify({ 1: "weak" }) },
    {
      CREDENTIAL_ENCRYPTION_KEYS_JSON: JSON.stringify(
        Object.fromEntries(Array.from({ length: 9 }, (_, index) => [index + 1, key(index)])),
      ),
    },
    {
      CREDENTIAL_ENCRYPTION_KEY: key(1),
      CREDENTIAL_ENCRYPTION_KEY_VERSION: "not-a-version",
    },
  ])("fails closed on absent or malformed configuration", (environment) => {
    expect(() => parseCredentialEncryptionKeyRing(environment)).toThrow(
      /credential encryption key/i,
    );
  });
});
