import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import {
  decryptSecret,
  decryptSecretWithKeyRing,
  encryptSecret,
  MAX_SECRET_PLAINTEXT_BYTES,
  parseEncryptionKey,
  type SecretAad,
} from "./encryption";

const hexKey = "11".repeat(32);
const base64Key = Buffer.alloc(32, 7).toString("base64");
const aad: SecretAad = {
  tenantId: "tenant_01",
  resourceType: "sending_inbox",
  resourceId: "inbox_01",
  field: "smtp_password",
  provider: "smtp",
  host: "smtp.example.com",
};

describe("secret encryption", () => {
  it("parses exactly 32-byte hexadecimal or base64 keys", () => {
    expect(parseEncryptionKey(hexKey)).toHaveLength(32);
    expect(parseEncryptionKey(base64Key)).toHaveLength(32);
    expect(() => parseEncryptionKey("aa".repeat(31))).toThrow(/32 bytes/i);
    expect(() => parseEncryptionKey("not valid base64!!")).toThrow(/key/i);
  });

  it("round trips through a versioned AES-256-GCM envelope with unique nonces", () => {
    const key = parseEncryptionKey(hexKey);
    const envelope = encryptSecret("smtp-super-secret", key, aad, "key-2026-08");
    const second = encryptSecret("smtp-super-secret", key, aad, "key-2026-08");
    const parsed = JSON.parse(envelope);

    expect(parsed).toMatchObject({ v: 1, kid: "key-2026-08" });
    expect(parsed).toHaveProperty("iv");
    expect(parsed).toHaveProperty("tag");
    expect(parsed).toHaveProperty("ciphertext");
    expect(envelope).not.toContain("smtp-super-secret");
    expect(second).not.toBe(envelope);
    expect(decryptSecret(envelope, key, aad)).toEqual({
      plaintext: "smtp-super-secret",
      keyVersion: "key-2026-08",
    });
  });

  it("rejects ciphertext tampering and different associated data", () => {
    const key = parseEncryptionKey(hexKey);
    const envelope = encryptSecret("secret", key, aad);
    const parsed = JSON.parse(envelope);
    parsed.ciphertext = `${parsed.ciphertext.slice(0, -1)}${
      parsed.ciphertext.endsWith("a") ? "b" : "a"
    }`;

    expect(() => decryptSecret(JSON.stringify(parsed), key, aad)).toThrow(/decrypt/i);
    expect(() =>
      decryptSecret(envelope, key, { ...aad, field: "imap_password" }),
    ).toThrow(/decrypt/i);
    expect(() =>
      decryptSecret(envelope, key, { ...aad, tenantId: "tenant_02" }),
    ).toThrow(/decrypt/i);
  });

  it("authenticates the key-version label and rejects non-canonical envelope encoding", () => {
    const key = parseEncryptionKey(hexKey);
    const envelope = encryptSecret("secret", key, aad, "key-2026-08");
    const changedVersion = JSON.parse(envelope);
    changedVersion.kid = "key-2026-09";
    expect(() => decryptSecret(JSON.stringify(changedVersion), key, aad)).toThrow(/decrypt/i);

    const aliasedTag = JSON.parse(envelope);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const lastIndex = alphabet.indexOf(aliasedTag.tag.at(-1));
    aliasedTag.tag = `${aliasedTag.tag.slice(0, -1)}${alphabet[lastIndex + 1]}`;
    expect(Buffer.from(aliasedTag.tag, "base64url")).toEqual(
      Buffer.from(JSON.parse(envelope).tag, "base64url"),
    );
    expect(() => decryptSecret(JSON.stringify(aliasedTag), key, aad)).toThrow(/decrypt/i);
  });

  it("selects a bounded key ring by kid and authenticates that kid through GCM", () => {
    const oldKey = parseEncryptionKey(hexKey);
    const currentKey = parseEncryptionKey("22".repeat(32));
    const envelope = encryptSecret("rotated-secret", oldKey, aad, "key-old");
    const ring = new Map([
      ["key-current", currentKey],
      ["key-old", oldKey],
    ]);

    expect(decryptSecretWithKeyRing(envelope, ring, aad)).toEqual({
      plaintext: "rotated-secret",
      keyVersion: "key-old",
    });

    const changedKid = JSON.parse(envelope);
    changedKid.kid = "key-current";
    expect(() => decryptSecretWithKeyRing(JSON.stringify(changedKid), ring, aad)).toThrow(
      /decrypt/i,
    );
    expect(() =>
      decryptSecretWithKeyRing(envelope, new Map([["key-current", currentKey]]), aad),
    ).toThrow(/decrypt/i);
    expect(() =>
      decryptSecretWithKeyRing(
        envelope,
        new Map(
          Array.from({ length: 9 }, (_, index) => [
            `key-${index}`,
            parseEncryptionKey(`${index + 1}`.repeat(64)),
          ]),
        ),
        aad,
      ),
    ).toThrow(/decrypt/i);
  });

  it("requires provider and host binding for sending-inbox credentials", () => {
    const key = parseEncryptionKey(hexKey);
    const incomplete = {
      tenantId: "tenant_01",
      resourceType: "sending_inbox",
      resourceId: "inbox_01",
      field: "credentials",
    } as SecretAad;

    expect(() => encryptSecret("secret", key, incomplete)).toThrow(/provider/i);
  });

  it("rejects oversized plaintext before emitting an undecryptable envelope", () => {
    const key = parseEncryptionKey(hexKey);
    const maximum = "x".repeat(MAX_SECRET_PLAINTEXT_BYTES);
    const envelope = encryptSecret(maximum, key, aad);

    expect(decryptSecret(envelope, key, aad).plaintext).toBe(maximum);
    expect(() => encryptSecret(`${maximum}x`, key, aad)).toThrow(/large/i);
  });
});
