import { generateKeyPairSync } from "node:crypto";

import { DNS_FRESHNESS_MS } from "@/server/dns/freshness";

import {
  assertLocalDkimKeyMatchesDns,
  LocalDkimVerificationError,
  type LocalDkimDnsSnapshot,
} from "./dkim-key-match";

const NOW = 1_800_000_000_000;

function rsaFixture() {
  const pair = generateKeyPairSync("rsa", { modulusLength: 1_024 });
  return {
    privateKey: pair.privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString(),
    publicKey: pair.publicKey
      .export({ format: "der", type: "spki" })
      .toString("base64"),
  };
}

function snapshot(
  publicKey: string,
  overrides: Partial<LocalDkimDnsSnapshot> = {},
): LocalDkimDnsSnapshot {
  return {
    domainLastDnsCheckAt: NOW,
    dnsCheckAt: NOW,
    dnsCheckStatus: "healthy",
    dnsCheckDkimStatus: "present_local_key",
    dnsCheckErrorCode: null,
    dnsCheckRecordsJson: JSON.stringify({
      alignment: "records_present_not_message_verified",
      sendReady: true,
      source: {
        sendingDomain: "example.com",
        dkimSelector: "outbound",
        dkimMode: "local",
      },
      records: {
        spf: [],
        dkim: [`v=DKIM1; k=rsa; p=${publicKey}`],
        dmarc: [],
        mx: [],
      },
    }),
    ...overrides,
  };
}

function snapshotWithDkimRecord(
  publicKey: string,
  dkimRecord: string,
): LocalDkimDnsSnapshot {
  const base = snapshot(publicKey);
  const document = JSON.parse(base.dnsCheckRecordsJson!) as {
    records: { dkim: string[] };
  };
  document.records.dkim = [dkimRecord];
  return { ...base, dnsCheckRecordsJson: JSON.stringify(document) };
}

describe("local DKIM key ownership gate", () => {
  it("accepts a fresh DNS snapshot whose normalized RSA SPKI matches the private key", () => {
    const key = rsaFixture();

    expect(() =>
      assertLocalDkimKeyMatchesDns({
        privateKey: key.privateKey,
        sendingDomain: "example.com",
        dkimSelector: "outbound",
        snapshot: snapshot(key.publicKey),
        now: NOW,
      }),
    ).not.toThrow();
  });

  it("fails closed when DNS contains a different RSA public key", () => {
    const configured = rsaFixture();
    const published = rsaFixture();

    expect(() =>
      assertLocalDkimKeyMatchesDns({
        privateKey: configured.privateKey,
        sendingDomain: "example.com",
        dkimSelector: "outbound",
        snapshot: snapshot(published.publicKey),
        now: NOW,
      }),
    ).toThrow(expect.objectContaining({ code: "local_dkim_key_mismatch" }));
  });

  it.each([
    ["h=sha1", (key: string) => `v=DKIM1; h=sha1; k=rsa; p=${key}`],
    ["s=other", (key: string) => `v=DKIM1; s=other; k=rsa; p=${key}`],
    [
      "duplicate tags",
      (key: string) => `v=DKIM1; h=sha256; h=sha256; k=rsa; p=${key}`,
    ],
    [
      "an empty colon-list item",
      (key: string) => `v=DKIM1; s=other::email; k=rsa; p=${key}`,
    ],
  ])("rejects %s in the live DNS key matcher", (_name, recordFor) => {
    const key = rsaFixture();

    expect(() =>
      assertLocalDkimKeyMatchesDns({
        privateKey: key.privateKey,
        sendingDomain: "example.com",
        dkimSelector: "outbound",
        snapshot: snapshotWithDkimRecord(key.publicKey, recordFor(key.publicKey)),
        now: NOW,
      }),
    ).toThrow(expect.objectContaining({ code: "local_dkim_dns_record_invalid" }));
  });

  it.each([
    [
      "h=sha1:sha256",
      (key: string) => `v=DKIM1; h=SHA1 : SHA256; k=rsa; p=${key}`,
    ],
    [
      "s=other:email",
      (key: string) => `v=DKIM1; s=other : EMAIL; k=rsa; p=${key}`,
    ],
  ])("accepts %s in the live DNS key matcher", (_name, recordFor) => {
    const key = rsaFixture();

    expect(() =>
      assertLocalDkimKeyMatchesDns({
        privateKey: key.privateKey,
        sendingDomain: "example.com",
        dkimSelector: "outbound",
        snapshot: snapshotWithDkimRecord(key.publicKey, recordFor(key.publicKey)),
        now: NOW,
      }),
    ).not.toThrow();
  });

  it("rejects stale, mismatched, and unhealthy DNS snapshots", () => {
    const key = rsaFixture();
    const staleAt = NOW - DNS_FRESHNESS_MS - 1;
    const cases: Array<[LocalDkimDnsSnapshot, string]> = [
      [
        snapshot(key.publicKey, {
          domainLastDnsCheckAt: staleAt,
          dnsCheckAt: staleAt,
        }),
        "local_dkim_dns_stale",
      ],
      [
        snapshot(key.publicKey, { dnsCheckAt: NOW - 1 }),
        "local_dkim_dns_snapshot_invalid",
      ],
      [
        snapshot(key.publicKey, {
          dnsCheckStatus: "error",
          dnsCheckErrorCode: "dns_timeout",
        }),
        "local_dkim_dns_unhealthy",
      ],
    ];

    for (const [dnsSnapshot, code] of cases) {
      expect(() =>
        assertLocalDkimKeyMatchesDns({
          privateKey: key.privateKey,
          sendingDomain: "example.com",
          dkimSelector: "outbound",
          snapshot: dnsSnapshot,
          now: NOW,
        }),
      ).toThrow(expect.objectContaining({ code }));
    }
  });

  it("rejects unsupported or malformed keys without exposing key material", () => {
    const key = rsaFixture();
    const secretMarker = "PRIVATE-KEY-SECRET-MARKER";
    const cases: Array<[string, LocalDkimDnsSnapshot, string]> = [
      [
        key.privateKey,
        snapshot(key.publicKey, {
          dnsCheckRecordsJson: JSON.stringify({
            source: {
              sendingDomain: "example.com",
              dkimSelector: "outbound",
              dkimMode: "local",
            },
            records: { dkim: [`v=DKIM1; k=ed25519; p=${"A".repeat(43)}`] },
          }),
        }),
        "local_dkim_public_key_unsupported",
      ],
      [
        secretMarker,
        snapshot(key.publicKey),
        "local_dkim_private_key_invalid",
      ],
    ];

    for (const [privateKey, dnsSnapshot, code] of cases) {
      let captured: unknown;
      try {
        assertLocalDkimKeyMatchesDns({
          privateKey,
          sendingDomain: "example.com",
          dkimSelector: "outbound",
          snapshot: dnsSnapshot,
          now: NOW,
        });
      } catch (error) {
        captured = error;
      }
      expect(captured).toBeInstanceOf(LocalDkimVerificationError);
      expect(captured).toMatchObject({ code });
      expect(String(captured)).not.toContain(secretMarker);
      expect(String(captured)).not.toContain(key.privateKey.slice(0, 32));
      expect(JSON.stringify(captured)).not.toContain(secretMarker);
    }
  });
});
