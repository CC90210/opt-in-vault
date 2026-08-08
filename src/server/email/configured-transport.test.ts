import { generateKeyPairSync } from "node:crypto";

import { encryptSecret } from "@/server/security/encryption";

import type { GatewayTransport } from "./gateway";
import {
  createConfiguredGatewayTransport,
  type ConfiguredTransportContext,
} from "./configured-transport";
import { createInboxCredentialBinding } from "./inbox-credentials";

const KEY = Buffer.alloc(32, 7);
const TEST_DNS_CHECK_AT = Date.now();
const TEST_DKIM_KEY_PAIR = generateKeyPairSync("rsa", { modulusLength: 1_024 });
const TEST_DKIM_PRIVATE_KEY = TEST_DKIM_KEY_PAIR.privateKey
  .export({ format: "pem", type: "pkcs8" })
  .toString();
const TEST_DKIM_PUBLIC_KEY = TEST_DKIM_KEY_PAIR.publicKey
  .export({ format: "der", type: "spki" })
  .toString("base64");

function context(
  overrides: Partial<ConfiguredTransportContext> = {},
  credentialOverrides: Record<string, unknown> = {},
): ConfiguredTransportContext {
  const provider = overrides.provider ?? "smtp";
  const smtpHost = overrides.smtpHost ?? "smtp.example.com";
  const imapHost = overrides.imapHost ?? "imap.example.com";
  const binding = createInboxCredentialBinding({
    smtpHost,
    imapHost,
  });
  const payload = JSON.stringify({
    username: "sender@example.com",
    password: "smtp-password",
    dkimPrivateKey: TEST_DKIM_PRIVATE_KEY,
    ...credentialOverrides,
  });
  const encrypted = encryptSecret(payload, KEY, {
    tenantId: "tenant-1",
    resourceType: "sending_inbox",
    resourceId: "inbox-1",
    field: "credentials",
    provider,
    host: binding,
  }, "2");
  return {
    tenantId: "tenant-1",
    inboxId: "inbox-1",
    provider,
    smtpHost,
    smtpPort: 465,
    smtpSecure: true,
    imapHost,
    encryptedCredentials: Buffer.from(encrypted, "utf8"),
    credentialKeyVersion: 2,
    credentialBinding: binding,
    fromAddress: "sender@example.com",
    sendingDomain: "example.com",
    domainLastDnsCheckAt: TEST_DNS_CHECK_AT,
    domainDnsCheckAt: TEST_DNS_CHECK_AT,
    domainDnsCheckStatus: "healthy",
    domainDnsCheckDkimStatus: "present_local_key",
    domainDnsCheckErrorCode: null,
    domainDnsCheckRecordsJson: JSON.stringify({
      alignment: "records_present_not_message_verified",
      sendReady: true,
      source: {
        sendingDomain: "example.com",
        dkimSelector: "outbound",
        dkimMode: "local",
      },
      records: {
        spf: [],
        dkim: [`v=DKIM1; k=rsa; p=${TEST_DKIM_PUBLIC_KEY}`],
        dmarc: [],
        mx: [],
      },
    }),
    dkimMode: "local",
    dkimSelector: "outbound",
    ...overrides,
  };
}

describe("configured inbox transport", () => {
  it("decrypts tenant-bound credentials and passes local DKIM to the gateway factory", async () => {
    const transport: GatewayTransport = { sendMail: vi.fn() };
    const gatewayFactory = vi.fn().mockResolvedValue(transport);

    await expect(
      createConfiguredGatewayTransport(context(), {
        credentialKeys: new Map([["2", KEY]]),
        gatewayFactory,
      }),
    ).resolves.toBe(transport);
    expect(gatewayFactory).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: "smtp",
        host: "smtp.example.com",
        username: "sender@example.com",
        password: "smtp-password",
        dkim: expect.objectContaining({
          domainName: "example.com",
          keySelector: "outbound",
        }),
      }),
    );
  });

  it("rejects a DNS/private-key mismatch before OAuth refresh or transport creation", async () => {
    const published = generateKeyPairSync("rsa", { modulusLength: 1_024 });
    const publishedPublicKey = published.publicKey
      .export({ format: "der", type: "spki" })
      .toString("base64");
    const fetchImpl = vi.fn();
    const gatewayFactory = vi.fn();

    await expect(
      createConfiguredGatewayTransport(
        context(
          {
            provider: "google",
            smtpHost: "smtp.gmail.com",
            imapHost: "imap.gmail.com",
            domainDnsCheckRecordsJson: JSON.stringify({
              source: {
                sendingDomain: "example.com",
                dkimSelector: "outbound",
                dkimMode: "local",
              },
              records: {
                dkim: [`v=DKIM1; k=rsa; p=${publishedPublicKey}`],
              },
            }),
          },
          {
            password: undefined,
            oauth2: {
              clientId: "client-id",
              clientSecret: "client-secret",
              refreshToken: "refresh-token",
            },
          },
        ),
        {
          credentialKeys: new Map([["2", KEY]]),
          gatewayFactory,
          fetchImpl,
        },
      ),
    ).rejects.toMatchObject({ code: "local_dkim_key_mismatch" });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(gatewayFactory).not.toHaveBeenCalled();
  });

  it("fails closed when the stored binding does not match the actual endpoints", async () => {
    const originalBinding = createInboxCredentialBinding({
      smtpHost: "smtp.example.com",
      imapHost: "imap.example.com",
    });
    await expect(
      createConfiguredGatewayTransport(
        context({
          smtpHost: "attacker.example.net",
          credentialBinding: originalBinding,
        }),
        {
          credentialKeys: new Map([["2", KEY]]),
          gatewayFactory: vi.fn(),
        },
      ),
    ).rejects.toMatchObject({ code: "credential_binding_mismatch" });
  });

  it.each([
    ["google", "https://oauth2.googleapis.com/token"],
    [
      "microsoft",
      "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    ],
  ] as const)(
    "refreshes %s OAuth with a bounded request before creating the SMTP transport",
    async (provider, expectedEndpoint) => {
      const transport: GatewayTransport = { sendMail: vi.fn() };
      const gatewayFactory = vi.fn().mockResolvedValue(transport);
      const fetchImpl = vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ access_token: "fresh-access-token" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
      const oauthContext = context(
        {
          provider,
          smtpHost:
            provider === "google"
              ? "smtp.gmail.com"
              : "smtp.office365.com",
          imapHost:
            provider === "google"
              ? "imap.gmail.com"
              : "outlook.office365.com",
          dkimMode: "local",
          dkimSelector: "outbound",
        },
        {
          password: undefined,
          oauth2: {
            clientId: "client-id",
            clientSecret: "client-secret",
            refreshToken: "refresh-token",
          },
        },
      );

      await expect(
        createConfiguredGatewayTransport(oauthContext, {
          credentialKeys: new Map([["2", KEY]]),
          gatewayFactory,
          fetchImpl,
        }),
      ).resolves.toBe(transport);

      expect(fetchImpl).toHaveBeenCalledTimes(1);
      const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(expectedEndpoint);
      expect(init.method).toBe("POST");
      expect(init.redirect).toBe("error");
      expect(init.signal).toBeInstanceOf(AbortSignal);
      const body = new URLSearchParams(init.body as string);
      expect(body.get("grant_type")).toBe("refresh_token");
      expect(body.get("client_id")).toBe("client-id");
      expect(body.get("client_secret")).toBe("client-secret");
      expect(body.get("refresh_token")).toBe("refresh-token");
      if (provider === "microsoft") {
        expect(body.get("scope")).toBe(
          "https://outlook.office.com/SMTP.Send offline_access",
        );
      } else {
        expect(body.has("scope")).toBe(false);
      }
      expect(gatewayFactory).toHaveBeenCalledWith(
        expect.objectContaining({
          provider,
          oauth2: { accessToken: "fresh-access-token" },
        }),
      );
    },
  );

  it("fails closed on oversized OAuth responses without creating a transport", async () => {
    const gatewayFactory = vi.fn();
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response("x", {
        status: 200,
        headers: { "content-length": "65537" },
      }),
    );
    const oauthContext = context(
      {
        provider: "google",
        smtpHost: "smtp.gmail.com",
        imapHost: "imap.gmail.com",
        dkimMode: "local",
        dkimSelector: "outbound",
      },
      {
        password: undefined,
        oauth2: {
          clientId: "client-id",
          clientSecret: "client-secret",
          refreshToken: "refresh-token",
        },
      },
    );

    await expect(
      createConfiguredGatewayTransport(oauthContext, {
        credentialKeys: new Map([["2", KEY]]),
        gatewayFactory,
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: "oauth_refresh_failed" });
    expect(gatewayFactory).not.toHaveBeenCalled();
  });

  it.each([
    ["google", "smtp.attacker.example", "imap.gmail.com"],
    ["google", "smtp.gmail.com", "imap.attacker.example"],
    ["microsoft", "smtp.attacker.example", "outlook.office365.com"],
    ["microsoft", "smtp.office365.com", "imap.attacker.example"],
  ] as const)(
    "rejects non-provider %s mail hosts before refresh or transport creation",
    async (provider, smtpHost, imapHost) => {
      const fetchImpl = vi.fn();
      const gatewayFactory = vi.fn();
      const oauthContext = context(
        { provider, smtpHost, imapHost },
        {
          password: undefined,
          oauth2: {
            clientId: "client-id",
            clientSecret: "client-secret",
            refreshToken: "refresh-token",
          },
        },
      );

      await expect(
        createConfiguredGatewayTransport(oauthContext, {
          credentialKeys: new Map([["2", KEY]]),
          gatewayFactory,
          fetchImpl,
        }),
      ).rejects.toMatchObject({ code: "oauth_provider_host_invalid" });
      expect(fetchImpl).not.toHaveBeenCalled();
      expect(gatewayFactory).not.toHaveBeenCalled();
    },
  );

  it("refuses provider-managed DKIM because one-click header coverage is unverified", async () => {
    const fetchImpl = vi.fn();
    const gatewayFactory = vi.fn();

    await expect(
      createConfiguredGatewayTransport(
        context(
          {
            provider: "google",
            smtpHost: "smtp.gmail.com",
            imapHost: "imap.gmail.com",
            dkimMode: "provider",
            dkimSelector: null,
          },
          {
            password: undefined,
            oauth2: {
              clientId: "client-id",
              clientSecret: "client-secret",
              refreshToken: "refresh-token",
            },
          },
        ),
        {
          credentialKeys: new Map([["2", KEY]]),
          gatewayFactory,
          fetchImpl,
        },
      ),
    ).rejects.toMatchObject({ code: "rfc8058_dkim_signing_unverified" });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(gatewayFactory).not.toHaveBeenCalled();
  });
});
