import "server-only";

import type { EncryptionKeyRing } from "@/server/security/encryption";
import { decryptSecretWithKeyRing } from "@/server/security/encryption";

import { createGatewayTransport, type GatewayTransport } from "./gateway";
import {
  createInboxCredentialBinding,
  parseInboxCredentialPayload,
} from "./inbox-credentials";
import type { InboxTransportConfiguration } from "./nodemailer-transport";
import {
  assertOAuthProviderHost,
  OAuthAccessTokenError,
  resolveOAuthAccessToken,
  type OAuthFetch,
} from "./oauth-refresh";

export type ConfiguredTransportContext = {
  tenantId: string;
  inboxId: string;
  provider: "smtp" | "google" | "microsoft";
  smtpHost: string;
  smtpPort: number;
  smtpSecure: boolean;
  imapHost: string | null;
  encryptedCredentials: Buffer;
  credentialKeyVersion: number;
  credentialBinding: string;
  fromAddress: string;
  sendingDomain: string;
  dkimMode: "provider" | "local";
  dkimSelector: string | null;
};

export class TransportConfigurationError extends Error {
  readonly code: string;

  constructor(code: string) {
    super("Inbox transport configuration is invalid");
    this.name = "TransportConfigurationError";
    this.code = code;
  }
}

export async function createConfiguredGatewayTransport(
  context: ConfiguredTransportContext,
  options: {
    credentialKeys: EncryptionKeyRing;
    fetchImpl?: OAuthFetch;
    gatewayFactory?: (
      configuration: InboxTransportConfiguration,
    ) => Promise<GatewayTransport>;
  },
): Promise<GatewayTransport> {
  try {
    if (context.dkimMode !== "local") {
      throw new TransportConfigurationError(
        "rfc8058_dkim_signing_unverified",
      );
    }
    if (context.provider === "google" || context.provider === "microsoft") {
      assertOAuthProviderHost(context.provider, "smtp", context.smtpHost);
      if (context.imapHost !== null) {
        assertOAuthProviderHost(context.provider, "imap", context.imapHost);
      }
    }
    const expectedBinding = createInboxCredentialBinding({
      smtpHost: context.smtpHost,
      imapHost: context.imapHost,
    });
    if (context.credentialBinding !== expectedBinding) {
      throw new TransportConfigurationError("credential_binding_mismatch");
    }
    if (
      !Number.isSafeInteger(context.credentialKeyVersion) ||
      context.credentialKeyVersion < 1 ||
      !Buffer.isBuffer(context.encryptedCredentials)
    ) {
      throw new TransportConfigurationError("credential_envelope_invalid");
    }
    const decrypted = decryptSecretWithKeyRing(
      context.encryptedCredentials.toString("utf8"),
      options.credentialKeys,
      {
        tenantId: context.tenantId,
        resourceType: "sending_inbox",
        resourceId: context.inboxId,
        field: "credentials",
        provider: context.provider,
        host: context.credentialBinding,
      },
    );
    if (decrypted.keyVersion !== String(context.credentialKeyVersion)) {
      throw new TransportConfigurationError("credential_version_mismatch");
    }
    const credentials = parseInboxCredentialPayload(decrypted.plaintext);
    const sendingDomain = context.sendingDomain.trim().toLowerCase();
    const fromDomain = context.fromAddress.trim().toLowerCase().split("@")[1];
    if (
      !fromDomain ||
      fromDomain !== sendingDomain ||
      sendingDomain.length > 253 ||
      !sendingDomain.split(".").every(
        (label) =>
          label.length >= 1 &&
          label.length <= 63 &&
          /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
      )
    ) {
      throw new TransportConfigurationError("from_domain_mismatch");
    }
    let configuration: InboxTransportConfiguration;
    if (context.provider === "smtp") {
      if (!credentials.password) {
        throw new TransportConfigurationError("smtp_password_missing");
      }
      configuration = {
        provider: context.provider,
        host: context.smtpHost,
        port: context.smtpPort,
        secure: context.smtpSecure,
        username: credentials.username,
        password: credentials.password,
      };
    } else {
      const storedOAuth = credentials.oauth2 ??
        (credentials.accessToken
          ? { accessToken: credentials.accessToken }
          : undefined);
      if (!storedOAuth) {
        throw new TransportConfigurationError("oauth_credentials_missing");
      }
      const accessToken = await resolveOAuthAccessToken({
        provider: context.provider,
        purpose: "smtp",
        credentials: storedOAuth,
        fetchImpl: options.fetchImpl,
      });
      configuration = {
        provider: context.provider,
        host: context.smtpHost,
        port: context.smtpPort,
        secure: context.smtpSecure,
        username: credentials.username,
        oauth2: { accessToken },
      };
    }

    if (
      !context.dkimSelector ||
      !/^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/.test(context.dkimSelector) ||
      !credentials.dkimPrivateKey
    ) {
      throw new TransportConfigurationError("local_dkim_material_missing");
    }
    configuration.dkim = {
      domainName: sendingDomain,
      keySelector: context.dkimSelector,
      privateKey: credentials.dkimPrivateKey,
    };
    return await (options.gatewayFactory ?? createGatewayTransport)(configuration);
  } catch (error) {
    if (error instanceof TransportConfigurationError) throw error;
    if (error instanceof OAuthAccessTokenError) {
      throw new TransportConfigurationError(error.code);
    }
    throw new TransportConfigurationError("transport_configuration_invalid");
  }
}
