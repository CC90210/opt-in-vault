import "server-only";

import type SMTPTransport from "nodemailer/lib/smtp-transport";

type LocalDkim = {
  domainName: string;
  keySelector: string;
  privateKey: string;
};

type OAuthCredentials = {
  clientId?: string;
  clientSecret?: string;
  refreshToken?: string;
  accessToken?: string;
};

export type InboxTransportConfiguration = {
  provider: "smtp" | "google" | "microsoft";
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password?: string;
  oauth2?: OAuthCredentials;
  dkim?: LocalDkim;
  tlsServername?: string;
};

function rejectHeaderControls(value: string, field: string): void {
  if (!value.trim() || /[\r\n\u0000]/.test(value)) {
    throw new Error(`Invalid ${field}`);
  }
}

export function buildNodemailerTransportOptions(
  configuration: InboxTransportConfiguration,
): SMTPTransport.Options {
  rejectHeaderControls(configuration.host, "SMTP host");
  rejectHeaderControls(configuration.username, "SMTP username");
  if (!Number.isInteger(configuration.port) || configuration.port < 1 || configuration.port > 65_535) {
    throw new Error("Invalid SMTP port");
  }
  if (
    (configuration.port !== 465 && configuration.port !== 587) ||
    (configuration.port === 465 && !configuration.secure) ||
    (configuration.port === 587 && configuration.secure)
  ) {
    throw new Error("SMTP must use implicit TLS on 465 or STARTTLS on 587");
  }

  let auth: NonNullable<SMTPTransport.Options["auth"]>;
  if (configuration.provider === "smtp") {
    if (!configuration.password) throw new Error("SMTP password is required");
    auth = { user: configuration.username, pass: configuration.password };
  } else {
    if (!configuration.oauth2?.accessToken) {
      throw new Error("A current OAuth2 access token is required");
    }
    auth = {
      type: "OAuth2",
      user: configuration.username,
      accessToken: configuration.oauth2.accessToken,
    };
  }

  return {
    host: configuration.host,
    port: configuration.port,
    secure: configuration.secure,
    requireTLS: !configuration.secure,
    opportunisticTLS: false,
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 45_000,
    tls: {
      servername: configuration.tlsServername ?? configuration.host,
      minVersion: "TLSv1.2",
      rejectUnauthorized: true,
    },
    auth,
    disableFileAccess: true,
    disableUrlAccess: true,
    dkim: configuration.dkim
      ? {
          domainName: configuration.dkim.domainName,
          keySelector: configuration.dkim.keySelector,
          privateKey: configuration.dkim.privateKey,
          headerFieldNames:
            "from:sender:reply-to:subject:date:message-id:to:cc:mime-version:content-type:list-unsubscribe:list-unsubscribe-post",
        }
      : undefined,
  };
}
