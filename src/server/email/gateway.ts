import "server-only";

import nodemailer from "nodemailer";

import { assertSafeEgressTarget } from "@/server/security/network";
import { validateSubject } from "@/server/templates/render";

import {
  buildNodemailerTransportOptions,
  type InboxTransportConfiguration,
} from "./nodemailer-transport";

export type GatewayMail = {
  from: { address: string; name: string };
  to: string;
  subject: string;
  text: string;
  html?: string;
  messageId: string;
  unsubscribeUrl: string;
  replyTo?: string;
};

export type GatewayMailOptions = Omit<GatewayMail, "unsubscribeUrl"> & {
  headers: {
    "List-Unsubscribe": string;
    "List-Unsubscribe-Post": "List-Unsubscribe=One-Click";
  };
};

export type GatewaySendInfo = {
  messageId?: string;
  accepted?: Array<string | { address?: string }>;
  rejected?: Array<string | { address?: string }>;
  response?: string;
};

export type GatewayTransport = {
  sendMail(message: GatewayMailOptions): Promise<GatewaySendInfo>;
  close?(): void;
};

const DEFAULT_DNS_TIMEOUT_MS = 10_000;
const MAX_DNS_TIMEOUT_MS = 30_000;
const MAX_SEND_DEADLINE_MS = 120_000;

class GatewayDeadlineError extends Error {
  readonly code: string;
  readonly closeError: unknown;

  constructor(code: string, closeError?: unknown) {
    super("The outbound gateway deadline expired");
    this.name = "GatewayDeadlineError";
    this.code = code;
    this.closeError = closeError;
  }
}

function boundedDeadline(value: number, maximum: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${field} is invalid`);
  }
  return value;
}

function withDeadline<T>(
  operation: Promise<T>,
  timeoutMs: number,
  code: string,
  onTimeout?: () => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      let closeError: unknown;
      try {
        onTimeout?.();
      } catch (error) {
        closeError = error;
      }
      reject(new GatewayDeadlineError(code, closeError));
    }, timeoutMs);
    operation.then(
      (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

export async function createGatewayTransport(
  configuration: InboxTransportConfiguration,
  dependencies: {
    resolveTarget?: typeof assertSafeEgressTarget;
    resolveTimeoutMs?: number;
    createTransport?: (
      options: ReturnType<typeof buildNodemailerTransportOptions>,
    ) => GatewayTransport;
  } = {},
): Promise<GatewayTransport> {
  const resolveTimeoutMs = boundedDeadline(
    dependencies.resolveTimeoutMs ?? DEFAULT_DNS_TIMEOUT_MS,
    MAX_DNS_TIMEOUT_MS,
    "SMTP DNS timeout",
  );
  const target = await withDeadline(
    (dependencies.resolveTarget ?? assertSafeEgressTarget)({
      hostname: configuration.host,
      port: configuration.port,
    }),
    resolveTimeoutMs,
    "smtp_dns_timeout",
  );
  const options = buildNodemailerTransportOptions({
    ...configuration,
    host: target.connectionAddress,
    tlsServername: target.tlsServername,
  });
  return dependencies.createTransport
    ? dependencies.createTransport(options)
    : (nodemailer.createTransport(options) as unknown as GatewayTransport);
}

export class DeliveryRejectedError extends Error {
  readonly code: string;

  constructor(code = "provider_rejected") {
    super("The provider definitively rejected the message");
    this.name = "DeliveryRejectedError";
    this.code = code;
  }
}

export class DeliveryUncertainError extends Error {
  readonly code: string;

  constructor(code = "delivery_outcome_unknown") {
    super("The provider delivery outcome is unknown; automatic retry is unsafe");
    this.name = "DeliveryUncertainError";
    this.code = code;
  }
}

function validateAddress(value: string, field: string): string {
  const normalized = value.trim();
  if (
    normalized.length > 320 ||
    /[\r\n\u0000]/.test(normalized) ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)
  ) {
    throw new Error(`Invalid ${field}`);
  }
  return normalized;
}

function validateDisplayName(value: string): string {
  const normalized = value.trim();
  if (
    !normalized ||
    Buffer.byteLength(normalized, "utf8") > 200 ||
    /[\u0000-\u001f\u007f]/.test(normalized)
  ) {
    throw new Error("Invalid sender display name");
  }
  return normalized;
}

function validateBody(value: string, field: string): string {
  if (!value || Buffer.byteLength(value, "utf8") > 256 * 1_024 || value.includes("\u0000")) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function validateUnsubscribeUrl(rawUrl: string): string {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Invalid unsubscribe URL");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new Error("Unsubscribe URL must be a clean HTTPS URL");
  }
  return url.toString();
}

function withVisibleUnsubscribe(
  content: string,
  url: string,
  format: "text" | "html",
): string {
  if (content.includes(url)) return content;
  if (format === "text") return `${content}\n\nUnsubscribe: ${url}`;
  const escaped = url.replaceAll("&", "&amp;").replaceAll('"', "&quot;");
  return `${content}<p><a href="${escaped}">Unsubscribe</a></p>`;
}

function errorCode(error: unknown): string {
  if (!error || typeof error !== "object") return "unknown_transport_error";
  const code = "code" in error ? String(error.code) : "transport_error";
  return /^[A-Za-z0-9_.-]{1,64}$/.test(code) ? code : "transport_error";
}

function isDefinitiveRejection(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const responseCode =
    "responseCode" in error && typeof error.responseCode === "number"
      ? error.responseCode
      : null;
  return responseCode !== null && responseCode >= 400 && responseCode <= 599;
}

function isKnownPreDeliveryFailure(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const record = error as Record<string, unknown>;
  const code = typeof record.code === "string" ? record.code.toUpperCase() : "";
  const command =
    typeof record.command === "string" ? record.command.trim().toUpperCase() : "";
  if (["DATA", "DOT"].includes(command)) return false;
  if (["CONN", "CONNECT", "AUTH", "MAIL FROM", "RCPT TO"].includes(command)) {
    return true;
  }
  return [
    "ECONNECTION",
    "ECONNREFUSED",
    "EDNS",
    "EAI_AGAIN",
    "ENOTFOUND",
    "EAUTH",
    "ETLS",
    "EENVELOPE",
    "EMESSAGE",
  ].includes(code);
}

function providerAddress(
  value: string | { address?: string },
): string | null {
  const address = typeof value === "string" ? value : value.address;
  return typeof address === "string" ? address.trim().toLowerCase() : null;
}

export async function sendViaGateway(
  message: GatewayMail,
  dependencies: {
    liveSendsEnabled: boolean;
    transport: GatewayTransport;
    deadlineMs?: number;
  },
): Promise<
  | { status: "dry_run" }
  | { status: "accepted"; providerMessageId: string | null; response: string | null }
> {
  const fromAddress = validateAddress(message.from.address, "from address");
  const to = validateAddress(message.to, "recipient address");
  const replyTo = message.replyTo
    ? validateAddress(message.replyTo, "reply-to address")
    : undefined;
  const subject = validateSubject(message.subject);
  const unsubscribeUrl = validateUnsubscribeUrl(message.unsubscribeUrl);
  if (
    !/^<[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}>$/.test(
      message.messageId,
    )
  ) {
    throw new Error("Invalid stable Message-ID");
  }
  const text = validateBody(message.text, "text body");
  const html = message.html ? validateBody(message.html, "HTML body") : undefined;

  const outbound: GatewayMailOptions = {
    from: { address: fromAddress, name: validateDisplayName(message.from.name) },
    to,
    subject,
    text: withVisibleUnsubscribe(text, unsubscribeUrl, "text"),
    html: html
      ? withVisibleUnsubscribe(html, unsubscribeUrl, "html")
      : undefined,
    messageId: message.messageId,
    replyTo,
    headers: {
      "List-Unsubscribe": `<${unsubscribeUrl}>`,
      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    },
  };

  if (!dependencies.liveSendsEnabled) return { status: "dry_run" };

  try {
    const deadlineMs = boundedDeadline(
      dependencies.deadlineMs ?? 90_000,
      MAX_SEND_DEADLINE_MS,
      "SMTP send deadline",
    );
    const info = await withDeadline(
      dependencies.transport.sendMail(outbound),
      deadlineMs,
      "smtp_total_timeout",
      () => dependencies.transport.close?.(),
    );
    const accepted = (info.accepted ?? []).map(providerAddress);
    const rejected = (info.rejected ?? []).map(providerAddress);
    const target = to.toLowerCase();
    const targetAccepted = accepted.includes(target);
    const targetRejected = rejected.includes(target);
    if (!targetAccepted && targetRejected && accepted.length === 0) {
      throw new DeliveryRejectedError();
    }
    if (!targetAccepted || rejected.length > 0 || accepted.length !== 1) {
      throw new DeliveryUncertainError("provider_response_ambiguous");
    }
    return {
      status: "accepted",
      providerMessageId: info.messageId ?? null,
      response: info.response ?? null,
    };
  } catch (error) {
    if (error instanceof DeliveryRejectedError) throw error;
    if (isDefinitiveRejection(error)) {
      throw new DeliveryRejectedError(errorCode(error));
    }
    if (isKnownPreDeliveryFailure(error)) {
      throw new DeliveryRejectedError(errorCode(error));
    }
    throw new DeliveryUncertainError(errorCode(error));
  }
}
