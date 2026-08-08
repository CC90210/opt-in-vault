import "server-only";

import { simpleParser } from "mailparser";

const MAX_SOURCE_BYTES = 1_000_000;
const MAX_TEXT_LENGTH = 256_000;
const MAX_DSN_SECTION_LENGTH = 64_000;
const CLASSIFICATION_HEADERS = new Set([
  "auto-submitted",
  "content-type",
  "precedence",
  "x-autoreply",
  "x-autorespond",
]);

function extractHeaders(
  headerLines: ReadonlyArray<{ key: string; line: string }>,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const header of headerLines) {
    const name = header.key.trim().toLowerCase();
    if (!CLASSIFICATION_HEADERS.has(name) || name in result) continue;
    const separator = header.line.indexOf(":");
    const value = (separator >= 0 ? header.line.slice(separator + 1) : header.line)
      .trim()
      .slice(0, 2_000);
    result[name] = value;
  }
  return result;
}

function normalizedMessageId(value: string | null | undefined): string | null {
  const normalized = value?.trim() ?? "";
  return normalized.length <= 998 && /^<[^<>\s]+@[^<>\s]+>$/.test(normalized)
    ? normalized
    : null;
}

export type ParsedDeliveryStatus = {
  originalMessageId: string | null;
  finalRecipient: string | null;
  action: string;
  status: string;
};

export class InboundParseError extends Error {
  readonly code: "invalid_source" | "missing_sender" | "malformed_mime";

  constructor(code: "invalid_source" | "missing_sender" | "malformed_mime") {
    super(
      code === "invalid_source"
        ? "Inbound source exceeds the allowed size"
        : code === "missing_sender"
          ? "Inbound sender address is missing"
          : "Inbound MIME could not be parsed",
    );
    this.name = "InboundParseError";
    this.code = code;
  }
}

function headerField(section: string, name: string): string | null {
  const unfolded = section.replace(/\r?\n[ \t]+/g, " ");
  const match = new RegExp(`(?:^|\\r?\\n)${name}:[ \\t]*([^\\r\\n]*)`, "i").exec(
    unfolded,
  );
  return match?.[1]?.trim().slice(0, 998) || null;
}

function extractDeliveryStatus(
  source: Buffer,
  contentType: string | undefined,
): ParsedDeliveryStatus | null {
  const normalizedType = contentType?.toLowerCase() ?? "";
  if (
    !normalizedType.includes("message/delivery-status") &&
    !(normalizedType.includes("multipart/report") &&
      normalizedType.includes("report-type=delivery-status"))
  ) {
    return null;
  }

  const raw = source.toString("utf8");
  let section: string | null = null;
  if (normalizedType.includes("message/delivery-status")) {
    const bodyStart = /\r?\n\r?\n/.exec(raw);
    section = bodyStart ? raw.slice(bodyStart.index + bodyStart[0].length) : null;
  } else {
    const marker = /(?:^|\r?\n)content-type:[ \t]*message\/delivery-status[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*\r?\n\r?\n/i.exec(
      raw,
    );
    if (marker) {
      const start = marker.index + marker[0].length;
      const remainder = raw.slice(start);
      const boundary = /\r?\n--[^\r\n]+/.exec(remainder);
      section = remainder.slice(0, boundary?.index ?? remainder.length);
    }
  }
  if (!section || section.length > MAX_DSN_SECTION_LENGTH) return null;

  const action = headerField(section, "Action")?.toLowerCase() ?? null;
  const status = headerField(section, "Status") ?? null;
  if (!action || !/^(?:failed|delayed|delivered|relayed|expanded)$/.test(action)) {
    return null;
  }
  if (!status || !/^[245]\.\d{1,3}\.\d{1,3}$/.test(status)) return null;

  const rawMessageId = headerField(section, "Original-Message-ID");
  const originalMessageId =
    rawMessageId && /^<[^<>\s]+@[^<>\s]+>$/.test(rawMessageId)
      ? rawMessageId
      : null;
  const rawRecipient =
    headerField(section, "Final-Recipient") ??
    headerField(section, "Original-Recipient");
  const recipientValue = rawRecipient?.includes(";")
    ? rawRecipient.slice(rawRecipient.indexOf(";") + 1).trim()
    : rawRecipient?.trim();
  const finalRecipient =
    recipientValue && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipientValue)
      ? recipientValue.toLowerCase()
      : null;

  return { originalMessageId, finalRecipient, action, status };
}

export async function parseInboundSource(source: Buffer): Promise<{
  messageId: string | null;
  inReplyTo: string | null;
  references: string[];
  fromAddress: string;
  subject: string;
  headers: Record<string, string>;
  text: string;
  textTruncated: boolean;
  dsn: ParsedDeliveryStatus | null;
  messageDate: number | null;
}> {
  if (!Buffer.isBuffer(source) || source.length === 0 || source.length > MAX_SOURCE_BYTES) {
    throw new InboundParseError("invalid_source");
  }
  let parsed: Awaited<ReturnType<typeof simpleParser>>;
  try {
    parsed = await simpleParser(source, {
      skipHtmlToText: true,
      skipTextToHtml: true,
      skipImageLinks: true,
      maxHtmlLengthToParse: 0,
    });
  } catch {
    throw new InboundParseError("malformed_mime");
  }
  const fromAddress = parsed.from?.value[0]?.address?.trim().toLowerCase();
  if (
    !fromAddress ||
    fromAddress.length > 320 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fromAddress) ||
    /[\u0000-\u001f\u007f]/.test(fromAddress)
  ) {
    throw new InboundParseError("missing_sender");
  }
  const references = parsed.references
    ? Array.isArray(parsed.references)
      ? parsed.references
      : [parsed.references]
    : [];

  const headers = extractHeaders(parsed.headerLines);
  const rawText = parsed.text ?? "";
  const rawDate = parsed.date?.getTime();
  return {
    messageId: normalizedMessageId(parsed.messageId),
    inReplyTo: normalizedMessageId(parsed.inReplyTo),
    references: references
      .map((value) => normalizedMessageId(value))
      .filter((value): value is string => value !== null)
      .slice(0, 50),
    fromAddress,
    subject: (parsed.subject ?? "").slice(0, 998),
    headers,
    text: rawText.slice(0, MAX_TEXT_LENGTH),
    textTruncated: rawText.length > MAX_TEXT_LENGTH,
    dsn: extractDeliveryStatus(source, headers["content-type"]),
    messageDate:
      rawDate !== undefined && Number.isSafeInteger(rawDate) && rawDate >= 0
        ? rawDate
        : null,
  };
}
