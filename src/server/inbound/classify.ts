import "server-only";

export type InboundClassification =
  | "unsubscribe"
  | "out_of_office"
  | "interested"
  | "not_interested"
  | "bounce"
  | "other";

export type InboundClassificationResult = {
  classification: InboundClassification;
  automated: boolean;
};

const MAX_TEXT_LENGTH = 256_000;
const MAX_SUBJECT_LENGTH = 998;

function normalizedHeaders(
  headers: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [
      name.trim().toLowerCase(),
      (value ?? "").trim().toLowerCase(),
    ]),
  );
}

function newestVisibleReply(text: string): string {
  const lines = text.replaceAll("\r\n", "\n").split("\n");
  const visible: string[] = [];
  for (const line of lines) {
    if (/^\s*>/.test(line) || /^on .+wrote:\s*$/i.test(line)) break;
    visible.push(line);
  }
  return visible.join("\n").trim().toLowerCase();
}

export function classifyInbound(message: {
  text: string;
  subject: string;
  headers: Readonly<Record<string, string | undefined>>;
  structuredDsn?: boolean;
}): InboundClassificationResult {
  if (
    message.text.length > MAX_TEXT_LENGTH ||
    message.subject.length > MAX_SUBJECT_LENGTH
  ) {
    throw new Error("Inbound message exceeds the classification size limit");
  }

  const headers = normalizedHeaders(message.headers);
  const subject = message.subject.trim().toLowerCase();
  const text = newestVisibleReply(message.text);
  const autoSubmitted = headers["auto-submitted"] ?? "";
  const automated =
    (autoSubmitted !== "" && autoSubmitted !== "no") ||
    Boolean(headers["x-autoreply"] || headers["x-autorespond"]) ||
    /^(bulk|list|junk)$/.test(headers.precedence ?? "");

  if (message.structuredDsn === true) {
    return { classification: "bounce", automated: true };
  }

  if (
    (automated && /(?:automatic reply|auto(?:matic)? response|out of office|away from)/i.test(`${subject}\n${text}`)) ||
    /^(?:out of office|ooo)\b/i.test(subject)
  ) {
    return { classification: "out_of_office", automated: true };
  }

  // Automated content often contains footer instructions such as "unsubscribe".
  // It must never drive a person-level compliance or sentiment effect.
  if (automated) return { classification: "other", automated: true };

  const unsubscribe =
    /\b(?:unsubscribe|opt me out|remove me|remove me from (?:your|the) list|take me off|(?:do not|don'?t|dont) (?:email|contact)|stop (?:emailing|contacting|sending)|(?:do not|don'?t|dont|no longer) wish to receive (?:any |further |more )?(?:emails?|messages?))\b/i.test(
      text,
    ) || /^(?:stop|unsubscribe|remove)$/i.test(text);
  if (unsubscribe) return { classification: "unsubscribe", automated: false };

  if (
    /\b(?:not interested|no thanks|do not need|don't need|not a fit|please don't)\b/i.test(
      text,
    )
  ) {
    return { classification: "not_interested", automated: false };
  }

  if (
    /\b(?:i(?:'m| am) interested|sounds (?:good|interesting)|let'?s (?:talk|chat|book)|book a call|yes[,! .]|tell me more)\b/i.test(
      text,
    )
  ) {
    return { classification: "interested", automated: false };
  }

  return { classification: "other", automated };
}
