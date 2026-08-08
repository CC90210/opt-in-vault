import "server-only";

export type ReplyCandidate = {
  tenantId: string;
  outboundMessageId: string;
  messageId: string;
  enrollmentId: string;
  leadId: string;
  recipientAddress: string;
};

export type ReplyMatch = ReplyCandidate & {
  matchedBy:
    | "in_reply_to"
    | "references"
    | "dsn_message_id"
    | "dsn_recipient"
    | "sender";
};

function normalizeMessageId(value: string | null | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim().toLowerCase();
  if (!/^<[^<>\s]+@[^<>\s]+>$/.test(trimmed)) return null;
  return trimmed;
}

function normalizeEmail(value: string): string | null {
  const normalized = value.trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized) ? normalized : null;
}

export function matchInboundReply(
  inbound: {
    tenantId: string;
    inReplyTo?: string | null;
    references: readonly string[];
    fromAddress: string;
    dsnOriginalMessageId?: string | null;
    dsnFinalRecipient?: string | null;
  },
  allCandidates: readonly ReplyCandidate[],
): ReplyMatch | null {
  const candidates = allCandidates.filter(
    (candidate) => candidate.tenantId === inbound.tenantId,
  );
  const dsnMessageId = normalizeMessageId(inbound.dsnOriginalMessageId);
  if (dsnMessageId) {
    const direct = candidates.filter(
      (candidate) => normalizeMessageId(candidate.messageId) === dsnMessageId,
    );
    if (direct.length === 1) return { ...direct[0], matchedBy: "dsn_message_id" };
    if (direct.length > 1) return null;
  }
  const inReplyTo = normalizeMessageId(inbound.inReplyTo);
  if (inReplyTo) {
    const direct = candidates.filter(
      (candidate) => normalizeMessageId(candidate.messageId) === inReplyTo,
    );
    if (direct.length === 1) return { ...direct[0], matchedBy: "in_reply_to" };
    if (direct.length > 1) return null;
  }

  for (const reference of [...inbound.references].reverse()) {
    const normalized = normalizeMessageId(reference);
    if (!normalized) continue;
    const matches = candidates.filter(
      (candidate) => normalizeMessageId(candidate.messageId) === normalized,
    );
    if (matches.length === 1) return { ...matches[0], matchedBy: "references" };
    if (matches.length > 1) return null;
  }

  const dsnRecipient = inbound.dsnFinalRecipient
    ? normalizeEmail(inbound.dsnFinalRecipient)
    : null;
  if (dsnRecipient) {
    const byRecipient = candidates.filter(
      (candidate) => normalizeEmail(candidate.recipientAddress) === dsnRecipient,
    );
    const byEnrollment = new Map<string, ReplyCandidate>();
    for (const candidate of byRecipient) {
      if (!byEnrollment.has(candidate.enrollmentId)) {
        byEnrollment.set(candidate.enrollmentId, candidate);
      }
    }
    const unambiguous = [...byEnrollment.values()];
    if (unambiguous.length === 1) {
      return { ...unambiguous[0], matchedBy: "dsn_recipient" };
    }
    if (unambiguous.length > 1) return null;
  }

  const sender = normalizeEmail(inbound.fromAddress);
  if (!sender) return null;
  const bySender = candidates.filter(
    (candidate) => normalizeEmail(candidate.recipientAddress) === sender,
  );
  const byEnrollment = new Map<string, ReplyCandidate>();
  for (const candidate of bySender) {
    if (!byEnrollment.has(candidate.enrollmentId)) {
      byEnrollment.set(candidate.enrollmentId, candidate);
    }
  }
  const unambiguous = [...byEnrollment.values()];
  return unambiguous.length === 1
    ? { ...unambiguous[0], matchedBy: "sender" }
    : null;
}
