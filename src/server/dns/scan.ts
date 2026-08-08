import "server-only";

import { createPublicKey } from "node:crypto";
import { resolveMx, resolveTxt } from "node:dns/promises";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

export type DnsResolver = {
  resolveTxt(name: string): Promise<string[][]>;
  resolveMx(name: string): Promise<Array<{ exchange: string; priority: number }>>;
};

export type DnsHealthResult = {
  status: "healthy" | "degraded" | "blocked" | "error";
  sendReady: boolean;
  spfStatus: string;
  dkimStatus: string;
  dmarcStatus: string;
  mxStatus: string;
  alignment: "records_present_not_message_verified";
  records: {
    spf: string[];
    dkim: string[];
    dmarc: string[];
    mx: Array<{ exchange: string; priority: number }>;
  };
  errorCode: string | null;
};

const defaultResolver: DnsResolver = { resolveTxt, resolveMx };
const DNS_TIMEOUT_MS = 5_000;
const TRANSIENT_DNS_CODES = new Set([
  "EAI_AGAIN",
  "ECANCELLED",
  "ECONNREFUSED",
  "EREFUSED",
  "ESERVFAIL",
  "ETIMEOUT",
]);

class DnsResponseError extends Error {}
class DnsTimeoutError extends Error {}

type LookupResult<T> =
  | { kind: "ok"; value: T }
  | { kind: "missing" }
  | { kind: "invalid" }
  | { kind: "error"; code: "dns_timeout" | "dns_transient" | "dns_lookup_failed" };

function normalizeDomain(rawDomain: string): string {
  const domain = domainToASCII(rawDomain.trim().replace(/\.$/, "").toLowerCase());
  if (
    !domain ||
    domain.length > 253 ||
    isIP(domain) !== 0 ||
    domain === "localhost" ||
    domain.endsWith(".local") ||
    domain.endsWith(".internal") ||
    !domain.split(".").every(
      (label) =>
        label.length >= 1 &&
        label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    ) ||
    !domain.includes(".")
  ) {
    throw new Error("Sending domain is invalid");
  }
  return domain;
}

function normalizeSelector(rawSelector: string | null): string | null {
  const selector = rawSelector?.trim().toLowerCase() ?? "";
  if (!selector) return null;
  if (selector.length > 63 || !/^[a-z0-9_-]+$/.test(selector)) {
    throw new Error("DKIM selector is invalid");
  }
  return selector;
}

function boundedTxt(records: string[][]): string[] {
  if (!Array.isArray(records) || records.length > 100) {
    throw new DnsResponseError();
  }
  const joined = records.map((parts) => {
    if (!Array.isArray(parts) || !parts.every((part) => typeof part === "string")) {
      throw new DnsResponseError();
    }
    return parts.join("");
  });
  if (joined.some((record) => record.length > 4_096 || /\u0000/.test(record))) {
    throw new DnsResponseError();
  }
  return joined;
}

function boundedMx(
  records: Array<{ exchange: string; priority: number }>,
): Array<{ exchange: string; priority: number }> {
  if (!Array.isArray(records) || records.length > 100) {
    throw new DnsResponseError();
  }
  return records.map(({ exchange, priority }) => {
    if (typeof exchange !== "string") throw new DnsResponseError();
    const normalized = domainToASCII(exchange.trim().replace(/\.$/, "").toLowerCase());
    if (
      !normalized ||
      normalized.length > 253 ||
      !Number.isInteger(priority) ||
      priority < 0 ||
      priority > 65_535
    ) {
      throw new DnsResponseError();
    }
    return { exchange: normalized, priority };
  });
}

function isMissingRecordError(error: unknown): boolean {
  if (!error || typeof error !== "object" || !("code" in error)) return false;
  return new Set(["ENODATA", "ENOTFOUND", "ENODOMAIN"]).has(String(error.code));
}

async function withTimeout<T>(promise: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new DnsTimeoutError()), DNS_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function lookup<TInput, TOutput>(
  operation: () => Promise<TInput>,
  normalize: (value: TInput) => TOutput,
): Promise<LookupResult<TOutput>> {
  try {
    return { kind: "ok", value: normalize(await withTimeout(operation())) };
  } catch (error) {
    if (isMissingRecordError(error)) return { kind: "missing" };
    if (error instanceof DnsResponseError) return { kind: "invalid" };
    if (error instanceof DnsTimeoutError) return { kind: "error", code: "dns_timeout" };
    const code =
      error && typeof error === "object" && "code" in error
        ? String(error.code)
        : "";
    return {
      kind: "error",
      code: TRANSIENT_DNS_CODES.has(code) ? "dns_transient" : "dns_lookup_failed",
    };
  }
}

function tag(record: string, name: string): string | null {
  const match = new RegExp(`(?:^|;)\\s*${name}=([^;]*)`, "i").exec(record);
  return match?.[1]?.trim() ?? null;
}

function spfStatus(records: string[]): string {
  if (records.length === 0) return "missing";
  if (records.length > 1) return "multiple_records";
  const terms = records[0].trim().split(/\s+/).slice(1);
  const allTerms = terms.filter((term) => /^[+?~-]?all$/i.test(term));
  const all = allTerms[0];
  if (
    allTerms.length > 1 ||
    (all && (!/^[~-]all$/i.test(all) || terms.at(-1) !== all))
  ) {
    return "invalid_policy";
  }
  let authorizesSender = false;
  for (const term of terms) {
    if (/^[+?~-]?all$/i.test(term)) continue;
    if (/^redirect=/i.test(term)) {
      const target = term.slice(term.indexOf("=") + 1);
      if (!/^[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?$/i.test(target)) {
        return "invalid_policy";
      }
      authorizesSender = true;
      continue;
    }
    if (/^exp=/i.test(term)) continue;
    const qualifier = /^[+?~-]/.test(term) ? term[0] : "+";
    const mechanism = /^[+?~-]/.test(term) ? term.slice(1) : term;
    const syntacticallyValid =
      /^(?:a|mx)(?::[a-z0-9_.-]+)?(?:\/\d{1,3}(?:\/\d{1,3})?)?$/i.test(
        mechanism,
      ) ||
      /^include:[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?$/i.test(mechanism) ||
      /^exists:[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?$/i.test(mechanism) ||
      (/^ip4:[^/]+(?:\/\d{1,2})?$/i.test(mechanism) &&
        isIP(mechanism.slice(4).split("/")[0]) === 4 &&
        Number(mechanism.split("/")[1] ?? 32) <= 32) ||
      (/^ip6:[^/]+(?:\/\d{1,3})?$/i.test(mechanism) &&
        isIP(mechanism.slice(4).split("/")[0]) === 6 &&
        Number(mechanism.split("/")[1] ?? 128) <= 128);
    if (!syntacticallyValid) return "invalid_policy";
    if (qualifier === "+") authorizesSender = true;
  }
  if (!authorizesSender && /^-all$/i.test(all ?? "")) return "present_deny_all";
  if (!authorizesSender || (!all && !terms.some((term) => /^redirect=/i.test(term)))) {
    return "invalid_policy";
  }
  return "present_usable";
}

function validDkimPublicKey(record: string): boolean {
  const algorithm = (tag(record, "k") ?? "rsa").toLowerCase();
  const raw = tag(record, "p");
  if (!raw || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) return false;
  try {
    const unpadded = raw.replace(/=+$/, "");
    const padded = `${unpadded}${"=".repeat((4 - (unpadded.length % 4)) % 4)}`;
    const decoded = Buffer.from(padded, "base64");
    if (decoded.toString("base64").replace(/=+$/, "") !== unpadded) return false;
    if (algorithm === "ed25519") return decoded.length === 32;
    if (algorithm !== "rsa") return false;
    for (const type of ["spki", "pkcs1"] as const) {
      try {
        const key = createPublicKey({ key: decoded, format: "der", type });
        if (
          key.asymmetricKeyType === "rsa" &&
          (key.asymmetricKeyDetails?.modulusLength ?? 0) >= 1_024
        ) {
          return true;
        }
      } catch {
        // Try the other standard RSA DER wrapper.
      }
    }
    return false;
  } catch {
    return false;
  }
}

function lookupStatus<T>(lookupResult: LookupResult<T>): string | null {
  if (lookupResult.kind === "missing") return "missing";
  if (lookupResult.kind === "invalid") return "invalid_response";
  if (lookupResult.kind === "error") return "lookup_error";
  return null;
}

export async function scanDnsHealth(
  input: {
    domain: string;
    dkimSelector: string | null;
    dkimMode: "provider" | "local";
  },
  resolver: DnsResolver = defaultResolver,
): Promise<DnsHealthResult> {
  const domain = normalizeDomain(input.domain);
  const selector = normalizeSelector(input.dkimSelector);

  const [rootLookup, dkimLookup, dmarcLookup, mxLookup] = await Promise.all([
    lookup(() => resolver.resolveTxt(domain), boundedTxt),
    selector
      ? lookup(
          () => resolver.resolveTxt(`${selector}._domainkey.${domain}`),
          boundedTxt,
        )
      : Promise.resolve({ kind: "missing" } as const),
    lookup(() => resolver.resolveTxt(`_dmarc.${domain}`), boundedTxt),
    lookup(() => resolver.resolveMx(domain), boundedMx),
  ]);

  const root = rootLookup.kind === "ok" ? rootLookup.value : [];
  const dkim = dkimLookup.kind === "ok" ? dkimLookup.value : [];
  const dmarc = dmarcLookup.kind === "ok" ? dmarcLookup.value : [];
  const mx = mxLookup.kind === "ok" ? mxLookup.value : [];
  const spf = root.filter((record) => /^v=spf1(?:\s|$)/i.test(record.trim()));
  const dkimRecords = dkim.filter((record) => /^v=dkim1(?:;|\s|$)/i.test(record.trim()));
  const dmarcRecords = dmarc.filter((record) => /^v=dmarc1(?:;|\s|$)/i.test(record.trim()));

  const resolvedSpfStatus =
    lookupStatus(rootLookup) ?? spfStatus(spf);
  let resolvedDkimStatus: string;
  if (!selector) {
    resolvedDkimStatus = "selector_missing";
  } else if (lookupStatus(dkimLookup)) {
    resolvedDkimStatus = lookupStatus(dkimLookup)!;
  } else if (dkimRecords.length === 0) {
    resolvedDkimStatus = "missing";
  } else if (dkimRecords.length > 1) {
    resolvedDkimStatus = "multiple_records";
  } else if (!validDkimPublicKey(dkimRecords[0])) {
    resolvedDkimStatus = "invalid_public_key";
  } else {
    resolvedDkimStatus =
      input.dkimMode === "provider"
        ? "present_provider_managed"
        : "present_local_key";
  }

  let resolvedDmarcStatus = lookupStatus(dmarcLookup);
  if (!resolvedDmarcStatus) {
    const policy =
      dmarcRecords.length === 1
        ? tag(dmarcRecords[0], "p")?.toLowerCase() ?? null
        : null;
    resolvedDmarcStatus =
      dmarcRecords.length === 0
        ? "missing"
        : dmarcRecords.length > 1
          ? "multiple_records"
          : policy === "none"
            ? "present_monitoring"
            : policy === "quarantine"
              ? "present_quarantine"
              : policy === "reject"
                ? "present_reject"
                : "invalid_policy";
  }
  const resolvedMxStatus = lookupStatus(mxLookup) ?? (mx.length > 0 ? "present" : "missing");

  const lookups = [rootLookup, dkimLookup, dmarcLookup, mxLookup];
  const lookupError = lookups.find(
    (value): value is Extract<LookupResult<unknown>, { kind: "error" }> =>
      value.kind === "error",
  );
  const invalidResponse = lookups.some((value) => value.kind === "invalid");
  const recordsUsable =
    resolvedSpfStatus === "present_usable" &&
    resolvedDkimStatus.startsWith("present_") &&
    resolvedDmarcStatus.startsWith("present_") &&
    resolvedMxStatus === "present";
  const status: DnsHealthResult["status"] = lookupError
    ? "error"
    : !recordsUsable
      ? "blocked"
      : resolvedDmarcStatus === "present_monitoring"
        ? "degraded"
        : "healthy";

  return {
    status,
    sendReady: recordsUsable && !lookupError,
    spfStatus: resolvedSpfStatus,
    dkimStatus: resolvedDkimStatus,
    dmarcStatus: resolvedDmarcStatus,
    mxStatus: resolvedMxStatus,
    alignment: "records_present_not_message_verified",
    records: { spf, dkim: dkimRecords, dmarc: dmarcRecords, mx },
    errorCode: lookupError?.code ?? (invalidResponse ? "dns_response_invalid" : null),
  };
}
