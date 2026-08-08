import "server-only";

import { randomUUID } from "node:crypto";

import type { Client } from "@libsql/client";

import { scanDnsHealth, type DnsResolver } from "./scan";

export class SendingDomainNotFoundError extends Error {
  constructor() {
    super("Sending domain not found");
    this.name = "SendingDomainNotFoundError";
  }
}

export async function scanSendingDomain(
  client: Client,
  identity: { tenantId: string; domainId: string },
  options: { resolver?: DnsResolver; now?: () => number } = {},
) {
  const domainResult = await client.execute({
    sql: `
      SELECT domain, dkim_selector, dkim_mode
      FROM sending_domains
      WHERE tenant_id = ? AND id = ?
      LIMIT 1
    `,
    args: [identity.tenantId, identity.domainId],
  });
  const domain = domainResult.rows[0];
  if (!domain) throw new SendingDomainNotFoundError();
  const sendingDomain = String(domain.domain).trim().replace(/\.$/, "").toLowerCase();
  const dkimSelector =
    domain.dkim_selector == null
      ? null
      : String(domain.dkim_selector).trim().toLowerCase();
  const dkimMode = String(domain.dkim_mode) === "local" ? "local" : "provider";
  const result = await scanDnsHealth(
    {
      domain: sendingDomain,
      dkimSelector,
      dkimMode,
    },
    options.resolver,
  );
  const now = (options.now ?? Date.now)();
  const gateStatus =
    result.status === "healthy" || result.status === "degraded"
      ? result.status
      : "blocked";
  await client.batch(
    [
      {
        sql: `
          INSERT INTO dns_checks
            (id, tenant_id, domain_id, status, spf_status, dkim_status,
             dmarc_status, mx_status, records_json, error_code, checked_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        args: [
          randomUUID(),
          identity.tenantId,
          identity.domainId,
          result.status,
          result.spfStatus,
          result.dkimStatus,
          result.dmarcStatus,
          result.mxStatus,
          JSON.stringify({
            alignment: result.alignment,
            sendReady: result.sendReady,
            source: {
              sendingDomain,
              dkimSelector,
              dkimMode,
            },
            records: result.records,
          }),
          result.errorCode,
          now,
        ],
      },
      {
        sql: "UPDATE sending_domains SET status = ?, last_dns_check_at = ? WHERE tenant_id = ? AND id = ?",
        args: [gateStatus, now, identity.tenantId, identity.domainId],
      },
    ],
    "write",
  );
  return result;
}
