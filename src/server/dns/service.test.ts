import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";

import type { DnsResolver } from "./scan";
import { scanSendingDomain } from "./service";

const MIGRATIONS_FOLDER = fileURLToPath(
  new URL("../../../drizzle", import.meta.url),
);
const VALID_DKIM_KEY =
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHD7oAFCZamdlS2bU7avjpSvARqgTXNUEeiTeUgz310gl2wsVT10zTz8/EAVjSEryT0xK4UWLsqM9/1tfqJbS8XLwi9Uv27/CdhJWzibvpiVi/GPlnK47SbEu4/dR2J4w61XFhYhfgzPcbX2mJTIgFRsdtyXC8zN+26ImyuX9KrQIDAQAB";

const healthyResolver: DnsResolver = {
  resolveTxt: vi.fn(async (name: string) => {
    if (name.startsWith("_dmarc.")) return [["v=DMARC1; p=reject"]];
    if (name.includes("._domainkey.")) {
      return [[`v=DKIM1; k=rsa; p=${VALID_DKIM_KEY}`]];
    }
    return [["v=spf1 mx -all"]];
  }),
  resolveMx: vi.fn(async () => [{ exchange: "mx.example.net", priority: 10 }]),
};

describe("sending domain DNS service", () => {
  let client: Client;
  let tenantA: string;
  let tenantB: string;
  let domainId: string;

  beforeEach(async () => {
    client = createClient({ url: "file::memory:?cache=shared" });
    await migrate(drizzle(client), { migrationsFolder: MIGRATIONS_FOLDER });
    await client.execute("PRAGMA foreign_keys = ON");
    tenantA = `tenant-a-${randomUUID()}`;
    tenantB = `tenant-b-${randomUUID()}`;
    domainId = `domain-${randomUUID()}`;
    await client.batch(
      [
        { sql: "INSERT INTO tenants (id, slug, name) VALUES (?, ?, 'A')", args: [tenantA, tenantA] },
        { sql: "INSERT INTO tenants (id, slug, name) VALUES (?, ?, 'B')", args: [tenantB, tenantB] },
        {
          sql: "INSERT INTO sending_domains (id, tenant_id, domain, dkim_selector, dkim_mode) VALUES (?, ?, 'example.com', 'selector', 'provider')",
          args: [domainId, tenantA],
        },
      ],
      "write",
    );
  });

  afterEach(() => client.close());

  it("stores a tenant-scoped snapshot and updates the sending gate", async () => {
    const result = await scanSendingDomain(
      client,
      { tenantId: tenantA, domainId },
      { resolver: healthyResolver, now: () => 1_800_000_000_000 },
    );
    expect(result.status).toBe("healthy");
    const stored = await client.execute({
      sql: "SELECT domain.status, domain.last_dns_check_at, check_row.records_json FROM sending_domains AS domain JOIN dns_checks AS check_row ON check_row.tenant_id = domain.tenant_id AND check_row.domain_id = domain.id WHERE domain.tenant_id = ? AND domain.id = ?",
      args: [tenantA, domainId],
    });
    expect(stored.rows[0]).toMatchObject({
      status: "healthy",
      last_dns_check_at: 1_800_000_000_000,
    });
    expect(JSON.parse(String(stored.rows[0]?.records_json))).toMatchObject({
      alignment: "records_present_not_message_verified",
    });
  });

  it("rejects forged cross-tenant domain access without a DNS lookup", async () => {
    await expect(
      scanSendingDomain(client, { tenantId: tenantB, domainId }, { resolver: healthyResolver }),
    ).rejects.toThrow(/not found/i);
  });

  it("stores a degraded snapshot and missing-selector status instead of throwing", async () => {
    await client.execute({
      sql: "UPDATE sending_domains SET dkim_selector = NULL WHERE tenant_id = ? AND id = ?",
      args: [tenantA, domainId],
    });
    const result = await scanSendingDomain(
      client,
      { tenantId: tenantA, domainId },
      { resolver: healthyResolver, now: () => 1_800_000_000_000 },
    );
    expect(result).toMatchObject({ status: "blocked", dkimStatus: "selector_missing" });
    const stored = await client.execute({
      sql: "SELECT domain.status, check_row.dkim_status FROM sending_domains AS domain JOIN dns_checks AS check_row ON check_row.tenant_id = domain.tenant_id AND check_row.domain_id = domain.id WHERE domain.tenant_id = ? AND domain.id = ?",
      args: [tenantA, domainId],
    });
    expect(stored.rows[0]).toMatchObject({
      status: "blocked",
      dkim_status: "selector_missing",
    });
  });

  it("preserves the degraded gate for a valid monitoring-only DMARC policy", async () => {
    const monitoringResolver: DnsResolver = {
      resolveTxt: vi.fn(async (name: string) => {
        if (name.startsWith("_dmarc.")) return [["v=DMARC1; p=none"]];
        if (name.includes("._domainkey.")) {
          return [[`v=DKIM1; k=rsa; p=${VALID_DKIM_KEY}`]];
        }
        return [["v=spf1 mx -all"]];
      }),
      resolveMx: vi.fn(async () => [{ exchange: "mx.example.net", priority: 10 }]),
    };
    const result = await scanSendingDomain(
      client,
      { tenantId: tenantA, domainId },
      { resolver: monitoringResolver, now: () => 1_800_000_000_000 },
    );
    expect(result).toMatchObject({ status: "degraded", sendReady: true });
    const stored = await client.execute({
      sql: "SELECT status FROM sending_domains WHERE tenant_id = ? AND id = ?",
      args: [tenantA, domainId],
    });
    expect(stored.rows[0]?.status).toBe("degraded");
  });
});
