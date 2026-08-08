import { scanDnsHealth, type DnsResolver } from "./scan";

const VALID_DKIM_KEY =
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHD7oAFCZamdlS2bU7avjpSvARqgTXNUEeiTeUgz310gl2wsVT10zTz8/EAVjSEryT0xK4UWLsqM9/1tfqJbS8XLwi9Uv27/CdhJWzibvpiVi/GPlnK47SbEu4/dR2J4w61XFhYhfgzPcbX2mJTIgFRsdtyXC8zN+26ImyuX9KrQIDAQAB";

function resolver(overrides: Partial<DnsResolver> = {}): DnsResolver {
  return {
    resolveTxt: vi.fn(async (name: string) => {
      if (name === "example.com") return [["v=spf1 include:_spf.example.net -all"]];
      if (name === "selector._domainkey.example.com") {
        return [[`v=DKIM1; k=rsa; p=${VALID_DKIM_KEY}`]];
      }
      if (name === "_dmarc.example.com") return [["v=DMARC1; p=quarantine"]];
      return [];
    }),
    resolveMx: vi.fn(async () => [{ exchange: "mx.example.net", priority: 10 }]),
    ...overrides,
  };
}

describe("DNS health scanner", () => {
  it("reports healthy record presence without claiming delivered-message alignment", async () => {
    const result = await scanDnsHealth(
      { domain: "Example.COM", dkimSelector: "selector", dkimMode: "provider" },
      resolver(),
    );

    expect(result).toMatchObject({
      status: "healthy",
      sendReady: true,
      spfStatus: "present_usable",
      dkimStatus: "present_provider_managed",
      dmarcStatus: "present_quarantine",
      mxStatus: "present",
      alignment: "records_present_not_message_verified",
    });
  });

  it("does not call present-but-unusable SPF and DKIM records send-ready", async () => {
    const result = await scanDnsHealth(
      { domain: "example.com", dkimSelector: "selector", dkimMode: "provider" },
      resolver({
        resolveTxt: vi.fn(async (name: string) => {
          if (name === "example.com") return [["v=spf1 -all"]];
          if (name.includes("._domainkey.")) {
            return [["v=DKIM1; k=rsa; p=not-a-real-public-key"]];
          }
          return [["v=DMARC1; p=quarantine"]];
        }),
      }),
    );

    expect(result).toMatchObject({
      status: "blocked",
      sendReady: false,
      spfStatus: "present_deny_all",
      dkimStatus: "invalid_public_key",
    });
  });

  it("reports a monitoring-only DMARC policy as degraded but send-ready", async () => {
    const result = await scanDnsHealth(
      { domain: "example.com", dkimSelector: "selector", dkimMode: "provider" },
      resolver({
        resolveTxt: vi.fn(async (name: string) => {
          if (name === "example.com") {
            return [["v=spf1 include:_spf.example.net -all"]];
          }
          if (name.includes("._domainkey.")) {
            return [[`v=DKIM1; k=rsa; p=${VALID_DKIM_KEY}`]];
          }
          return [["v=DMARC1; p=none"]];
        }),
      }),
    );
    expect(result).toMatchObject({
      status: "degraded",
      sendReady: true,
      dmarcStatus: "present_monitoring",
    });
  });

  it("blocks missing or conflicting records with actionable statuses", async () => {
    const result = await scanDnsHealth(
      { domain: "example.com", dkimSelector: "selector", dkimMode: "local" },
      resolver({
        resolveTxt: vi.fn(async (name: string) =>
          name === "example.com"
            ? [["v=spf1 -all"], ["v=spf1 include:other.example -all"]]
            : [],
        ),
        resolveMx: vi.fn(async () => []),
      }),
    );

    expect(result).toMatchObject({
      status: "blocked",
      spfStatus: "multiple_records",
      dkimStatus: "missing",
      dmarcStatus: "missing",
      mxStatus: "missing",
    });
  });

  it("returns a bounded error snapshot on transient resolver failure", async () => {
    const result = await scanDnsHealth(
      { domain: "example.com", dkimSelector: "selector", dkimMode: "provider" },
      resolver({ resolveMx: vi.fn(async () => Promise.reject(new Error("timeout"))) }),
    );
    expect(result).toMatchObject({
      status: "error",
      sendReady: false,
      errorCode: "dns_lookup_failed",
      spfStatus: "present_usable",
      dkimStatus: "present_provider_managed",
      dmarcStatus: "present_quarantine",
      mxStatus: "lookup_error",
    });
    expect(result.records.spf).toHaveLength(1);
    expect(JSON.stringify(result)).not.toContain("timeout");
  });

  it("separates known transient DNS outages from invalid record responses", async () => {
    const transient = Object.assign(new Error("private resolver detail"), {
      code: "ETIMEOUT",
    });
    const outage = await scanDnsHealth(
      { domain: "example.com", dkimSelector: "selector", dkimMode: "provider" },
      resolver({ resolveMx: vi.fn(async () => Promise.reject(transient)) }),
    );
    expect(outage).toMatchObject({
      status: "error",
      errorCode: "dns_transient",
      mxStatus: "lookup_error",
    });

    const invalid = await scanDnsHealth(
      { domain: "example.com", dkimSelector: "selector", dkimMode: "provider" },
      resolver({
        resolveMx: vi.fn(async () => [{ exchange: "", priority: -1 }]),
      }),
    );
    expect(invalid).toMatchObject({
      status: "blocked",
      sendReady: false,
      errorCode: "dns_response_invalid",
      mxStatus: "invalid_response",
    });
    expect(JSON.stringify([outage, invalid])).not.toContain("private resolver detail");
  });

  it("persists a missing selector result without attempting a made-up DKIM lookup", async () => {
    const resolveTxt = vi.fn(async (name: string) => {
      if (name === "example.com") return [["v=spf1 mx -all"]];
      if (name === "_dmarc.example.com") return [["v=DMARC1; p=reject"]];
      return [];
    });
    const result = await scanDnsHealth(
      { domain: "example.com", dkimSelector: null, dkimMode: "provider" },
      resolver({ resolveTxt }),
    );

    expect(result).toMatchObject({
      status: "blocked",
      sendReady: false,
      dkimStatus: "selector_missing",
      spfStatus: "present_usable",
    });
    expect(resolveTxt.mock.calls.some(([name]) => String(name).includes("._domainkey."))).toBe(
      false,
    );
  });

  it("treats NXDOMAIN and ENODATA as missing records instead of hiding them as an outage", async () => {
    const missing = Object.assign(new Error("resolver detail must stay private"), {
      code: "ENODATA",
    });
    const notFound = Object.assign(new Error("resolver detail must stay private"), {
      code: "ENOTFOUND",
    });
    const result = await scanDnsHealth(
      { domain: "example.com", dkimSelector: "selector", dkimMode: "provider" },
      resolver({
        resolveTxt: vi.fn(async () => Promise.reject(missing)),
        resolveMx: vi.fn(async () => Promise.reject(notFound)),
      }),
    );

    expect(result).toMatchObject({
      status: "blocked",
      spfStatus: "missing",
      dkimStatus: "missing",
      dmarcStatus: "missing",
      mxStatus: "missing",
      errorCode: null,
    });
    expect(JSON.stringify(result)).not.toContain("resolver detail");
  });

  it("rejects IPs, local names, and invalid selectors before DNS calls", async () => {
    await expect(
      scanDnsHealth(
        { domain: "127.0.0.1", dkimSelector: "selector", dkimMode: "provider" },
        resolver(),
      ),
    ).rejects.toThrow(/domain/i);
    await expect(
      scanDnsHealth(
        { domain: "example.com", dkimSelector: "bad.selector", dkimMode: "provider" },
        resolver(),
      ),
    ).rejects.toThrow(/selector/i);
  });
});
