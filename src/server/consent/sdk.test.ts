import { readFile } from "node:fs/promises";
import { join } from "node:path";
import vm from "node:vm";

import { describe, expect, it, vi } from "vitest";

describe("browser consent SDK", () => {
  it("is self-contained and sends only a publishable key plus explicit affirmative action", async () => {
    const source = await readFile(join(process.cwd(), "public/v1/optinvault.js"), "utf8");
    const fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ consent_id: "consent-1" }),
    });
    const window = {} as Record<string, unknown>;
    vm.runInNewContext(source, {
      window,
      fetch,
      URL,
      crypto: { randomUUID: () => "12345678-1234-1234-1234-123456789012" },
      location: { href: "https://example.test/signup", origin: "https://example.test" },
      console,
    });

    const sdk = window.OptInVault as {
      capture(input: Record<string, unknown>): Promise<unknown>;
    };
    await sdk.capture({
      endpoint: "https://vault.example/api/v1/consent/log",
      siteKey: `oiv_pk_${"e".repeat(43)}`,
      disclosureVersion: "v1",
      affirmativeAction: "form_submit",
      email: "person@example.test",
    });

    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://vault.example/api/v1/consent/log");
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({
      "Content-Type": "application/json",
      "X-OptInVault-Site-Key": `oiv_pk_${"e".repeat(43)}`,
      "Idempotency-Key": "12345678-1234-1234-1234-123456789012",
    });
    expect(JSON.parse(String(init.body))).toMatchObject({
      disclosure_version: "v1",
      affirmative_action: "form_submit",
      form_url: "https://example.test/signup",
      email: "person@example.test",
    });
    expect(String(init.body)).not.toContain("tenant_id");
    expect(source).not.toContain("oiv_sk_");
    expect(source).not.toMatch(/secret|private[_-]?key/i);
  });
});
