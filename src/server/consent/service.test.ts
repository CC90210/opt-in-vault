import { randomUUID } from "node:crypto";
import { join } from "node:path";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";
import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { decryptSecret } from "@/server/security/encryption";

import {
  ConsentCaptureError,
  createConsentService,
  createLibsqlConsentRepository,
  hashCaptureSiteKey,
} from "./service";

const SITE_KEY = `oiv_pk_${"a".repeat(43)}`;
const SITE_PEPPER = "site-pepper-with-at-least-thirty-two-bytes";
const SUBJECT_KEY = "subject-hash-key-with-at-least-thirty-two-bytes";
const SIGNATURE_KEY = "signature-key-with-at-least-thirty-two-bytes";
const ENCRYPTION_KEY = Buffer.alloc(32, 7);
const NOW = Date.UTC(2026, 7, 8, 12, 0, 0);
const RETENTION_MS = 365 * 24 * 60 * 60 * 1_000;

describe("consent capture service", () => {
  let client: Client;
  let tenantId: string;
  let siteId: string;
  let now: number;

  beforeEach(async () => {
    client = createClient({ url: "file::memory:" });
    await migrate(drizzle(client), { migrationsFolder: join(process.cwd(), "drizzle") });
    await client.execute("PRAGMA foreign_keys = ON");
    tenantId = `tenant-${randomUUID()}`;
    siteId = `site-${randomUUID()}`;
    now = NOW;
    const keyHash = hashCaptureSiteKey(SITE_KEY, SITE_PEPPER);
    await client.batch(
      [
        {
          sql: "INSERT INTO tenants (id, slug, name) VALUES (?, ?, ?)",
          args: [tenantId, tenantId, "Example Controller"],
        },
        {
          sql: `INSERT INTO capture_sites
            (id, tenant_id, name, public_key_prefix, public_key_hash,
             allowed_origins_json, form_url_pattern, disclosure_version,
             disclosure_text, controller, purpose, channels_json, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
          args: [
            siteId,
            tenantId,
            "Signup",
            SITE_KEY.slice(0, 18),
            keyHash,
            JSON.stringify(["https://example.test"]),
            "https://example.test/signup*",
            "disclosure-2026-08",
            "I agree to receive product updates by email.",
            "Example Controller Inc.",
            "Product updates",
            JSON.stringify(["email"]),
          ],
        },
      ],
      "write",
    );
  });

  afterEach(() => client.close());

  function service() {
    return createConsentService(createLibsqlConsentRepository(client), {
      siteKeyPepper: SITE_PEPPER,
      subjectHashKey: SUBJECT_KEY,
      signatureKey: SIGNATURE_KEY,
      signatureKeyVersion: 4,
      payloadEncryptionKey: ENCRYPTION_KEY,
      payloadKeyVersion: 3,
      retentionMs: RETENTION_MS,
      now: () => now,
      createId: (kind) => `${kind}-${randomUUID()}`,
    });
  }

  const body = {
    disclosure_version: "disclosure-2026-08",
    affirmative_action: "form_submit",
    form_url: "https://example.test/signup?campaign=spring",
    occurred_at: "2026-08-08T11:59:30.000Z",
    email: " Person@Example.TEST ",
  };

  it("binds evidence to the authenticated active site and registered disclosure", async () => {
    const result = await service().capture(body, {
      siteKey: SITE_KEY,
      origin: "https://example.test",
      idempotencyKey: "idem-consent-0001",
      userAgent: "Consent Browser/1.0",
      trustedEdge: { ip: "203.0.113.9", source: "cloudflare" },
    });

    expect(result).toMatchObject({ created: true, tenantId, captureSiteId: siteId });
    expect(result.payloadSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.signatureHmac).toMatch(/^[a-f0-9]{64}$/);
    expect(result.signatureKeyVersion).toBe(4);
    expect(result.receivedAt).toBe(NOW);
    expect(result.retentionExpiresAt).toBe(NOW + RETENTION_MS);

    const stored = await client.execute({
      sql: `SELECT canonical_payload_ciphertext, payload_key_version,
                   payload_sha256, signature_hmac, signature_key_version,
                   subject_identifier_hash, controller, purpose,
                   disclosure_version, received_at, retention_expires_at
            FROM consent_logs WHERE id = ? AND tenant_id = ?`,
      args: [result.consentId, tenantId],
    });
    const row = stored.rows[0];
    const ciphertext = Buffer.from(
      row.canonical_payload_ciphertext as unknown as Uint8Array,
    );
    expect(ciphertext.toString("utf8")).not.toContain("person@example.test");
    expect(Number(row.payload_key_version)).toBe(3);
    expect(Number(row.retention_expires_at)).toBe(NOW + RETENTION_MS);

    const decrypted = decryptSecret(ciphertext.toString("utf8"), ENCRYPTION_KEY, {
      tenantId,
      resourceType: "consent_log",
      resourceId: result.consentId,
      field: "canonical_payload",
      provider: siteId,
    });
    const evidence = JSON.parse(decrypted.plaintext);
    expect(evidence).toMatchObject({
      schema_version: 1,
      tenant_id: tenantId,
      capture_site_id: siteId,
      subject: { email: "person@example.test" },
      controller: "Example Controller Inc.",
      purpose: "Product updates",
      disclosure: {
        version: "disclosure-2026-08",
        text: "I agree to receive product updates by email.",
      },
      affirmative_action: "form_submit",
      received_at: "2026-08-08T12:00:00.000Z",
      network: { trusted_ip: "203.0.113.9", source: "cloudflare" },
    });
    expect(evidence).not.toHaveProperty("tenant_id", "attacker");
  });

  it("returns the original evidence for an identical replay and rejects changed reuse", async () => {
    const first = await service().capture(body, {
      siteKey: SITE_KEY,
      origin: "https://example.test",
      idempotencyKey: "idem-consent-0002",
    });
    now += 60_000;
    const replay = await service().capture(body, {
      siteKey: SITE_KEY,
      origin: "https://example.test",
      idempotencyKey: "idem-consent-0002",
    });

    expect(replay).toEqual({ ...first, created: false });
    await expect(
      service().capture({ ...body, affirmative_action: "checkbox_change" }, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-consent-0002",
      }),
    ).rejects.toMatchObject({ code: "idempotency_conflict" } satisfies Partial<ConsentCaptureError>);
  });

  it("atomically converges concurrent retries on one evidence and certificate", async () => {
    const capture = service();
    const context = {
      siteKey: SITE_KEY,
      origin: "https://example.test",
      idempotencyKey: "idem-concurrent-0001",
    };
    const [first, second] = await Promise.all([
      capture.capture(body, context),
      capture.capture(body, context),
    ]);

    expect(first.consentId).toBe(second.consentId);
    expect(first.certificateCode).toBe(second.certificateCode);
    expect([first.created, second.created].sort()).toEqual([false, true]);
    const counts = await client.execute(
      `SELECT
         (SELECT count(*) FROM consent_logs) AS logs,
         (SELECT count(*) FROM consent_certificates) AS certificates`,
    );
    expect(counts.rows[0]).toMatchObject({ logs: 1, certificates: 1 });
  });

  it("keeps retries idempotent when occurred_at is omitted and server time advances", async () => {
    const input = { ...body, occurred_at: undefined };
    const first = await service().capture(input, {
      siteKey: SITE_KEY,
      origin: "https://example.test",
      idempotencyKey: "idem-server-time-0001",
    });
    now += 90_000;
    const replay = await service().capture(input, {
      siteKey: SITE_KEY,
      origin: "https://example.test",
      idempotencyKey: "idem-server-time-0001",
    });

    expect(replay).toEqual({ ...first, created: false });
  });

  it("refuses to decrypt an idempotent record at or after its retention deadline", async () => {
    await service().capture(body, {
      siteKey: SITE_KEY,
      origin: "https://example.test",
      idempotencyKey: "idem-expired-evidence",
    });
    now += RETENTION_MS;

    await expect(
      service().capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-expired-evidence",
      }),
    ).rejects.toMatchObject({ code: "evidence_verification_failed" });
  });

  it.each([
    ["origin", { origin: "https://evil.test" }, body, "origin_not_allowed"],
    ["disclosure", {}, { ...body, disclosure_version: "old" }, "disclosure_mismatch"],
    ["form URL", {}, { ...body, form_url: "https://example.test/other" }, "form_url_mismatch"],
  ])("rejects a %s mismatch before inserting", async (_name, contextPatch, bodyPatch, code) => {
    await expect(
      service().capture(bodyPatch, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: `idem-${code}`,
        ...contextPatch,
      }),
    ).rejects.toMatchObject({ code });
    const count = await client.execute("SELECT count(*) AS count FROM consent_logs");
    expect(Number(count.rows[0].count)).toBe(0);
  });

  it("rejects paused sites and malformed trusted-edge addresses", async () => {
    await client.execute({
      sql: "UPDATE capture_sites SET status = 'paused' WHERE id = ? AND tenant_id = ?",
      args: [siteId, tenantId],
    });
    await expect(
      service().capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-paused-site",
      }),
    ).rejects.toMatchObject({ code: "site_inactive" });

    await client.execute({
      sql: "UPDATE capture_sites SET status = 'active' WHERE id = ? AND tenant_id = ?",
      args: [siteId, tenantId],
    });
    await expect(
      service().capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-invalid-ip",
        trustedEdge: { ip: "not-an-ip", source: "cloudflare" },
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("rejects evidence when a configured channel has no matching subject identifier", async () => {
    await expect(
      service().capture(
        { ...body, email: undefined, phone: "+1 514 555 0100" },
        {
          siteKey: SITE_KEY,
          origin: "https://example.test",
          idempotencyKey: "idem-channel-mismatch",
        },
      ),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("does not let a suffix wildcard broaden a registered form pathname", async () => {
    await expect(
      service().capture(
        { ...body, form_url: "https://example.test/signup-malicious" },
        {
          siteKey: SITE_KEY,
          origin: "https://example.test",
          idempotencyKey: "idem-form-prefix-bypass",
        },
      ),
    ).rejects.toMatchObject({ code: "form_url_mismatch" });
  });

  it("fails closed when immutable evidence is mutated", async () => {
    const result = await service().capture(body, {
      siteKey: SITE_KEY,
      origin: "https://example.test",
      idempotencyKey: "idem-immutable-0001",
    });
    await expect(
      client.execute({
        sql: "UPDATE consent_logs SET purpose = 'Changed' WHERE id = ?",
        args: [result.consentId],
      }),
    ).rejects.toThrow(/immutable/i);
  });
});
