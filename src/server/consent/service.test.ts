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

  function service(captureRateLimit?: {
    maxRequests: number;
    sourceMaxRequests: number;
    replayMaxRequests: number;
    windowMs: number;
  }, requireTrustedSource = false) {
    return createConsentService(createLibsqlConsentRepository(client), {
      siteKeyPepper: SITE_PEPPER,
      subjectHashKey: SUBJECT_KEY,
      signatureKey: SIGNATURE_KEY,
      signatureKeyVersion: 4,
      payloadEncryptionKey: ENCRYPTION_KEY,
      payloadKeyVersion: 3,
      retentionMs: RETENTION_MS,
      captureRateLimit,
      requireTrustedSource,
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
      trustedEdge: { ip: "8.8.8.8", source: "cloudflare" },
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
      network: { trusted_ip: "8.8.8.8", source: "cloudflare" },
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

  it("enforces the fixed-window boundary and resets only in the next window", async () => {
    const capture = service({
      maxRequests: 2,
      sourceMaxRequests: 2,
      replayMaxRequests: 2,
      windowMs: 1_000,
    });
    for (const idempotencyKey of ["idem-rate-boundary-01", "idem-rate-boundary-02"]) {
      await expect(
        capture.capture(body, {
          siteKey: SITE_KEY,
          origin: "https://example.test",
          idempotencyKey,
        }),
      ).resolves.toMatchObject({ created: true });
    }

    await expect(
      capture.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-rate-boundary-03",
      }),
    ).rejects.toMatchObject({ code: "rate_limited", retryAfterSeconds: 1 });

    now += 1_000;
    await expect(
      capture.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-rate-boundary-03",
      }),
    ).resolves.toMatchObject({ created: true });

    const buckets = await client.execute({
      sql: `SELECT window_started_at, count FROM rate_limit_buckets
            WHERE tenant_id = ? AND scope = 'public_consent_capture'
            ORDER BY window_started_at`,
      args: [tenantId],
    });
    expect(buckets.rows.map((row) => Number(row.count))).toEqual([2, 1]);
  });

  it("preserves bounded completed idempotent retries outside the site allowance", async () => {
    const capture = service(
      {
        maxRequests: 1,
        sourceMaxRequests: 3,
        replayMaxRequests: 2,
        windowMs: 60_000,
      },
      true,
    );
    const context = {
      siteKey: SITE_KEY,
      origin: "https://example.test",
      idempotencyKey: "idem-rate-replay-01",
      trustedEdge: { ip: "8.8.8.8", source: "vercel" },
    };
    const original = await capture.capture(body, context);
    const firstReplay = await capture.capture(body, context);
    const secondReplay = await capture.capture(body, context);

    expect(firstReplay).toEqual({ ...original, created: false });
    expect(secondReplay).toEqual({ ...original, created: false });
    await expect(capture.capture(body, context)).rejects.toMatchObject({
      code: "rate_limited",
    });
    await expect(
      capture.capture(body, {
        ...context,
        idempotencyKey: "idem-rate-new-0001",
      }),
    ).rejects.toMatchObject({ code: "rate_limited" });

    const buckets = await client.execute({
      sql: `SELECT scope, count FROM rate_limit_buckets
            WHERE tenant_id = ? ORDER BY scope`,
      args: [tenantId],
    });
    expect(buckets.rows).toEqual([
      expect.objectContaining({ scope: "public_consent_capture", count: 1 }),
      expect.objectContaining({ scope: "public_consent_replay", count: 2 }),
      expect.objectContaining({ scope: "public_consent_source", count: 3 }),
    ]);
  });

  it("applies the source cap across replays of many completed idempotency keys", async () => {
    const source = { ip: "8.8.8.8", source: "vercel" };
    const idempotencyKeys = [
      "idem-replay-source-01",
      "idem-replay-source-02",
      "idem-replay-source-03",
    ];
    const seed = service(
      {
        maxRequests: 10,
        sourceMaxRequests: 10,
        replayMaxRequests: 10,
        windowMs: 60_000,
      },
      true,
    );
    for (const idempotencyKey of idempotencyKeys) {
      await seed.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey,
        trustedEdge: source,
      });
    }

    now += 60_000;
    const replay = service(
      {
        maxRequests: 120,
        sourceMaxRequests: 2,
        replayMaxRequests: 10,
        windowMs: 60_000,
      },
      true,
    );
    for (const idempotencyKey of idempotencyKeys.slice(0, 2)) {
      await expect(
        replay.capture(body, {
          siteKey: SITE_KEY,
          origin: "https://example.test",
          idempotencyKey,
          trustedEdge: source,
        }),
      ).resolves.toMatchObject({ created: false });
    }
    await expect(
      replay.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: idempotencyKeys[2],
        trustedEdge: source,
      }),
    ).rejects.toMatchObject({ code: "rate_limited" });

    const currentWindow = await client.execute({
      sql: `SELECT scope, count FROM rate_limit_buckets
            WHERE tenant_id = ? AND window_started_at = ?
            ORDER BY scope, bucket_key_hash`,
      args: [tenantId, NOW + 60_000],
    });
    expect(
      currentWindow.rows.find((row) => row.scope === "public_consent_source"),
    ).toMatchObject({ count: 2 });
    expect(
      currentWindow.rows.filter((row) => row.scope === "public_consent_replay"),
    ).toHaveLength(2);
    expect(
      currentWindow.rows.some((row) => row.scope === "public_consent_capture"),
    ).toBe(false);
  });

  it("atomically caps concurrent libSQL bucket consumption", async () => {
    const repository = createLibsqlConsentRepository(client);
    const decisions = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        repository.consumeCaptureRateLimit({
          tenantId,
          idempotencyKey: `idem-atomic-${String(index).padStart(4, "0")}`,
          captureBucketKeyHash: "a".repeat(64),
          sourceBucketKeyHash: "c".repeat(64),
          replayBucketKeyHash: "b".repeat(64),
          windowStartedAt: NOW,
          expiresAt: NOW + 60_000,
          maxRequests: 3,
          sourceMaxRequests: 3,
          replayMaxRequests: 2,
        }),
      ),
    );

    expect(decisions.filter((decision) => decision.allowed)).toHaveLength(3);
    expect(decisions.filter((decision) => !decision.allowed)).toHaveLength(9);
    const buckets = await client.execute({
      sql: `SELECT scope, count FROM rate_limit_buckets
            WHERE tenant_id = ? AND scope IN (
              'public_consent_capture', 'public_consent_source'
            ) ORDER BY scope`,
      args: [tenantId],
    });
    expect(buckets.rows).toEqual([
      expect.objectContaining({ scope: "public_consent_capture", count: 3 }),
      expect.objectContaining({ scope: "public_consent_source", count: 3 }),
    ]);
  });

  it("blocks an abusive source without consuming the aggregate allowance", async () => {
    const capture = service(
      {
        maxRequests: 4,
        sourceMaxRequests: 2,
        replayMaxRequests: 2,
        windowMs: 60_000,
      },
      true,
    );
    const sourceA = { ip: "8.8.8.8", source: "vercel" };
    const sourceB = { ip: "1.1.1.1", source: "vercel" };
    for (const idempotencyKey of ["idem-source-a-0001", "idem-source-a-0002"]) {
      await capture.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey,
        trustedEdge: sourceA,
      });
    }
    await expect(
      capture.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-source-a-0003",
        trustedEdge: sourceA,
      }),
    ).rejects.toMatchObject({ code: "rate_limited" });
    await expect(
      capture.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-source-b-0001",
        trustedEdge: sourceB,
      }),
    ).resolves.toMatchObject({ created: true });

    const buckets = await client.execute({
      sql: `SELECT scope, count FROM rate_limit_buckets
            WHERE tenant_id = ? ORDER BY scope, bucket_key_hash`,
      args: [tenantId],
    });
    expect(
      buckets.rows.find((row) => row.scope === "public_consent_capture"),
    ).toMatchObject({ count: 3 });
    expect(
      buckets.rows
        .filter((row) => row.scope === "public_consent_source")
        .map((row) => Number(row.count))
        .sort(),
    ).toEqual([1, 2]);
  });

  it("keeps the aggregate backstop across distributed public sources", async () => {
    const capture = service(
      {
        maxRequests: 2,
        sourceMaxRequests: 2,
        replayMaxRequests: 2,
        windowMs: 60_000,
      },
      true,
    );
    for (const [index, ip] of ["8.8.8.8", "1.1.1.1"].entries()) {
      await capture.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: `idem-distributed-${index + 1}`,
        trustedEdge: { ip, source: "vercel" },
      });
    }
    await expect(
      capture.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-distributed-3",
        trustedEdge: { ip: "9.9.9.9", source: "vercel" },
      }),
    ).rejects.toMatchObject({ code: "rate_limited" });

    const buckets = await client.execute({
      sql: `SELECT scope, count FROM rate_limit_buckets
            WHERE tenant_id = ? ORDER BY scope, bucket_key_hash`,
      args: [tenantId],
    });
    expect(
      buckets.rows.find((row) => row.scope === "public_consent_capture"),
    ).toMatchObject({ count: 2 });
    expect(
      buckets.rows.filter((row) => row.scope === "public_consent_source"),
    ).toHaveLength(2);
  });

  it("fails closed when a required trusted source is unavailable", async () => {
    const capture = service(undefined, true);
    await expect(
      capture.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-source-missing",
      }),
    ).rejects.toMatchObject({ code: "source_unavailable" });

    const state = await client.execute(
      `SELECT
         (SELECT count(*) FROM rate_limit_buckets) AS buckets,
         (SELECT count(*) FROM consent_logs) AS logs`,
    );
    expect(state.rows[0]).toMatchObject({ buckets: 0, logs: 0 });
  });

  it("stores only HMACs for source limiter identities", async () => {
    const rawIp = "8.8.8.8";
    await service(undefined, true).capture(body, {
      siteKey: SITE_KEY,
      origin: "https://example.test",
      idempotencyKey: "idem-source-privacy",
      trustedEdge: { ip: rawIp, source: "vercel" },
    });

    const buckets = await client.execute(
      "SELECT bucket_key_hash FROM rate_limit_buckets",
    );
    expect(buckets.rows).toHaveLength(2);
    for (const row of buckets.rows) {
      expect(String(row.bucket_key_hash)).toMatch(/^[a-f0-9]{64}$/);
      expect(String(row.bucket_key_hash)).not.toContain(rawIp);
    }
  });

  it("treats an inactive tenant as a non-enumerating site miss", async () => {
    await client.execute({
      sql: "UPDATE tenants SET status = 'paused' WHERE id = ?",
      args: [tenantId],
    });
    await expect(
      service(undefined, true).capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-paused-tenant",
        trustedEdge: { ip: "8.8.8.8", source: "vercel" },
      }),
    ).rejects.toMatchObject({ code: "site_not_found" });
    const buckets = await client.execute(
      "SELECT count(*) AS count FROM rate_limit_buckets",
    );
    expect(Number(buckets.rows[0].count)).toBe(0);
  });

  it("gives each capture site an independent tenant-scoped allowance", async () => {
    const secondSiteId = `site-${randomUUID()}`;
    const secondSiteKey = `oiv_pk_${"d".repeat(43)}`;
    await client.execute({
      sql: `INSERT INTO capture_sites
        (id, tenant_id, name, public_key_prefix, public_key_hash,
         allowed_origins_json, form_url_pattern, disclosure_version,
         disclosure_text, controller, purpose, channels_json, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
      args: [
        secondSiteId,
        tenantId,
        "Second site",
        secondSiteKey.slice(0, 18),
        hashCaptureSiteKey(secondSiteKey, SITE_PEPPER),
        JSON.stringify(["https://example.test"]),
        "https://example.test/signup*",
        "disclosure-2026-08",
        "I agree to receive product updates by email.",
        "Example Controller Inc.",
        "Product updates",
        JSON.stringify(["email"]),
      ],
    });
    const capture = service({
      maxRequests: 1,
      sourceMaxRequests: 1,
      replayMaxRequests: 1,
      windowMs: 60_000,
    });
    await capture.capture(body, {
      siteKey: SITE_KEY,
      origin: "https://example.test",
      idempotencyKey: "idem-site-one-0001",
    });
    await expect(
      capture.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-site-one-0002",
      }),
    ).rejects.toMatchObject({ code: "rate_limited" });
    await expect(
      capture.capture(body, {
        siteKey: secondSiteKey,
        origin: "https://example.test",
        idempotencyKey: "idem-site-two-0001",
      }),
    ).resolves.toMatchObject({ captureSiteId: secondSiteId, created: true });

    const buckets = await client.execute({
      sql: `SELECT bucket_key_hash, count FROM rate_limit_buckets
            WHERE tenant_id = ? AND scope = 'public_consent_capture'`,
      args: [tenantId],
    });
    expect(buckets.rows).toHaveLength(2);
    expect(new Set(buckets.rows.map((row) => String(row.bucket_key_hash))).size).toBe(2);
    expect(buckets.rows.every((row) => Number(row.count) === 1)).toBe(true);
  });

  it("isolates capture quotas by tenant and stores only HMAC bucket keys", async () => {
    const secondTenantId = `tenant-${randomUUID()}`;
    const secondSiteId = `site-${randomUUID()}`;
    const secondSiteKey = `oiv_pk_${"c".repeat(43)}`;
    await client.batch(
      [
        {
          sql: "INSERT INTO tenants (id, slug, name) VALUES (?, ?, ?)",
          args: [secondTenantId, secondTenantId, "Second Controller"],
        },
        {
          sql: `INSERT INTO capture_sites
            (id, tenant_id, name, public_key_prefix, public_key_hash,
             allowed_origins_json, form_url_pattern, disclosure_version,
             disclosure_text, controller, purpose, channels_json, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
          args: [
            secondSiteId,
            secondTenantId,
            "Second signup",
            secondSiteKey.slice(0, 18),
            hashCaptureSiteKey(secondSiteKey, SITE_PEPPER),
            JSON.stringify(["https://example.test"]),
            "https://example.test/signup*",
            "disclosure-2026-08",
            "I agree to receive product updates by email.",
            "Second Controller Inc.",
            "Product updates",
            JSON.stringify(["email"]),
          ],
        },
      ],
      "write",
    );
    const capture = service({
      maxRequests: 1,
      sourceMaxRequests: 1,
      replayMaxRequests: 1,
      windowMs: 60_000,
    });
    await capture.capture(body, {
      siteKey: SITE_KEY,
      origin: "https://example.test",
      idempotencyKey: "idem-tenant-one-01",
    });
    await capture.capture(body, {
      siteKey: secondSiteKey,
      origin: "https://example.test",
      idempotencyKey: "idem-tenant-two-01",
    });
    await expect(
      capture.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-tenant-one-02",
      }),
    ).rejects.toMatchObject({ code: "rate_limited" });

    const buckets = await client.execute(
      `SELECT tenant_id, bucket_key_hash, count FROM rate_limit_buckets
       WHERE scope = 'public_consent_capture' ORDER BY tenant_id`,
    );
    expect(buckets.rows).toHaveLength(2);
    expect(new Set(buckets.rows.map((row) => String(row.tenant_id)))).toEqual(
      new Set([tenantId, secondTenantId]),
    );
    for (const row of buckets.rows) {
      const hash = String(row.bucket_key_hash);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
      expect(hash).not.toContain(siteId);
      expect(hash).not.toContain(secondSiteId);
      expect(hash).not.toContain("person@example.test");
      expect(Number(row.count)).toBe(1);
    }
  });

  it("fails closed before persistence when the durable limiter is unavailable", async () => {
    const repository = createLibsqlConsentRepository(client);
    const persistOrGet = vi.fn(repository.persistOrGet.bind(repository));
    const capture = createConsentService(
      {
        ...repository,
        consumeCaptureRateLimit: vi
          .fn()
          .mockRejectedValue(new Error("rate-limit database unavailable")),
        persistOrGet,
      },
      {
        siteKeyPepper: SITE_PEPPER,
        subjectHashKey: SUBJECT_KEY,
        signatureKey: SIGNATURE_KEY,
        signatureKeyVersion: 4,
        payloadEncryptionKey: ENCRYPTION_KEY,
        payloadKeyVersion: 3,
        retentionMs: RETENTION_MS,
        requireTrustedSource: false,
        now: () => now,
      },
    );

    await expect(
      capture.capture(body, {
        siteKey: SITE_KEY,
        origin: "https://example.test",
        idempotencyKey: "idem-rate-fail-closed",
      }),
    ).rejects.toThrow("rate-limit database unavailable");
    expect(persistOrGet).not.toHaveBeenCalled();
    const stored = await client.execute("SELECT count(*) AS count FROM consent_logs");
    expect(Number(stored.rows[0].count)).toBe(0);
  });
});
