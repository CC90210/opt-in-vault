import { randomUUID } from "node:crypto";
import { join } from "node:path";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";
import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";

vi.mock("server-only", () => ({}));

import {
  buildCaptureSnippet,
  createCaptureSite,
  generateCaptureSiteKey,
  updateCaptureSiteStatus,
  CaptureSiteNotFoundError,
  CaptureSiteTransitionError,
  CaptureSiteValidationError,
} from "./sites";
import { hashCaptureSiteKey } from "./service";

const SITE_PEPPER = "site-pepper-with-at-least-thirty-two-bytes";

describe("capture site administration", () => {
  let client: Client;
  let tenantId: string;

  beforeEach(async () => {
    client = createClient({ url: "file::memory:" });
    await migrate(drizzle(client), { migrationsFolder: join(process.cwd(), "drizzle") });
    await client.execute("PRAGMA foreign_keys = ON");
    tenantId = `tenant-${randomUUID()}`;

    await client.execute({
      sql: "INSERT INTO tenants (id, slug, name) VALUES (?, ?, ?)",
      args: [tenantId, tenantId, "Test Tenant"],
    });
  });

  afterEach(() => {
    client.close();
  });

  describe("generateCaptureSiteKey", () => {
    it("generates a raw key matching oiv_pk_ format and 18-char prefix", () => {
      const { rawKey, prefix, hash } = generateCaptureSiteKey(SITE_PEPPER);
      expect(rawKey).toMatch(/^oiv_pk_[A-Za-z0-9_-]{43}$/);
      expect(prefix).toBe(rawKey.slice(0, 18));
      expect(hash).toBe(hashCaptureSiteKey(rawKey, SITE_PEPPER));
    });
  });

  describe("createCaptureSite", () => {
    it("creates an active capture site and stores hashed key", async () => {
      const input = {
        name: "Main Lead Form",
        allowedOrigins: ["https://example.com"],
        formUrlPattern: "https://example.com/join*",
        disclosureVersion: "2026-08-01",
        disclosureText: "By submitting this form, you agree...",
        controller: "OASIS AI Solutions",
        purpose: "Product updates and newsletter",
        channels: ["email"],
      };

      const result = await createCaptureSite(client, tenantId, input, {
        siteKeyPepper: SITE_PEPPER,
        now: () => 1700000000000,
      });

      expect(result.site.name).toBe("Main Lead Form");
      expect(result.site.status).toBe("active");
      expect(result.site.publicKeyPrefix).toBe(result.rawKey.slice(0, 18));
      expect(result.site.allowedOrigins).toEqual(["https://example.com"]);
      expect(result.site.channels).toEqual(["email"]);

      const row = await client.execute({
        sql: "SELECT * FROM capture_sites WHERE id = ?",
        args: [result.site.id],
      });
      expect(row.rows.length).toBe(1);
    });

    it("rejects invalid input schema with CaptureSiteValidationError", async () => {
      await expect(
        createCaptureSite(
          client,
          tenantId,
          { name: "" },
          { siteKeyPepper: SITE_PEPPER },
        ),
      ).rejects.toThrow(CaptureSiteValidationError);
    });
  });

  describe("updateCaptureSiteStatus", () => {
    it("transitions active site to paused and revoked", async () => {
      const { site } = await createCaptureSite(
        client,
        tenantId,
        {
          name: "Form 1",
          allowedOrigins: ["https://example.com"],
          disclosureVersion: "1.0",
          disclosureText: "Terms",
          controller: "Corp",
          purpose: "Outreach",
          channels: ["email"],
        },
        { siteKeyPepper: SITE_PEPPER },
      );

      const paused = await updateCaptureSiteStatus(client, tenantId, site.id, "paused");
      expect(paused.status).toBe("paused");

      const revoked = await updateCaptureSiteStatus(client, tenantId, site.id, "revoked");
      expect(revoked.status).toBe("revoked");

      await expect(
        updateCaptureSiteStatus(client, tenantId, site.id, "active"),
      ).rejects.toThrow(CaptureSiteTransitionError);
    });

    it("throws CaptureSiteNotFoundError for non-existent site", async () => {
      await expect(
        updateCaptureSiteStatus(client, tenantId, "non-existent", "paused"),
      ).rejects.toThrow(CaptureSiteNotFoundError);
    });
  });

  describe("buildCaptureSnippet", () => {
    it("generates script snippet with configured endpoint and site key", () => {
      const { rawKey } = generateCaptureSiteKey(SITE_PEPPER);
      const snippet = buildCaptureSnippet({
        appBaseUrl: "https://vault.example.com",
        siteKey: rawKey,
        disclosureVersion: "2026-08-01",
      });

      expect(snippet).toContain('<script src="https://vault.example.com/v1/optinvault.js"></script>');
      expect(snippet).toContain('endpoint: "https://vault.example.com/api/v1/consent/log"');
      expect(snippet).toContain(`siteKey: "${rawKey}"`);
      expect(snippet).toContain('disclosureVersion: "2026-08-01"');
    });

    it("throws on invalid site key or appBaseUrl", () => {
      expect(() =>
        buildCaptureSnippet({
          appBaseUrl: "http://unsecure.com",
          siteKey: "invalid_key",
          disclosureVersion: "1.0",
        }),
      ).toThrow();
    });
  });
});
