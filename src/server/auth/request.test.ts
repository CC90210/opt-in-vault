import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";

import { createApiKey } from "./api-keys";
import { authenticateRequest, parseApiKeyPepperRing } from "./request";
import {
  createSessionToken,
  SESSION_COOKIE_NAME,
} from "./session";

const MIGRATIONS_FOLDER = fileURLToPath(
  new URL("../../../drizzle", import.meta.url),
);
const PEPPER = "test-only-api-pepper-with-at-least-32-bytes";
const SESSION_SECRET = "test-only-session-secret-with-at-least-32-bytes";

describe("request authentication repository", () => {
  let client: Client;
  let tenantId: string;
  let rawKey: string;

  beforeEach(async () => {
    client = createClient({ url: "file::memory:?cache=shared" });
    await migrate(drizzle(client), { migrationsFolder: MIGRATIONS_FOLDER });
    await client.execute("PRAGMA foreign_keys = ON");
    tenantId = `tenant-${randomUUID()}`;
    const key = createApiKey(PEPPER, 1);
    rawKey = key.rawKey;
    await client.batch(
      [
        {
          sql: "INSERT INTO tenants (id, slug, name, status) VALUES (?, ?, 'Tenant', 'active')",
          args: [tenantId, tenantId],
        },
        {
          sql: "INSERT INTO tenant_api_keys (id, tenant_id, prefix, key_hash, hash_key_version, scopes_json) VALUES (?, ?, ?, ?, ?, ?)",
          args: [
            `key-${tenantId}`,
            tenantId,
            key.prefix,
            key.hash,
            key.hashKeyVersion,
            JSON.stringify(["dashboard:read", "domains:write"]),
          ],
        },
      ],
      "write",
    );
  });

  afterEach(() => client.close());

  it("derives tenant identity and scopes from a valid bearer key", async () => {
    const principal = await authenticateRequest(
      client,
      new Request("https://vault.example/api", {
        headers: { authorization: `Bearer ${rawKey}` },
      }),
      {
        apiKeyPeppers: new Map([[1, PEPPER]]),
        sessionSecret: SESSION_SECRET,
        requiredScope: "domains:write",
        now: () => 1_800_000_000_000,
      },
    );
    expect(principal).toMatchObject({ tenantId, authType: "api_key" });
  });

  it("accepts a signed session but rechecks live tenant state and required scope", async () => {
    const token = createSessionToken(
      {
        tenantId,
        scopes: ["dashboard:read"],
        expiresAt: 1_800_000_100_000,
      },
      SESSION_SECRET,
      { now: 1_800_000_000_000 },
    );
    const request = new Request("https://vault.example/dashboard", {
      headers: { cookie: `${SESSION_COOKIE_NAME}=${token}` },
    });
    await expect(
      authenticateRequest(client, request, {
        apiKeyPeppers: new Map([[1, PEPPER]]),
        sessionSecret: SESSION_SECRET,
        requiredScope: "dashboard:read",
        now: () => 1_800_000_000_000,
      }),
    ).resolves.toMatchObject({ tenantId, authType: "session" });

    await client.execute({
      sql: "UPDATE tenants SET status = 'paused' WHERE id = ?",
      args: [tenantId],
    });
    await expect(
      authenticateRequest(client, request, {
        apiKeyPeppers: new Map([[1, PEPPER]]),
        sessionSecret: SESSION_SECRET,
        requiredScope: "dashboard:read",
        now: () => 1_800_000_000_000,
      }),
    ).resolves.toBeNull();
  });

  it("fails closed for malformed auth, missing scopes, and invalid JSON records", async () => {
    await expect(
      authenticateRequest(
        client,
        new Request("https://vault.example/api", {
          headers: { authorization: `Bearer ${rawKey}` },
        }),
        {
          apiKeyPeppers: new Map([[1, PEPPER]]),
          sessionSecret: SESSION_SECRET,
          requiredScope: "admin:write",
        },
      ),
    ).resolves.toBeNull();
    await expect(
      authenticateRequest(
        client,
        new Request("https://vault.example/api", {
          headers: { authorization: "Bearer bad token" },
        }),
        { apiKeyPeppers: new Map([[1, PEPPER]]), sessionSecret: SESSION_SECRET },
      ),
    ).resolves.toBeNull();
  });

  it("loads bounded historical API-key peppers for zero-downtime rotation", () => {
    const previous = "previous-api-key-pepper-that-is-at-least-32-bytes";
    const ring = parseApiKeyPepperRing({
      API_KEY_PEPPER: PEPPER,
      API_KEY_PEPPER_VERSION: "2",
      API_KEY_PEPPERS_JSON: JSON.stringify({ 1: previous }),
    });

    expect([...ring.entries()]).toEqual([
      [1, previous],
      [2, PEPPER],
    ]);
    expect(
      parseApiKeyPepperRing({
        API_KEY_PEPPER: PEPPER,
        API_KEY_PEPPER_VERSION: "2",
        API_KEY_PEPPERS_JSON: "not-json",
      }).size,
    ).toBe(0);
  });
});
