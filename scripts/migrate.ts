import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createClient } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";
import { config } from "dotenv";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const migrationsFolder = resolve(projectRoot, "drizzle");

config({ path: resolve(projectRoot, ".env.local") });

function resolveDatabaseUrl(rawUrl: string): string {
  if (rawUrl.startsWith("file:./") || rawUrl.startsWith("file:../")) {
    return pathToFileURL(resolve(projectRoot, rawUrl.slice("file:".length))).href;
  }
  return rawUrl;
}

function ensureLocalDatabaseDirectory(url: string): void {
  if (!url.startsWith("file:") || url.startsWith("file::memory:")) return;
  mkdirSync(dirname(fileURLToPath(url)), { recursive: true });
}

async function main() {
  const configuredUrl = process.env.TURSO_DATABASE_URL;
  if (!configuredUrl) {
    throw new Error("TURSO_DATABASE_URL is required to run migrations");
  }
  const url = resolveDatabaseUrl(configuredUrl);
  ensureLocalDatabaseDirectory(url);

  const client = createClient({
    url,
    authToken: process.env.TURSO_AUTH_TOKEN || undefined,
  });

  try {
    await client.execute("PRAGMA foreign_keys = ON");
    await migrate(drizzle(client), { migrationsFolder });

    const violations = await client.execute("PRAGMA foreign_key_check");
    if (violations.rows.length > 0) {
      throw new Error(
        `Migration left ${violations.rows.length} foreign-key violation(s)`,
      );
    }

    const triggers = await client.execute(`
      SELECT name FROM sqlite_schema
      WHERE type = 'trigger'
        AND name IN ('consent_logs_immutable_update', 'consent_logs_immutable_delete')
      ORDER BY name
    `);
    if (triggers.rows.length !== 2) {
      throw new Error(
        "Migration invariant failed: immutable consent triggers are missing",
      );
    }

    process.stdout.write(
      "Migration complete; foreign_key_check: 0 violations; consent_triggers: 2\n",
    );
  } finally {
    client.close();
  }
}

main().catch((error: unknown) => {
  const message =
    error instanceof Error ? error.message : "Unknown migration failure";
  process.stderr.write(`Migration failed: ${message}\n`);
  process.exitCode = 1;
});
