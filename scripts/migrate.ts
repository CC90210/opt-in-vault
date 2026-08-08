import { createClient } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";
import { config } from "dotenv";

config({ path: ".env.local" });

async function main() {
  const url = process.env.TURSO_DATABASE_URL;
  if (!url) {
    throw new Error("TURSO_DATABASE_URL is required to run migrations");
  }

  const client = createClient({
    url,
    authToken: process.env.TURSO_AUTH_TOKEN || undefined,
  });

  try {
    await client.execute("PRAGMA foreign_keys = ON");
    await migrate(drizzle(client), { migrationsFolder: "drizzle" });

    const violations = await client.execute("PRAGMA foreign_key_check");
    if (violations.rows.length > 0) {
      throw new Error(
        `Migration left ${violations.rows.length} foreign-key violation(s)`,
      );
    }

    process.stdout.write("Migration complete; foreign_key_check: 0 violations\n");
  } finally {
    client.close();
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown migration failure";
  process.stderr.write(`Migration failed: ${message}\n`);
  process.exitCode = 1;
});

