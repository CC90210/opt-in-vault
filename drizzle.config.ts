import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { config } from "dotenv";
import { defineConfig } from "drizzle-kit";

const projectRoot = dirname(fileURLToPath(import.meta.url));
process.chdir(projectRoot);
config({ path: resolve(projectRoot, ".env.local") });

function resolveDatabaseUrl(rawUrl: string): string {
  if (rawUrl.startsWith("file:./") || rawUrl.startsWith("file:../")) {
    return pathToFileURL(resolve(projectRoot, rawUrl.slice("file:".length))).href;
  }
  return rawUrl;
}

const databaseUrl = resolveDatabaseUrl(
  process.env.TURSO_DATABASE_URL ?? "file:./data/opt-in-vault.db",
);
if (databaseUrl.startsWith("file:") && !databaseUrl.startsWith("file::memory:")) {
  mkdirSync(dirname(fileURLToPath(databaseUrl)), { recursive: true });
}

export default defineConfig({
  out: "./drizzle",
  schema: "./src/db/schema.ts",
  dialect: "turso",
  dbCredentials: {
    url: databaseUrl,
    authToken: process.env.TURSO_AUTH_TOKEN,
  },
  strict: true,
  verbose: true,
});
