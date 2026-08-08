import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createClient } from "@libsql/client";
import { config } from "dotenv";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const reactServerChildMarker = "OPT_IN_VAULT_DISPATCH_REACT_SERVER_CHILD";

config({ path: resolve(projectRoot, ".env.local") });

function resolveDatabaseUrl(rawUrl: string): string {
  if (rawUrl.startsWith("file:./") || rawUrl.startsWith("file:../")) {
    return pathToFileURL(resolve(projectRoot, rawUrl.slice("file:".length))).href;
  }
  return rawUrl;
}

function requireEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required for the dispatch worker`);
  return value;
}

function boundedLimit(): number {
  const flagIndex = process.argv.indexOf("--limit");
  const raw =
    flagIndex >= 0 ? process.argv[flagIndex + 1] : process.env.DISPATCH_BATCH_SIZE;
  if (raw === undefined) return 25;
  if (!/^\d{1,3}$/.test(raw)) {
    throw new Error("Dispatch worker limit must be an integer between 1 and 50");
  }
  const limit = Number(raw);
  if (limit < 1 || limit > 50) {
    throw new Error("Dispatch worker limit must be an integer between 1 and 50");
  }
  return limit;
}

function safeErrorMessage(error: unknown): string {
  const message =
    error instanceof Error ? error.message : "Unknown dispatch worker failure";
  return message
    .replace(/(?:libsql|https?):\/\/[^\s]+/gi, "[database-url]")
    .replace(/[\r\n\u0000]+/g, " ")
    .slice(0, 500);
}

async function runOneCycle(): Promise<void> {
  const databaseUrl = resolveDatabaseUrl(
    requireEnvironment("TURSO_DATABASE_URL"),
  );
  const leasePepper = requireEnvironment("DISPATCH_LEASE_PEPPER");
  const unsubscribeTokenSecret = requireEnvironment(
    "UNSUBSCRIBE_TOKEN_SECRET",
  );
  const suppressionHashKey = requireEnvironment("SUPPRESSION_HASH_KEY");
  const appBaseUrl = requireEnvironment("NEXT_PUBLIC_APP_URL");
  const client = createClient({
    url: databaseUrl,
    authToken: process.env.TURSO_AUTH_TOKEN || undefined,
  });

  try {
    await client.execute("PRAGMA foreign_keys = ON");
    const migrated = await client.execute(
      "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'send_jobs'",
    );
    if (migrated.rows.length !== 1) {
      throw new Error(
        "Dispatch database is not migrated; run npm run db:migrate first",
      );
    }

    const [
      { createDispatchRepository },
      { createDispatchService },
      { createConfiguredGatewayTransport },
      { parseCredentialEncryptionKeyRing },
    ] =
      await Promise.all([
        import("../src/server/dispatch/repository"),
        import("../src/server/dispatch/service"),
        import("../src/server/email/configured-transport"),
        import("../src/server/security/credential-keyring"),
      ]);
    const repository = createDispatchRepository(client, { leasePepper });
    const service = createDispatchService({
      repository,
      liveSendsEnabled: process.env.LIVE_SENDS_ENABLED === "true",
      transportFactory: async (context) =>
        createConfiguredGatewayTransport(context, {
          credentialKeys: parseCredentialEncryptionKeyRing(process.env),
        }),
      appBaseUrl,
      unsubscribeTokenSecret,
      suppressionHashKey,
    });
    const summary = await service.runCycle({ limit: boundedLimit() });
    process.stdout.write(`${JSON.stringify(summary)}\n`);
  } finally {
    client.close();
  }
}

async function bootstrap(): Promise<void> {
  // `server-only` resolves to an empty marker only under the react-server
  // condition. The npm script cannot carry that condition, so re-enter once
  // before loading the server service graph.
  if (process.env[reactServerChildMarker] !== "1") {
    const child = spawnSync(
      process.execPath,
      [
        "--conditions=react-server",
        "--import",
        "tsx",
        fileURLToPath(import.meta.url),
        ...process.argv.slice(2),
      ],
      {
        cwd: projectRoot,
        env: { ...process.env, [reactServerChildMarker]: "1" },
        stdio: "inherit",
        windowsHide: true,
      },
    );
    if (child.error) throw child.error;
    process.exitCode = child.status ?? 1;
    return;
  }

  await runOneCycle();
}

bootstrap().catch((error: unknown) => {
  process.stderr.write(`Dispatch worker failed: ${safeErrorMessage(error)}\n`);
  process.exitCode = 1;
});
