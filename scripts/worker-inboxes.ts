import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { config } from "dotenv";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
config({ path: resolve(projectRoot, ".env.local") });

async function main(): Promise<void> {
  const [{ getDatabase, closeDatabase }, { parseCredentialEncryptionKeyRing }, { pollConfiguredInboxes }] =
    await Promise.all([
      import("../src/db/client"),
      import("../src/server/security/credential-keyring"),
      import("../src/server/inbound/poll"),
    ]);
  try {
    const suppressionHashKey = process.env.SUPPRESSION_HASH_KEY;
    if (!suppressionHashKey) {
      throw new Error("Inbox worker secrets are not configured");
    }
    const database = await getDatabase();
    const result = await pollConfiguredInboxes(database.client, {
      credentialKeys: parseCredentialEncryptionKeyRing(process.env),
      suppressionHashKey,
      maxInboxes: 10,
      maxMessagesPerInbox: 25,
      maxCycleMs: 45_000,
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (result.failures > 0) process.exitCode = 1;
  } finally {
    await closeDatabase();
  }
}

main().catch((error: unknown) => {
  const rawName = error instanceof Error ? error.name : "Error";
  const errorName = /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(rawName)
    ? rawName
    : "Error";
  process.stderr.write(
    `${JSON.stringify({ code: "inbox_worker_failed", errorName })}\n`,
  );
  process.exitCode = 1;
});
