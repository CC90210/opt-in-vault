import "server-only";

import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";

import { schema } from "./schema";
import type { OptInVaultDatabase } from "./types";

export type DatabaseConnection = {
  client: Client;
  db: OptInVaultDatabase;
};

export async function createDatabase(options: {
  url: string;
  authToken?: string;
}): Promise<DatabaseConnection> {
  if (!options.url.trim()) {
    throw new Error("TURSO_DATABASE_URL is required");
  }

  const client = createClient({
    url: options.url,
    authToken: options.authToken || undefined,
  });
  await client.execute("PRAGMA foreign_keys = ON");

  return {
    client,
    db: drizzle(client, { schema }),
  };
}
