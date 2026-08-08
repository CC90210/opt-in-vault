import "server-only";

import { createDatabase } from "./connect";

const databaseUrl = process.env.TURSO_DATABASE_URL;

if (!databaseUrl) {
  throw new Error("TURSO_DATABASE_URL is required to initialize the server database");
}

export const database = await createDatabase({
  url: databaseUrl,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

export const db = database.db;

