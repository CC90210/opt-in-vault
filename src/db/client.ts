import "server-only";

import { createDatabase, type DatabaseConnection } from "./connect";

type DatabaseRegistry = {
  connection?: DatabaseConnection;
  promise?: Promise<DatabaseConnection>;
};

const globalDatabase = globalThis as typeof globalThis & {
  __optInVaultDatabase?: DatabaseRegistry;
};

const registry = (globalDatabase.__optInVaultDatabase ??= {});

export async function getDatabase(): Promise<DatabaseConnection> {
  if (registry.connection) return registry.connection;
  if (!registry.promise) {
    registry.promise = (async () => {
      const databaseUrl = process.env.TURSO_DATABASE_URL;
      if (!databaseUrl) {
        throw new Error(
          "TURSO_DATABASE_URL is required to initialize the server database",
        );
      }
      const connection = await createDatabase({
        url: databaseUrl,
        authToken: process.env.TURSO_AUTH_TOKEN,
      });
      registry.connection = connection;
      return connection;
    })().catch((error) => {
      registry.promise = undefined;
      throw error;
    });
  }
  return registry.promise;
}

export async function closeDatabase(): Promise<void> {
  const connection = registry.connection ?? (await registry.promise);
  connection?.client.close();
  registry.connection = undefined;
  registry.promise = undefined;
}
