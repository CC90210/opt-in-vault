import type { LibSQLDatabase } from "drizzle-orm/libsql";

import type { schema } from "./schema";

export type OptInVaultDatabase = LibSQLDatabase<typeof schema>;

