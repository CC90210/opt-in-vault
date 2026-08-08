import "server-only";

import type { Client } from "@libsql/client";

import { addSuppressionWithinTransaction } from "@/server/suppression/service";

import { hashUnsubscribeToken, isUnsubscribeTokenShape } from "./tokens";

export type UnsubscribeStatus =
  | "active"
  | "unsubscribed"
  | "expired"
  | "invalid";

type UnsubscribeOptions = {
  tokenSecret: string;
  suppressionHashKey: string;
  now?: () => number;
};

type TokenRecord = {
  tenantId: string;
  leadId: string;
  identifier: string;
  usedAt: number | null;
  expiresAt: number | null;
};

async function findToken(
  client: Pick<Client, "execute">,
  rawToken: string,
  tokenSecret: string,
): Promise<TokenRecord | null> {
  if (!isUnsubscribeTokenShape(rawToken)) {
    return null;
  }
  const tokenHash = hashUnsubscribeToken(rawToken, tokenSecret);
  const result = await client.execute({
    sql: `
      SELECT token.tenant_id, token.lead_id, token.used_at, token.expires_at,
             lead.normalized_email
      FROM unsubscribe_tokens AS token
      JOIN leads AS lead
        ON lead.tenant_id = token.tenant_id AND lead.id = token.lead_id
      WHERE token.token_hash = ? AND token.revoked_at IS NULL
      LIMIT 1
    `,
    args: [tokenHash],
  });
  const row = result.rows[0];
  if (!row?.tenant_id || !row.lead_id || !row.normalized_email) {
    return null;
  }
  return {
    tenantId: String(row.tenant_id),
    leadId: String(row.lead_id),
    identifier: String(row.normalized_email),
    usedAt: row.used_at == null ? null : Number(row.used_at),
    expiresAt: row.expires_at == null ? null : Number(row.expires_at),
  };
}

export function createUnsubscribeService(
  client: Client,
  options: UnsubscribeOptions,
) {
  const now = options.now ?? Date.now;

  return {
    async preview(rawToken: string): Promise<{ status: UnsubscribeStatus }> {
      const record = await findToken(client, rawToken, options.tokenSecret);
      if (!record) return { status: "invalid" };
      if (record.expiresAt !== null && record.expiresAt <= now()) {
        return { status: "expired" };
      }
      return { status: record.usedAt === null ? "active" : "unsubscribed" };
    },

    async apply(rawToken: string): Promise<{ status: UnsubscribeStatus }> {
      const transaction = await client.transaction("write");
      try {
        const record = await findToken(
          transaction as unknown as Pick<Client, "execute">,
          rawToken,
          options.tokenSecret,
        );
        if (!record) {
          await transaction.rollback();
          return { status: "invalid" };
        }
        if (record.expiresAt !== null && record.expiresAt <= now()) {
          await transaction.rollback();
          return { status: "expired" };
        }

        await addSuppressionWithinTransaction(transaction, {
          tenantId: record.tenantId,
          identifierType: "email",
          identifier: record.identifier,
          reason: "unsubscribe",
          source: "one_click",
          hashKey: options.suppressionHashKey,
        });
        await transaction.execute({
          sql: `
            UPDATE unsubscribe_tokens
            SET used_at = COALESCE(used_at, ?)
            WHERE tenant_id = ? AND lead_id = ? AND token_hash = ?
          `,
          args: [
            now(),
            record.tenantId,
            record.leadId,
            hashUnsubscribeToken(rawToken, options.tokenSecret),
          ],
        });
        await transaction.commit();
        return { status: "unsubscribed" };
      } catch (error) {
        if (!transaction.closed) await transaction.rollback();
        throw error;
      }
    },
  };
}
