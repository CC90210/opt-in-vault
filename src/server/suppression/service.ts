import "server-only";

import { createHmac, randomUUID } from "node:crypto";

import type { Client, InStatement, ResultSet, Transaction } from "@libsql/client";

export type SuppressionIdentifierType = "email" | "sms";

type SqlExecutor = {
  execute(statement: InStatement): Promise<ResultSet>;
};

export type AddSuppressionInput = {
  tenantId: string;
  identifierType: SuppressionIdentifierType;
  identifier: string;
  reason: string;
  source: string;
  hashKey: string;
};

export type AddSuppressionResult = {
  suppressionId: string;
  created: boolean;
  cancelledJobs: number;
};

function requireHashKey(hashKey: string): void {
  if (Buffer.byteLength(hashKey, "utf8") < 32) {
    throw new Error("Suppression hash key must contain at least 32 bytes");
  }
}

export function normalizeEmail(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (
    normalized.length > 320 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized) ||
    /[\u0000-\u001f\u007f]/.test(normalized)
  ) {
    throw new Error("Invalid email address");
  }
  return normalized;
}

export function normalizePhone(value: string): string {
  const normalized = value.trim().replace(/[\s().-]/g, "");
  if (!/^\+[1-9]\d{7,14}$/.test(normalized)) {
    throw new Error("Phone number must be in E.164 format");
  }
  return normalized;
}

export function normalizeIdentifier(
  identifierType: SuppressionIdentifierType,
  value: string,
): string {
  return identifierType === "email"
    ? normalizeEmail(value)
    : normalizePhone(value);
}

export function hashSuppressionIdentifier(
  identifierType: SuppressionIdentifierType,
  normalizedIdentifier: string,
  hashKey: string,
): string {
  requireHashKey(hashKey);
  return createHmac("sha256", hashKey)
    .update(`opt-in-vault:suppression:v1:${identifierType}\0`)
    .update(normalizedIdentifier)
    .digest("hex");
}

function requireInternalLabel(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 100 || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error(`Invalid suppression ${field}`);
  }
  return normalized;
}

export async function addSuppressionWithinTransaction(
  transaction: Transaction,
  input: AddSuppressionInput,
): Promise<AddSuppressionResult> {
  const tenantId = input.tenantId.trim();
  if (!tenantId) {
    throw new Error("Tenant identity is required");
  }

  const identifier = normalizeIdentifier(input.identifierType, input.identifier);
  const identifierHash = hashSuppressionIdentifier(
    input.identifierType,
    identifier,
    input.hashKey,
  );
  const suppressionId = randomUUID();
  const inserted = await transaction.execute({
    sql: `
      INSERT INTO suppressions
        (id, tenant_id, identifier_type, identifier_hash, reason, source)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT (tenant_id, identifier_type, identifier_hash) DO NOTHING
      RETURNING id
    `,
    args: [
      suppressionId,
      tenantId,
      input.identifierType,
      identifierHash,
      requireInternalLabel(input.reason, "reason"),
      requireInternalLabel(input.source, "source"),
    ],
  });
  const created = inserted.rows.length === 1;
  let resolvedSuppressionId: string = suppressionId;

  if (!created) {
    const existing = await transaction.execute({
      sql: `
        SELECT id FROM suppressions
        WHERE tenant_id = ? AND identifier_type = ? AND identifier_hash = ?
        LIMIT 1
      `,
      args: [tenantId, input.identifierType, identifierHash],
    });
    if (!existing.rows[0]?.id) {
      throw new Error("Suppression upsert could not be reconciled");
    }
    resolvedSuppressionId = String(existing.rows[0].id);
  } else {
    await transaction.execute({
      sql: `
        INSERT INTO suppression_events
          (id, tenant_id, suppression_id, action, source, metadata_json)
        VALUES (?, ?, ?, 'added', ?, '{}')
      `,
      args: [randomUUID(), tenantId, resolvedSuppressionId, input.source],
    });
  }

  const identifierColumn =
    input.identifierType === "email" ? "normalized_email" : "normalized_phone";
  await transaction.execute({
    sql: `
      UPDATE leads SET status = 'unsubscribed', updated_at = ?
      WHERE tenant_id = ? AND ${identifierColumn} = ?
        AND status NOT IN ('archived', 'complained')
    `,
    args: [Date.now(), tenantId, identifier],
  });
  await transaction.execute({
    sql: `
      UPDATE campaign_enrollments
      SET status = 'unsubscribed', pause_reason = 'suppressed', updated_at = ?
      WHERE tenant_id = ?
        AND lead_id IN (
          SELECT id FROM leads WHERE tenant_id = ? AND ${identifierColumn} = ?
        )
        AND status IN ('pending', 'active', 'paused')
    `,
    args: [Date.now(), tenantId, tenantId, identifier],
  });
  const cancelled = await transaction.execute({
    sql: `
      UPDATE send_jobs
      SET status = 'cancelled', lease_token_hash = NULL,
          lease_expires_at = NULL, last_error_code = 'suppressed', updated_at = ?
      WHERE tenant_id = ?
        AND status IN ('queued', 'leased')
        AND enrollment_id IN (
          SELECT enrollment.id
          FROM campaign_enrollments AS enrollment
          JOIN leads AS lead
            ON lead.tenant_id = enrollment.tenant_id AND lead.id = enrollment.lead_id
          WHERE enrollment.tenant_id = ? AND lead.${identifierColumn} = ?
        )
    `,
    args: [Date.now(), tenantId, tenantId, identifier],
  });

  return {
    suppressionId: resolvedSuppressionId,
    created,
    cancelledJobs: cancelled.rowsAffected,
  };
}

export async function addSuppression(
  client: Client,
  input: AddSuppressionInput,
): Promise<AddSuppressionResult> {
  const transaction = await client.transaction("write");
  try {
    const result = await addSuppressionWithinTransaction(transaction, input);
    await transaction.commit();
    return result;
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
}

export async function isSuppressed(
  executor: SqlExecutor,
  input: Pick<
    AddSuppressionInput,
    "tenantId" | "identifierType" | "identifier" | "hashKey"
  >,
): Promise<boolean> {
  const normalized = normalizeIdentifier(input.identifierType, input.identifier);
  const identifierHash = hashSuppressionIdentifier(
    input.identifierType,
    normalized,
    input.hashKey,
  );
  const result = await executor.execute({
    sql: `
      SELECT 1 FROM suppressions
      WHERE tenant_id = ? AND identifier_type = ? AND identifier_hash = ?
      LIMIT 1
    `,
    args: [input.tenantId, input.identifierType, identifierHash],
  });
  return result.rows.length === 1;
}
