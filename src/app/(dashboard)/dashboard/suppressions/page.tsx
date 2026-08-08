import type { Metadata } from "next";

import {
  DataUnavailable,
  SuppressionsView,
} from "@/components/dashboard/dashboard-views";
import { getSuppressions } from "@/server/dashboard/queries";

import { requireDashboardContext } from "../../_lib/dashboard-context";

export const metadata: Metadata = { title: "Suppressions" };

export default async function SuppressionsPage() {
  const { client, principal } = await requireDashboardContext();
  try {
    const result = await getSuppressions(client, principal.tenantId);
    return (
      <SuppressionsView suppressions={result.items} total={result.total} />
    );
  } catch (error) {
    console.error("Suppression ledger query failed", error);
    return <DataUnavailable resource="Suppression ledger" />;
  }
}
