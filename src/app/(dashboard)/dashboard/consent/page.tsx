import type { Metadata } from "next";

import {
  ConsentView,
  DataUnavailable,
} from "@/components/dashboard/dashboard-views";
import { getConsentRecords } from "@/server/dashboard/queries";

import { requireDashboardContext } from "../../_lib/dashboard-context";

export const metadata: Metadata = { title: "Consent vault" };

export default async function ConsentPage() {
  const { client, principal } = await requireDashboardContext();
  try {
    const result = await getConsentRecords(client, principal.tenantId);
    return <ConsentView records={result.items} total={result.total} />;
  } catch (error) {
    console.error("Consent evidence query failed", error);
    return <DataUnavailable resource="Consent evidence" />;
  }
}
