import type { Metadata } from "next";

import {
  CampaignsView,
  DataUnavailable,
} from "@/components/dashboard/dashboard-views";
import { getCampaigns } from "@/server/dashboard/queries";

import { requireDashboardContext } from "../../_lib/dashboard-context";

export const metadata: Metadata = { title: "Campaigns" };

export default async function CampaignsPage() {
  const { client, principal } = await requireDashboardContext();
  try {
    const result = await getCampaigns(client, principal.tenantId);
    return <CampaignsView campaigns={result.items} total={result.total} />;
  } catch (error) {
    console.error("Campaign ledger query failed", error);
    return <DataUnavailable resource="Campaign ledger" />;
  }
}
