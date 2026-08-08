import type { Metadata } from "next";

import {
  DataUnavailable,
  InboxHealthView,
} from "@/components/dashboard/dashboard-views";
import { getInboxHealth } from "@/server/dashboard/queries";

import { requireDashboardContext } from "../../_lib/dashboard-context";

export const metadata: Metadata = { title: "Inboxes & domains" };

export default async function InboxesPage() {
  const { client, principal } = await requireDashboardContext();
  try {
    const result = await getInboxHealth(client, principal.tenantId);
    return <InboxHealthView inboxes={result.items} total={result.total} />;
  } catch (error) {
    console.error("Inbox and domain health query failed", error);
    return <DataUnavailable resource="Inbox and domain health" />;
  }
}
