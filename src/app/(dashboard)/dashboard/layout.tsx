import { DashboardShell } from "@/components/dashboard/dashboard-shell";

import { loadDashboardSnapshot } from "../_lib/dashboard-context";

export const dynamic = "force-dynamic";

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const snapshot = await loadDashboardSnapshot();
  return <DashboardShell tenant={snapshot.tenant}>{children}</DashboardShell>;
}
