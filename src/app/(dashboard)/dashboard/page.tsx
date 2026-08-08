import type { Metadata } from "next";

import {
  DataUnavailable,
  OverviewView,
} from "@/components/dashboard/dashboard-views";

import { loadDashboardSnapshot } from "../_lib/dashboard-context";

export const metadata: Metadata = { title: "Overview" };

export default async function DashboardOverviewPage() {
  try {
    return <OverviewView snapshot={await loadDashboardSnapshot()} />;
  } catch (error) {
    if (isNextControlFlow(error)) throw error;
    console.error("Dashboard overview query failed", error);
    return <DataUnavailable resource="Dashboard overview" />;
  }
}

function isNextControlFlow(error: unknown): boolean {
  return Boolean(
    error &&
      typeof error === "object" &&
      "digest" in error &&
      typeof error.digest === "string" &&
      error.digest.startsWith("NEXT_"),
  );
}
