import { render, screen, within } from "@testing-library/react";

import {
  CampaignsView,
  ConsentView,
  InboxHealthView,
  OverviewView,
  SuppressionsView,
} from "./dashboard-views";

describe("live dashboard views", () => {
  it("renders the overview from its supplied live snapshot", () => {
    render(
      <OverviewView
        snapshot={{
          tenant: { id: "tenant-1", name: "OASIS", status: "active" },
          metrics: {
            activeCampaigns: 3,
            activeInboxes: 4,
            healthyDomains: 2,
            domainsNeedingAttention: 1,
            pendingMessages: 17,
            unknownDeliveries: 2,
            consentRecords: 81,
            suppressions: 6,
            pendingNotifications: 1,
          },
          chain: [
            { kind: "consent", state: "sealed", occurredAt: 1_800_000_000_000 },
            { kind: "delivery", state: "accepted", occurredAt: 1_799_999_000_000 },
          ],
        }}
      />,
    );

    expect(screen.getByRole("heading", { name: /evidence control room/i })).toBeVisible();
    expect(screen.getByText("81")).toBeVisible();
    expect(screen.getByText("17")).toBeVisible();
    expect(screen.getByText(/manual reconciliation/i)).toBeVisible();
    expect(screen.getByText(/active campaign records/i)).toBeVisible();
    expect(screen.queryByText(/approved execution lanes/i)).not.toBeInTheDocument();
    expect(screen.getAllByText(/consent/i).length).toBeGreaterThan(0);
  });

  it("renders an honest campaign empty state and live campaign rows", () => {
    const { rerender } = render(<CampaignsView campaigns={[]} total={0} />);
    expect(screen.getByText(/no campaigns have been created/i)).toBeVisible();

    rerender(
      <CampaignsView
        total={124}
        campaigns={[
          {
            id: "campaign-1",
            name: "Founder follow-up",
            status: "active",
            dryRun: true,
            approvedAt: 1_800_000_000_000,
            timezone: "America/Toronto",
            enrollments: 24,
            replies: 3,
            pending: 8,
          },
        ]}
      />,
    );
    const row = screen.getByRole("row", { name: /founder follow-up/i });
    expect(within(row).getByText("DRY RUN")).toBeVisible();
    expect(within(row).getByText("24")).toBeVisible();
    expect(within(row).getByText("3")).toBeVisible();
    expect(screen.getByText("Showing latest 1 of 124")).toBeVisible();
    expect(screen.getByRole("region", { name: /campaign ledger table/i })).toHaveAttribute(
      "tabindex",
      "0",
    );
  });

  it("describes live mode as requested without claiming full send eligibility", () => {
    render(
      <CampaignsView
        total={1}
        campaigns={[
          {
            id: "campaign-1",
            name: "Founder follow-up",
            status: "active",
            dryRun: false,
            approvedAt: null,
            timezone: "America/Toronto",
            enrollments: 24,
            replies: 3,
            pending: 8,
          },
        ]}
      />,
    );

    expect(screen.getByText("LIVE MODE REQUESTED")).toBeVisible();
    expect(screen.queryByText("LIVE ELIGIBLE")).not.toBeInTheDocument();
    expect(screen.getByText(/runtime safety gates still apply/i)).toBeVisible();
  });

  it("shows unchecked DNS state instead of presenting a stored result as current", () => {
    render(
      <InboxHealthView
        total={1}
        now={1_800_000_000_000}
        inboxes={[
          {
            id: "inbox-1",
            emailAddress: "operator@example.com",
            displayName: "Operator",
            provider: "smtp",
            status: "active",
            dailyLimit: 40,
            reservedToday: 3,
            sentToday: 12,
            nextAvailableAt: 1_800_000_000_000,
            lastPollAt: null,
            hasAuthError: false,
            domain: {
              id: "domain-1",
              name: "example.com",
              status: "healthy",
              dkimMode: "provider",
              lastCheckedAt: null,
            },
          },
        ]}
      />,
    );

    expect(screen.getByText("12 sent")).toBeVisible();
    expect(screen.getByText("3 reserved")).toBeVisible();
    expect(screen.getByText(/provider signing \/ live blocked/i)).toBeVisible();
    expect(screen.getByText("UNCHECKED")).toBeVisible();
    expect(screen.getByText(/no dns check recorded/i)).toBeVisible();
    expect(screen.getByText("Showing all 1")).toBeVisible();
    expect(screen.queryByText(/guaranteed inbox/i)).not.toBeInTheDocument();
  });

  it("marks DNS checks stale at the conservative 24-hour boundary", () => {
    const now = 1_800_000_000_000;
    render(
      <InboxHealthView
        total={1}
        now={now}
        inboxes={[
          {
            id: "inbox-1",
            emailAddress: "operator@example.com",
            displayName: "Operator",
            provider: "smtp",
            status: "active",
            dailyLimit: 40,
            reservedToday: 3,
            sentToday: 12,
            nextAvailableAt: now,
            lastPollAt: null,
            hasAuthError: true,
            domain: {
              id: "domain-1",
              name: "example.com",
              status: "healthy",
              dkimMode: "provider",
              lastCheckedAt: now - 24 * 60 * 60 * 1_000,
            },
          },
        ]}
      />,
    );

    expect(screen.getByText("STALE")).toBeVisible();
    expect(screen.getByText(/last result: healthy/i)).toBeVisible();
    expect(screen.getByText(/24h ago/i)).toBeVisible();
    expect(screen.getByText("AUTH ATTENTION")).toHaveClass("auth-state-attention");
  });

  it("labels consent evidence as tamper-evident and exposes only shortened hashes", () => {
    render(
      <ConsentView
        total={240}
        records={[
          {
            id: "consent-1",
            subjectHash: "subjecthash0123456789abcdefghijklmnopqrstuvwxyz",
            controller: "OASIS AI Solutions",
            purpose: "Product updates",
            disclosureVersion: "v3",
            affirmativeAction: "submit",
            evidenceHash: "evidencehash0123456789abcdefghijklmnopqrstuvwxyz",
            signatureKeyVersion: 4,
            occurredAt: 1_800_000_000_000,
            receivedAt: 1_800_000_000_100,
            retentionExpiresAt: 1_900_000_000_000,
            certificateId: "certificate-1",
          },
        ]}
      />,
    );

    expect(screen.getByText(/tamper-evident evidence/i)).toBeVisible();
    expect(screen.getByRole("link", { name: /open certificate/i })).toHaveAttribute(
      "href",
      "/api/v1/certificate/certificate-1",
    );
    expect(
      [...document.querySelectorAll(".evidence-table code")].every(
        (element) => !element.hasAttribute("title"),
      ),
    ).toBe(true);
    expect(screen.getByText("Showing latest 1 of 240")).toBeVisible();
    expect(screen.getByRole("region", { name: /consent evidence table/i })).toHaveAttribute(
      "tabindex",
      "0",
    );
    expect(screen.queryByText(/subjecthash0123456789abcdefghijklmnopqrstuvwxyz/)).not.toBeInTheDocument();
  });

  it("renders tenant-wide suppression records as hashed identifiers", () => {
    render(
      <SuppressionsView
        total={501}
        suppressions={[
          {
            id: "suppression-1",
            identifierType: "email",
            identifierHash: "abcdef0123456789abcdef0123456789abcdef0123456789",
            reason: "unsubscribe",
            source: "one_click",
            createdAt: 1_800_000_000_000,
          },
        ]}
      />,
    );

    expect(screen.getByText(/tenant-wide stop ledger/i)).toBeVisible();
    expect(screen.getByText("UNSUBSCRIBE")).toBeVisible();
    expect(document.querySelector(".vault-table code")).not.toHaveAttribute("title");
    expect(screen.getByText("EMAIL / SHOWN SET")).toBeVisible();
    expect(screen.getByText("OTHER / SHOWN SET")).toBeVisible();
    expect(screen.getByText("501")).toBeVisible();
    expect(screen.getByText("Showing latest 1 of 501")).toBeVisible();
    expect(screen.getByRole("region", { name: /suppression ledger table/i })).toHaveAttribute(
      "tabindex",
      "0",
    );
    expect(screen.queryByText(/@/)).not.toBeInTheDocument();
  });
});
