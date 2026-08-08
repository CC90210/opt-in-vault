import Link from "next/link";

export type DashboardSnapshot = {
  tenant: { id: string; name: string; status: string };
  metrics: {
    activeCampaigns: number;
    activeInboxes: number;
    healthyDomains: number;
    domainsNeedingAttention: number;
    pendingMessages: number;
    unknownDeliveries: number;
    consentRecords: number;
    suppressions: number;
    pendingNotifications: number;
  };
  chain: Array<{ kind: string; state: string; occurredAt: number }>;
};

export type CampaignRecord = {
  id: string;
  name: string;
  status: string;
  dryRun: boolean;
  approvedAt: number | null;
  timezone: string;
  enrollments: number;
  replies: number;
  pending: number;
};

export type InboxHealthRecord = {
  id: string;
  emailAddress: string;
  displayName: string;
  provider: string;
  status: string;
  dailyLimit: number;
  reservedToday: number;
  sentToday: number;
  nextAvailableAt: number;
  lastPollAt: number | null;
  hasAuthError: boolean;
  domain: {
    id: string;
    name: string;
    status: string;
    dkimMode: string;
    lastCheckedAt: number | null;
  };
};

export type ConsentRecord = {
  id: string;
  subjectHash: string;
  controller: string;
  purpose: string;
  disclosureVersion: string;
  affirmativeAction: string;
  evidenceHash: string;
  signatureKeyVersion: number;
  occurredAt: number;
  receivedAt: number;
  retentionExpiresAt: number;
  certificateId: string | null;
};

export type SuppressionRecord = {
  id: string;
  identifierType: string;
  identifierHash: string;
  reason: string;
  source: string;
  createdAt: number;
};

const DNS_FRESHNESS_WINDOW_MS = 24 * 60 * 60 * 1_000;

function formatTimestamp(timestamp: number | null): string {
  if (!timestamp || !Number.isFinite(timestamp)) return "Not recorded";
  return new Intl.DateTimeFormat("en-CA", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(timestamp));
}

function isoTimestamp(timestamp: number | null): string | undefined {
  return timestamp && Number.isFinite(timestamp)
    ? new Date(timestamp).toISOString()
    : undefined;
}

function compactHash(value: string): string {
  if (value.length <= 22) return value;
  return `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function label(value: string): string {
  return value.replaceAll("_", " ").toUpperCase();
}

function ResultCount({ shown, total }: { shown: number; total: number }) {
  return (
    <p className="result-count">
      {shown < total ? `Showing latest ${shown} of ${total}` : `Showing all ${total}`}
    </p>
  );
}

function formatAge(ageMs: number): string {
  const minutes = Math.floor(ageMs / 60_000);
  if (minutes < 1) return "less than 1m ago";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function dnsGatePresentation(
  domain: InboxHealthRecord["domain"],
  now: number,
): { status: string; detail: string; checkedAt: number | null } {
  const checkedAt = domain.lastCheckedAt;
  if (checkedAt === null) {
    return {
      status: "unchecked",
      detail: "No DNS check recorded",
      checkedAt: null,
    };
  }
  if (!Number.isSafeInteger(checkedAt) || checkedAt <= 0 || checkedAt > now) {
    return {
      status: "stale",
      detail: `Last result: ${label(domain.status)} · Check timestamp invalid`,
      checkedAt: null,
    };
  }

  const age = now - checkedAt;
  if (age >= DNS_FRESHNESS_WINDOW_MS) {
    return {
      status: "stale",
      detail: `Last result: ${label(domain.status)} · Checked ${formatAge(age)}`,
      checkedAt,
    };
  }
  return {
    status: domain.status,
    detail: `Checked ${formatAge(age)}`,
    checkedAt,
  };
}

function toneFor(status: string): "good" | "warn" | "bad" | "neutral" {
  const normalized = status.toLowerCase();
  if (["active", "healthy", "accepted", "sealed", "sent"].includes(normalized)) {
    return "good";
  }
  if (
    ["unknown", "degraded", "paused", "pending", "leased", "stale", "unchecked"].includes(
      normalized,
    )
  ) {
    return "warn";
  }
  if (["blocked", "error", "failed", "rejected", "cancelled"].includes(normalized)) {
    return "bad";
  }
  return "neutral";
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`status-badge status-${toneFor(status)}`}>
      <span className="status-dot" aria-hidden="true" />
      {label(status || "unknown")}
    </span>
  );
}

export function PageHeader({
  index,
  eyebrow,
  title,
  description,
  action,
}: {
  index: string;
  eyebrow: string;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <header className="page-header">
      <div className="page-index" aria-hidden="true">
        {index}
      </div>
      <div className="page-heading-copy">
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p className="page-description">{description}</p>
      </div>
      {action ? <div className="page-action">{action}</div> : null}
    </header>
  );
}

export function EmptyLedger({
  code,
  title,
  detail,
}: {
  code: string;
  title: string;
  detail: string;
}) {
  return (
    <div className="empty-ledger" role="status">
      <div className="empty-mark" aria-hidden="true">
        ∅
      </div>
      <div>
        <p className="eyebrow">Ledger state / {code}</p>
        <h2>{title}</h2>
        <p>{detail}</p>
      </div>
    </div>
  );
}

export function DataUnavailable({ resource }: { resource: string }) {
  return (
    <section className="error-ledger" role="alert">
      <p className="eyebrow">Read failure / fail closed</p>
      <h2>{resource} could not be loaded</h2>
      <p>
        No replacement values are being shown. Refresh once the database
        connection is healthy.
      </p>
    </section>
  );
}

function MetricCard({
  value,
  label: metricLabel,
  note,
  signal = "neutral",
}: {
  value: number;
  label: string;
  note: string;
  signal?: "neutral" | "good" | "warn";
}) {
  return (
    <article className={`metric-card metric-${signal}`}>
      <p className="metric-label">{metricLabel}</p>
      <p className="metric-value">{value.toLocaleString("en-CA")}</p>
      <p className="metric-note">{note}</p>
    </article>
  );
}

export function OverviewView({ snapshot }: { snapshot: DashboardSnapshot }) {
  const { metrics } = snapshot;
  return (
    <>
      <PageHeader
        index="00"
        eyebrow="Overview / custody chain"
        title="Evidence control room"
        description="Live operational truth from consent capture through suppression, delivery, and reply handling."
        action={<StatusBadge status={snapshot.tenant.status} />}
      />

      <section className="signal-strip" aria-label="Critical operational signals">
        <div>
          <span className="signal-code">DNS</span>
          <strong>{metrics.domainsNeedingAttention}</strong>
          <span>domains need attention</span>
        </div>
        <div>
          <span className="signal-code">UNK</span>
          <strong>{metrics.unknownDeliveries}</strong>
          <span>manual reconciliation required</span>
        </div>
        <div>
          <span className="signal-code">NTF</span>
          <strong>{metrics.pendingNotifications}</strong>
          <span>operator notices pending</span>
        </div>
      </section>

      <section className="metric-grid" aria-label="Live workspace metrics">
        <MetricCard
          value={metrics.pendingMessages}
          label="Pending messages"
          note="Queued, leased, or sending"
          signal={metrics.pendingMessages > 0 ? "warn" : "neutral"}
        />
        <MetricCard
          value={metrics.activeCampaigns}
          label="Active campaigns"
          note="Active campaign records"
          signal="good"
        />
        <MetricCard
          value={metrics.activeInboxes}
          label="Active inboxes"
          note={`${metrics.healthyDomains} healthy domains`}
          signal="good"
        />
        <MetricCard
          value={metrics.consentRecords}
          label="Consent records"
          note="Immutable evidence events"
        />
        <MetricCard
          value={metrics.suppressions}
          label="Suppressions"
          note="Tenant-wide stop ledger"
        />
        <MetricCard
          value={metrics.unknownDeliveries}
          label="Unknown outcomes"
          note="Never retried automatically"
          signal={metrics.unknownDeliveries > 0 ? "warn" : "neutral"}
        />
      </section>

      <section className="ledger-panel chain-panel" aria-labelledby="chain-heading">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Latest 12 events</p>
            <h2 id="chain-heading">Chain of custody</h2>
          </div>
          <span className="panel-rule">SOURCE → EFFECT</span>
        </div>
        {snapshot.chain.length === 0 ? (
          <EmptyLedger
            code="NO-EVENTS"
            title="The custody rail is empty"
            detail="Consent, suppression, delivery, and reply events will appear here as they are recorded."
          />
        ) : (
          <ol className="custody-chain">
            {snapshot.chain.map((event, index) => (
              <li key={`${event.kind}-${event.occurredAt}-${index}`}>
                <div className="chain-node" aria-hidden="true">
                  {String(index + 1).padStart(2, "0")}
                </div>
                <div className="chain-copy">
                  <span className="chain-kind">{label(event.kind)}</span>
                  <strong>{label(event.state)}</strong>
                </div>
                <time dateTime={isoTimestamp(event.occurredAt)}>
                  {formatTimestamp(event.occurredAt)} UTC
                </time>
              </li>
            ))}
          </ol>
        )}
      </section>
    </>
  );
}

export function CampaignsView({
  campaigns,
  total,
}: {
  campaigns: CampaignRecord[];
  total: number;
}) {
  return (
    <>
      <PageHeader
        index="01"
        eyebrow="Sequence operations"
        title="Campaign ledger"
        description="Approval, dry-run posture, enrollment, and reply state—read directly from durable campaign records."
        action={<ResultCount shown={campaigns.length} total={total} />}
      />
      {campaigns.length === 0 ? (
        <EmptyLedger
          code="NO-CAMPAIGNS"
          title="No campaigns have been created"
          detail="Create and approve a campaign through the operator workflow before any work can enter the dispatch queue."
        />
      ) : (
        <div
          className="table-shell"
          role="region"
          aria-label="Campaign ledger table"
          tabIndex={0}
        >
          <table className="vault-table">
            <caption className="sr-only">Live tenant campaigns</caption>
            <thead>
              <tr>
                <th scope="col">Campaign</th>
                <th scope="col">State</th>
                <th scope="col">Safety</th>
                <th scope="col">Enrollments</th>
                <th scope="col">Replies</th>
                <th scope="col">Pending</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((campaign) => (
                <tr key={campaign.id}>
                  <th scope="row">
                    <strong>{campaign.name}</strong>
                    <span>{campaign.timezone || "Timezone not set"}</span>
                  </th>
                  <td><StatusBadge status={campaign.status} /></td>
                  <td>
                    <span className={campaign.dryRun ? "safety-chip" : "request-chip"}>
                      {campaign.dryRun ? "DRY RUN" : "LIVE MODE REQUESTED"}
                    </span>
                    <small>
                      {campaign.approvedAt
                        ? `Approved ${formatTimestamp(campaign.approvedAt)} UTC`
                        : "Approval missing"}
                    </small>
                    {!campaign.dryRun ? (
                      <small className="gate-copy">
                        Runtime safety gates still apply before delivery.
                      </small>
                    ) : null}
                  </td>
                  <td className="numeric-cell">{campaign.enrollments}</td>
                  <td className="numeric-cell">{campaign.replies}</td>
                  <td className="numeric-cell">{campaign.pending}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

export function InboxHealthView({
  inboxes,
  total,
  now = Date.now(),
}: {
  inboxes: InboxHealthRecord[];
  total: number;
  now?: number;
}) {
  return (
    <>
      <PageHeader
        index="02"
        eyebrow="Sending infrastructure"
        title="Inbox & domain health"
        description="Capacity, authentication, polling, and DNS gate state. Health reflects configured checks; it does not predict message placement."
        action={<ResultCount shown={inboxes.length} total={total} />}
      />
      {inboxes.length === 0 ? (
        <EmptyLedger
          code="NO-INBOXES"
          title="No sending inboxes are connected"
          detail="Connect an encrypted mailbox and verify its sending domain before enabling a campaign."
        />
      ) : (
        <div className="inbox-grid">
          {inboxes.map((inbox) => {
            const used = inbox.sentToday + inbox.reservedToday;
            const progressMaximum = Math.max(1, inbox.dailyLimit);
            const progressValue = Math.max(0, Math.min(used, progressMaximum));
            const percentage = inbox.dailyLimit > 0
              ? Math.min(100, Math.round((used / inbox.dailyLimit) * 100))
              : 0;
            const dnsGate = dnsGatePresentation(inbox.domain, now);
            return (
              <article className="inbox-card" key={inbox.id}>
                <header>
                  <div className="inbox-monogram" aria-hidden="true">
                    {(inbox.displayName || inbox.emailAddress).slice(0, 2).toUpperCase()}
                  </div>
                  <div>
                    <h2>{inbox.displayName || "Unnamed sender"}</h2>
                    <p>{inbox.emailAddress}</p>
                  </div>
                  <StatusBadge status={inbox.status} />
                </header>

                <dl className="inbox-facts">
                  <div><dt>Provider</dt><dd>{label(inbox.provider)}</dd></div>
                  <div><dt>Domain</dt><dd>{inbox.domain.name}</dd></div>
                  <div>
                    <dt>DNS gate</dt>
                    <dd>
                      <StatusBadge status={dnsGate.status} />
                      <span className="dns-gate-detail">
                        {dnsGate.checkedAt ? (
                          <time dateTime={isoTimestamp(dnsGate.checkedAt)}>{dnsGate.detail}</time>
                        ) : (
                          dnsGate.detail
                        )}
                      </span>
                    </dd>
                  </div>
                  <div>
                    <dt>DKIM</dt>
                    <dd>
                      {inbox.domain.dkimMode === "provider"
                        ? "Provider signing / live blocked"
                        : "Local signing"}
                    </dd>
                  </div>
                </dl>

                <div className="capacity-block">
                  <div className="capacity-label">
                    <span>UTC daily capacity</span>
                    <strong>{used} / {inbox.dailyLimit}</strong>
                  </div>
                  <div
                    className="capacity-track"
                    role="progressbar"
                    aria-label={`${inbox.emailAddress} daily capacity`}
                    aria-valuemin={0}
                    aria-valuemax={progressMaximum}
                    aria-valuenow={progressValue}
                  >
                    <span style={{ width: `${percentage}%` }} />
                  </div>
                  <p><span>{inbox.sentToday} sent</span><span>{inbox.reservedToday} reserved</span></p>
                </div>

                <footer>
                  <span
                    className={
                      inbox.hasAuthError
                        ? "auth-state auth-state-attention"
                        : "auth-state auth-state-clear"
                    }
                  >
                    {inbox.hasAuthError ? "AUTH ATTENTION" : "AUTH CLEAR"}
                  </span>
                  <span>
                    Last poll: {inbox.lastPollAt ? `${formatTimestamp(inbox.lastPollAt)} UTC` : "Not recorded"}
                  </span>
                </footer>
              </article>
            );
          })}
        </div>
      )}
    </>
  );
}

export function ConsentView({
  records,
  total,
}: {
  records: ConsentRecord[];
  total: number;
}) {
  return (
    <>
      <PageHeader
        index="03"
        eyebrow="Evidence vault"
        title="Consent chain"
        description="Append-only, signed, tamper-evident evidence records. These records support auditability; they are not independent proof of identity or legal advice."
        action={<ResultCount shown={records.length} total={total} />}
      />
      {records.length === 0 ? (
        <EmptyLedger
          code="NO-CONSENT"
          title="No consent evidence has been sealed"
          detail="Verified capture events will appear here with their disclosure, evidence digest, and retention boundary."
        />
      ) : (
        <div
          className="table-shell"
          role="region"
          aria-label="Consent evidence table"
          tabIndex={0}
        >
          <table className="vault-table evidence-table">
            <caption className="sr-only">Tamper-evident consent records</caption>
            <thead>
              <tr>
                <th scope="col">Subject / event</th>
                <th scope="col">Purpose</th>
                <th scope="col">Disclosure</th>
                <th scope="col">Evidence digest</th>
                <th scope="col">Certificate</th>
              </tr>
            </thead>
            <tbody>
              {records.map((record) => (
                <tr key={record.id}>
                  <th scope="row">
                    <code>{compactHash(record.subjectHash)}</code>
                    <span>{formatTimestamp(record.occurredAt)} UTC</span>
                  </th>
                  <td>
                    <strong>{record.purpose}</strong>
                    <span>{record.controller}</span>
                  </td>
                  <td>
                    <span className="safety-chip">{label(record.disclosureVersion)}</span>
                    <small>{label(record.affirmativeAction)}</small>
                  </td>
                  <td>
                    <code>{compactHash(record.evidenceHash)}</code>
                    <span>HMAC key v{record.signatureKeyVersion}</span>
                  </td>
                  <td>
                    {record.certificateId ? (
                      <Link className="text-link" href={`/api/v1/certificate/${encodeURIComponent(record.certificateId)}`}>
                        Open certificate <span aria-hidden="true">↗</span>
                      </Link>
                    ) : (
                      <span className="muted-label">Not generated</span>
                    )}
                    <small>Retain until {formatTimestamp(record.retentionExpiresAt)} UTC</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

export function SuppressionsView({
  suppressions,
  total,
}: {
  suppressions: SuppressionRecord[];
  total: number;
}) {
  const emailCount = suppressions.filter(
    (record) => record.identifierType === "email",
  ).length;
  const otherCount = suppressions.length - emailCount;

  return (
    <>
      <PageHeader
        index="04"
        eyebrow="Safety perimeter"
        title="Tenant-wide stop ledger"
        description="Hashed identifiers blocked across every campaign and inbox in this workspace. Suppression is checked again immediately before delivery preparation."
        action={
          <div className="header-summary">
            <div className="header-count">
              <strong>{total}</strong>
              <span>total stops</span>
            </div>
            <ResultCount shown={suppressions.length} total={total} />
          </div>
        }
      />
      {suppressions.length === 0 ? (
        <EmptyLedger
          code="NO-STOPS"
          title="The suppression ledger is empty"
          detail="Unsubscribes, complaints, bounces, and manual stops will appear here as hashed tenant-wide records."
        />
      ) : (
        <>
          <section className="suppression-summary" aria-label="Suppression totals">
            <div><span>EMAIL / SHOWN SET</span><strong>{emailCount}</strong></div>
            <div><span>OTHER / SHOWN SET</span><strong>{otherCount}</strong></div>
            <p>Raw recipient identifiers are not displayed in this ledger.</p>
          </section>
          <div
            className="table-shell"
            role="region"
            aria-label="Suppression ledger table"
            tabIndex={0}
          >
            <table className="vault-table">
              <caption className="sr-only">Live tenant suppression records</caption>
              <thead>
                <tr>
                  <th scope="col">Identifier hash</th>
                  <th scope="col">Type</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Source</th>
                  <th scope="col">Recorded</th>
                </tr>
              </thead>
              <tbody>
                {suppressions.map((record) => (
                  <tr key={record.id}>
                    <th scope="row"><code>{compactHash(record.identifierHash)}</code></th>
                    <td>{label(record.identifierType)}</td>
                    <td><span className="safety-chip">{label(record.reason)}</span></td>
                    <td>{label(record.source || "unknown")}</td>
                    <td><time dateTime={isoTimestamp(record.createdAt)}>{formatTimestamp(record.createdAt)} UTC</time></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}
