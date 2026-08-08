"use client";

export default function DashboardError({ reset }: { reset: () => void }) {
  return (
    <section className="fatal-stage" aria-labelledby="dashboard-error-title">
      <div className="error-ledger" role="alert">
        <p className="eyebrow">Workspace failure / fail closed</p>
        <h1 id="dashboard-error-title">The control room could not be opened</h1>
        <p>
          Authentication or live database state is unavailable. No cached or
          replacement metrics are being shown.
        </p>
        <button className="primary-action" type="button" onClick={reset}>
          Retry live connection
        </button>
      </div>
    </section>
  );
}
