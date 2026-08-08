export default function DashboardLoading() {
  return (
    <div className="loading-ledger" role="status" aria-live="polite">
      <span className="loading-mark" aria-hidden="true" />
      <div>
        <p className="eyebrow">Reading live ledger</p>
        <strong>Verifying chain state…</strong>
      </div>
    </div>
  );
}
