import { DashboardNav } from "./dashboard-nav";

export function DashboardShell({
  tenant,
  children,
}: {
  tenant: { name: string; id: string; status: string };
  children: React.ReactNode;
}) {
  return (
    <div className="vault-shell">
      <a className="skip-link" href="#main-content">
        Skip to dashboard content
      </a>
      <aside className="vault-rail">
        <div className="vault-brand">
          <span className="brand-sigil" aria-hidden="true">OV</span>
          <div>
            <strong>OPT—IN VAULT</strong>
            <span>Evidence operations</span>
          </div>
        </div>

        <DashboardNav />

        <div className="rail-footer">
          <p className="eyebrow">Authenticated workspace</p>
          <strong>{tenant.name}</strong>
          <code title={tenant.id}>{tenant.id}</code>
          <form action="/api/auth/logout" method="post">
            <button type="submit" className="logout-action">
              End session <span aria-hidden="true">↘</span>
            </button>
          </form>
        </div>
      </aside>

      <div className="vault-stage">
        <div className="stage-topline">
          <span>PRIVATE / TENANT ISOLATED</span>
          <span className="stage-seal">
            <i aria-hidden="true" /> {tenant.status.toUpperCase()}
          </span>
        </div>
        <main id="main-content" className="vault-main" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}
