import type { Metadata } from "next";

import { LoginForm } from "@/components/auth/login-form";

export const metadata: Metadata = {
  title: "Private access",
};

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  return (
    <main className="login-stage">
      <section className="login-manifesto" aria-labelledby="login-title">
        <div className="login-brand">
          <span className="brand-sigil" aria-hidden="true">OV</span>
          <div><strong>OPT—IN VAULT</strong><span>Private evidence operations</span></div>
        </div>

        <div className="manifesto-copy">
          <p className="eyebrow">Authorized operators only / V1</p>
          <h1 id="login-title">Every permission leaves a trace.</h1>
          <p>
            Enter the workspace where consent, suppression, delivery, and
            reply state stay linked as one durable chain of custody.
          </p>
        </div>

        <ol className="manifesto-chain" aria-label="Evidence chain">
          <li><span>01</span><div><strong>CAPTURE</strong><small>Affirmative action sealed</small></div></li>
          <li><span>02</span><div><strong>VERIFY</strong><small>Domain and inbox gates checked</small></div></li>
          <li><span>03</span><div><strong>HONOUR</strong><small>Suppression wins every race</small></div></li>
          <li><span>04</span><div><strong>RECONCILE</strong><small>Unknown delivery never retries</small></div></li>
        </ol>
      </section>

      <section className="login-panel" aria-label="Sign in">
        <div className="login-panel-inner">
          <div className="access-stamp" aria-hidden="true">
            <span>PRIVATE</span>
            <strong>ACCESS</strong>
            <small>SESSION / 60 MIN</small>
          </div>
          <p className="eyebrow">Workspace authentication</p>
          <h2>Unlock the control room</h2>
          <p className="login-intro">
            Use a tenant API key carrying the <code>dashboard:read</code> scope.
          </p>
          <LoginForm error={error} />
          <p className="login-footnote">
            No password reset. No public registration. Access is issued by the
            workspace operator.
          </p>
        </div>
      </section>
    </main>
  );
}
