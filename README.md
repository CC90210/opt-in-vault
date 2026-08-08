# Opt-in Vault

Opt-in Vault is a private, multi-tenant outbound operations and consent-evidence MVP. It combines a read-only operator dashboard, durable campaign dispatch, bounded inbox polling, tenant-wide suppression, RFC 8058 one-click unsubscribe, DNS readiness checks, and tamper-evident consent records.

The application uses Next.js 15, React 19, Turso/libSQL, Drizzle ORM, Nodemailer, and ImapFlow. It does **not** use Supabase. Live delivery is disabled by default, and this repository does not contain real tenant data, inbox credentials, or a production deployment.

> Consent records are tamper-evident evidence, not a legal shield. They do not independently prove identity, authority, or lawful consent. Applicable law, counsel guidance, and email/SMS provider rules still govern every campaign.

## What is implemented

- Tenant API-key authentication and a 60-minute, secure dashboard session.
- Live, tenant-scoped dashboard pages for campaigns, inbox/domain state, consent evidence, and suppressions. No sample metrics are substituted when data is unavailable.
- One-cycle dispatch and inbox-poll workers, plus cron-authenticated HTTP equivalents.
- A fail-closed outbound gateway for SMTP 465 with implicit TLS or SMTP 587 with required STARTTLS.
- Password SMTP and Google/Microsoft OAuth credential payloads, encrypted at rest with versioned AES-256-GCM keys.
- Local DKIM signing for live RFC 8058 delivery, plus honestly labelled provider-managed DKIM snapshots that remain blocked from live delivery because header coverage cannot be proved.
- Durable message material, stable Message-IDs, quota reservations, suppression rechecks, and quarantine of unknown delivery outcomes.
- RFC 8058 one-click unsubscribe with a non-mutating GET and an idempotent POST.
- Browser JavaScript and dependency-free Python consent clients, immutable evidence rows, verified certificate PDFs, and explicit retention deadlines.

The current MVP has no public registration, tenant bootstrap command, mailbox/campaign CRUD UI, or automatic retention-key destruction job. Trusted operators must provision tenant, API-key, capture-site, inbox, and campaign records through a controlled administrative database workflow.

## Local setup

Requirements: Node.js 20 or newer and npm.

```powershell
npm install
Copy-Item .env.example .env.local
```

Replace every secret placeholder in `.env.local` with a distinct secret. A local file database works without a Turso token:

```dotenv
TURSO_DATABASE_URL=file:./data/opt-in-vault.db
TURSO_AUTH_TOKEN=
LIVE_SENDS_ENABLED=false
```

The development UI is served at `http://localhost:3000`, but `NEXT_PUBLIC_APP_URL` is the public base used in unsubscribe links. The dispatch worker requires that value to be a clean HTTPS URL even during a local dry run; replace the reserved-domain template value with an HTTPS test or production origin before running dispatch.

Apply the checked-in migration before starting the application:

```powershell
npm run db:migrate
npm run dev
```

The migration creates the local database directory, enables foreign keys, applies `drizzle/`, runs `PRAGMA foreign_key_check`, and verifies both immutable-consent triggers. The app is then available at [http://localhost:3000/login](http://localhost:3000/login). Dashboard login requires a pre-provisioned active tenant API key with the `dashboard:read` scope.

Use `npm run db:generate` only when intentionally authoring a schema migration. It is not part of normal startup.

## Safe operating default

`LIVE_SENDS_ENABLED=false` is only the first safety lock. A real SMTP call requires both independent activation layers:

1. Runtime lock: `LIVE_SENDS_ENABLED=true`.
2. Campaign lock: `status='active'`, `approved_at` is set, and `dry_run=false`.

Inbox, domain, schedule, quota, suppression, enrollment, and tenant gates must also pass. The latest usable DNS snapshot must be no more than 24 hours old, and live delivery requires local DKIM material so both one-click unsubscribe headers are covered. With either activation layer closed, dispatch persists a dry-run preview and defers the job without constructing a mail transport.

Do not enable live delivery until the operator checklist in [`docs/operations/runbook.md`](docs/operations/runbook.md) is complete.

## Workers

Both CLI commands run one bounded cycle and exit; an external scheduler is required for repetition.

```powershell
npm run worker:dispatch -- --limit 25
npm run worker:inboxes
```

Equivalent HTTP endpoints are available for a scheduler:

- `POST /api/v1/cron/dispatch`
- `POST /api/v1/cron/poll-inboxes`

Both require `Authorization: Bearer <CRON_SECRET>`. This repository does not configure or deploy a scheduler automatically.

## Verification

```powershell
npm test
npm run lint
npm run typecheck
npm run build
```

Automated tests do not perform real SMTP, IMAP, OAuth, DNS mutation, production Turso writes, or deployment.

## Operator documentation

- [`docs/operations/runbook.md`](docs/operations/runbook.md) — environments, database, inboxes, campaigns, DNS, workers, activation, deployment, and rollback.
- [`docs/operations/consent-capture.md`](docs/operations/consent-capture.md) — browser/Python integration, API contract, certificates, retention, and key destruction.
- [`SECURITY.md`](SECURITY.md) — trust boundaries, secret rotation, containment, and responsible reporting.
- [`docs/plans/2026-08-08-opt-in-vault-design.md`](docs/plans/2026-08-08-opt-in-vault-design.md) — approved MVP architecture and safety rationale.
