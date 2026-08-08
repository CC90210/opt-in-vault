# Opt-in Vault operator runbook

This runbook covers the implemented MVP. It does not authorize a deployment, connect a real provider, or enable live sends. Perform production mutations only under an approved change with a database snapshot and rollback owner.

Opt-in Vault uses Turso/libSQL directly. There is no Supabase project, client, environment variable, migration path, or RLS configuration in this application.

## 1. Runtime map

| Component | Entry point | Behavior |
| --- | --- | --- |
| Web/dashboard | `npm run dev` or `npm start` | Next.js UI and Route Handlers. |
| Migration | `npm run db:migrate` | Applies checked-in Drizzle migrations once, then verifies foreign keys and immutable consent triggers. |
| Dispatch CLI | `npm run worker:dispatch -- --limit 25` | Runs one bounded dispatch cycle and exits. Default 25; accepted range 1–50. |
| Inbox CLI | `npm run worker:inboxes` | Polls at most 10 active inboxes and 25 messages per inbox within a 45-second cycle, then exits. |
| Dispatch cron | `POST /api/v1/cron/dispatch` | One authenticated cycle. The optional `limit` query is clamped to the route's bound (25 in the production handler). |
| Inbox cron | `POST /api/v1/cron/poll-inboxes` | One authenticated poll cycle; returns 207 when any inbox fails. |
| DNS scan | `POST /api/v1/domains/{id}/scan` | Tenant-authorized SPF/DKIM/DMARC/MX snapshot and sending-domain gate update. |

The workers do not contain an internal loop or scheduler. Choose either the CLI entry points in a persistent/container scheduler or the HTTP cron routes. Do not run both paths for the same cadence unless overlapping bounded cycles are intentional and monitored.

## 2. Environment configuration

Start from `.env.example`. Values are loaded from `.env.local` by the local migration and CLI workers; deployment platforms must inject them into the application/worker runtime.

### Core

| Variable | Required by | Contract |
| --- | --- | --- |
| `NEXT_PUBLIC_APP_URL` | Dispatch | Public application origin used for unsubscribe URLs. The worker requires a clean HTTPS URL in every environment and rejects HTTP, including localhost. Do not include credentials, a query, or fragment. |
| `TURSO_DATABASE_URL` | App, migration, workers | Local `file:./data/opt-in-vault.db` or a durable Turso/libSQL URL. |
| `TURSO_AUTH_TOKEN` | Remote Turso | Optional for a local file database; provision for the remote database according to Turso access policy. |
| `LIVE_SENDS_ENABLED` | Dispatch | Only the exact string `true` opens the runtime delivery lock. Missing/other values stay dry-run. |
| `DISPATCH_BATCH_SIZE` | Dispatch CLI | Optional integer 1–50; default 25. |

### Authentication and dispatch secrets

| Variable | Minimum/format | Purpose |
| --- | --- | --- |
| `API_KEY_PEPPER` | 32 bytes | Current tenant API-key HMAC pepper. |
| `API_KEY_PEPPER_VERSION` | Positive integer, default 1 | Version written beside API-key hashes. |
| `API_KEY_PEPPERS_JSON` | Optional JSON object | Historical peppers. Current plus historical versions are capped at 8; JSON is capped at 16 KiB. |
| `SESSION_SECRET` | 32 bytes | Dashboard session HMAC. There is no historical session ring. |
| `CRON_SECRET` | 32 bytes | Bearer secret for both cron routes. |
| `DISPATCH_LEASE_PEPPER` | 32 bytes | Hashes short-lived job lease tokens. |
| `UNSUBSCRIBE_TOKEN_SECRET` | 32 bytes | Derives/hashes opaque unsubscribe tokens. |
| `SUPPRESSION_HASH_KEY` | 32 bytes | Tenant-scoped email/SMS suppression hashes. |

### Inbox credential encryption

| Variable | Contract |
| --- | --- |
| `CREDENTIAL_ENCRYPTION_KEY` | Current AES key: exactly 32 bytes encoded as 64 hex characters or canonical base64. |
| `CREDENTIAL_ENCRYPTION_KEY_VERSION` | Positive integer; default 1. Must match the envelope `kid`/database version for newly provisioned credentials. |
| `CREDENTIAL_ENCRYPTION_KEYS_JSON` | Optional historical `{version:key}` map. Current plus historical keys are capped at 8; serialized JSON is capped at 32 KiB. Both dispatch and inbox polling must receive the same ring. |

### Consent evidence

| Variable | Minimum/format | Purpose |
| --- | --- | --- |
| `CAPTURE_SITE_KEY_PEPPER` | 32 bytes | Hashes publishable capture-site keys. |
| `CONSENT_TRUSTED_EDGE_PROVIDER` | Exact value `vercel` | Enables the only implemented production source resolver. It additionally requires Vercel's injected `VERCEL=1` marker and a single public `x-vercel-forwarded-for` value. |
| `CONSENT_SUBJECT_HASH_KEY` | 32 bytes | Keyed, tenant-bound subject identifier hash. |
| `CONSENT_SIGNATURE_KEY` | 32 bytes | Current evidence HMAC key. |
| `CONSENT_SIGNATURE_KEY_VERSION` | Positive integer | Stored with new evidence. |
| `CONSENT_SIGNATURE_KEYS_JSON` | Optional, max 8 entries | Historical signature keys used to verify certificates. Each value is capped at 16 KiB. |
| `CONSENT_ENCRYPTION_KEY` | Exactly 32 bytes | Current AES key for canonical evidence payloads. |
| `CONSENT_PAYLOAD_KEY_VERSION` | Positive integer | Stored with new evidence envelopes. |
| `CONSENT_ENCRYPTION_KEYS_JSON` | Optional, max 8 entries | Historical payload keys used to render retained certificates. Each value is capped at 16 KiB. |
| `CONSENT_RETENTION_DAYS` | Positive integer | Retention deadline added to the server receive time for new records. |
| `CERTIFICATE_SHARE_TOKEN_PEPPER` | 32 bytes | Required when externally shared certificate tokens are provisioned/used. |

Use a different secret for every secret row above and for every environment. An empty optional JSON variable is not equivalent to an absent variable in every parser; leave optional rings commented out until they contain valid JSON. Public capture must run directly on Vercel in this MVP; do not set `VERCEL=1` yourself or trust a header forwarded by another proxy.

## 3. Database lifecycle

### Local database

```powershell
Copy-Item .env.example .env.local
npm run db:migrate
```

With `TURSO_DATABASE_URL=file:./data/opt-in-vault.db`, paths are resolved from the repository root and the directory is created. The migration command:

1. enables SQLite foreign keys;
2. applies all checked-in files under `drizzle/`;
3. requires `PRAGMA foreign_key_check` to return zero violations;
4. requires both insert-only `consent_logs` triggers to exist.

Do not run `npm run db:generate` during normal startup. That command authors new migration material from the schema and requires review.

### Remote Turso

Use a durable `libsql://` database and a least-privilege token. Run the migration once from a controlled release job before web/worker processes using the new schema start. Do not point multiple environments at the same database.

The current migration is forward-only; no automatic down migration exists. Take a provider snapshot/backup before applying it. A local file backup is only consistent when the web app and both worker paths are stopped; preserve the database and any SQLite sidecar files together.

### Provisioning boundary

The MVP does not ship tenant, API-key, capture-site, inbox, lead, campaign, or enrollment CRUD endpoints. The dashboard is read-only. Provision records through a reviewed, tenant-scoped administrative database process that:

- creates hashes/encrypted envelopes with the repository's server utilities;
- stores key versions beside hashes/ciphertext;
- satisfies composite tenant foreign keys and status checks;
- never logs or stores raw bearer keys after the one-time handoff;
- leaves every campaign in `dry_run=true` until activation review.

Do not insert plaintext credential JSON into `sending_inboxes.encrypted_credentials`.

## 4. API and dashboard authentication

Tenant API keys have the shape `oiv_sk_…`, but only their prefix and HMAC hash belong in the database. Route authorization rejects revoked/expired keys, inactive tenants, missing scopes, malformed scope JSON, and unknown pepper versions.

| Surface | Authentication |
| --- | --- |
| Dashboard login | HTML form posts a tenant API key requiring `dashboard:read`; success returns a 60-minute secure session cookie. |
| Dashboard pages | Server-side session verification and active-tenant check on every request. |
| DNS scan | Session or bearer API key requiring `domains:write`. |
| Certificate download | Same-tenant session/API key with `admin`, `consent:read`, or `certificate:read`; alternatively an unexpired, unrevoked share token in the `Authorization: Share …` header. |
| Consent log | Publishable capture-site key plus exact Origin and idempotency key; never an admin API key. |
| Unsubscribe | Opaque URL token; RFC 8058 POST intentionally requires no cookie. |
| Cron | `Authorization: Bearer <CRON_SECRET>`. |

The login form exchanges the API key once and does not write it to browser storage. The session cookie is `Secure`, so production and realistic login testing require HTTPS.

## 5. Sending inboxes and credentials

### Connection rules

- SMTP 465 requires `smtp_secure=true` and implicit TLS.
- SMTP 587 requires `smtp_secure=false`; Nodemailer sets `requireTLS=true` and disables opportunistic downgrade.
- IMAP requires port 993 with `imap_secure=true`.
- TLS certificate validation and TLS 1.2 minimum are enforced.
- Hosts must resolve only to public addresses on approved ports.
- `from_address` must use the exact configured sending domain.

Use the exact supported provider mail hosts: Google `smtp.gmail.com` / `imap.gmail.com`, or Microsoft `smtp.office365.com` / `outlook.office365.com`. OAuth refreshes go only to the fixed Google or Microsoft token endpoint. Provider tenant policies and token lifetimes remain external configuration and can change.

### One combined encrypted payload

SMTP, IMAP, OAuth, and optional local-DKIM material are stored together. Supported password SMTP JSON:

```json
{
  "username": "sender@example.invalid",
  "password": "<password from secret manager>"
}
```

Google/Microsoft OAuth refresh-grant JSON is sufficient for both outbound SMTP and inbound IMAP polling:

```json
{
  "username": "sender@example.invalid",
  "oauth2": {
    "clientId": "<provider client ID>",
    "clientSecret": "<provider client secret>",
    "refreshToken": "<provider refresh token>"
  }
}
```

An access-token-only payload is accepted when a refresh grant is unavailable, but it becomes unusable when that token expires:

```json
{
  "username": "sender@example.invalid",
  "oauth2": {
    "accessToken": "<current provider access token>"
  }
}
```

SMTP and IMAP share the same bounded refresh implementation. A complete refresh grant is exchanged before each operation; Google uses its fixed token endpoint, while Microsoft requests the purpose-specific delegated scope (`SMTP.Send` or `IMAP.AccessAsUser.All`, plus `offline_access`). Token responses, credential sizes, redirects, and refresh time are bounded. The application has no interactive reauthorization UI, so an expired/revoked grant must be replaced through the trusted provisioning workflow.

For local DKIM, add `dkimPrivateKey` containing the PEM private key obtained from the operator's secret manager. Never include it in a migration, log, issue, or runbook.

The parser rejects unknown fields, empty secrets, control characters, oversized values, malformed PEM material, and incomplete OAuth refresh grants.

### Binding and encryption

The normalized binding is:

```text
oiv-inbox-v1|smtp=<normalized-smtp-host>|imap=<normalized-imap-host-or-->
```

The AES-256-GCM associated data binds the envelope to:

- tenant ID;
- resource type `sending_inbox`;
- inbox ID;
- field `credentials`;
- provider (`smtp`, `google`, or `microsoft`);
- the combined binding above.

Store the same binding in `credential_binding`. Dispatch and inbox polling recompute it before decryption. Changing either host, tenant, inbox ID, provider, binding, ciphertext, tag, or key version requires a newly encrypted credential envelope.

During rotation, add the old key to `CREDENTIAL_ENCRYPTION_KEYS_JSON` before changing the current version. Run dispatch in dry-run and poll a synthetic/test inbox, then re-encrypt every old envelope before removing its historical key.

### DKIM modes

`dkim_mode='local'` requires a selector and `dkimPrivateKey`. The DNS snapshot records its normalized domain, selector, and mode. Before OAuth refresh or SMTP construction, live dispatch requires that exact snapshot to be unique, usable, no more than 24 hours old, allow SHA-256 when the `h=` tag is present, allow `email` or `*` when the `s=` tag is present, and contain the RSA public key derived from the configured private key. Nodemailer then signs the normal message fields plus both `List-Unsubscribe` and `List-Unsubscribe-Post`.

`dkim_mode='provider'` does not load a local private key. A selector record must still be present for the DNS gate, but the application can only label it `present_provider_managed`; it does not verify the signature on a delivered message or prove domain alignment. Live transport creation therefore fails closed with `rfc8058_dkim_signing_unverified`. Use `dkim_mode='local'` for live delivery.

## 6. DNS health and its limits

The DNS scanner records bounded snapshots for:

- one usable SPF policy at the root;
- one syntactically usable public key at `<selector>._domainkey.<domain>`;
- one DMARC record at `_dmarc.<domain>`;
- at least one MX record.

The scanner separates send readiness from assurance level. Both `healthy` and warning-only `degraded` states are technically send-ready; the implemented degraded case is otherwise usable records with DMARC `p=none` monitoring. DMARC `quarantine` or `reject` can be healthy when the other checks pass. Missing, invalid, or unusable required SPF/DKIM/MX records are blocked; multiple SPF/DKIM/DMARC policy records are invalid, while multiple MX hosts are normal. Resolver timeouts/transient failures are non-ready and fail closed.

These checks are deliberately limited:

- SPF inspection is a bounded structural heuristic, not recursive evaluation from the actual sending IP.
- The scanner alone checks DKIM record/public-key shape. Live local-DKIM transport adds a cryptographic private/public-key match against that exact snapshot, but neither step verifies the signature on a provider-accepted message.
- DMARC checks the published policy, not message-level SPF/DKIM alignment.
- MX proves a record exists, not that the mailbox can receive.
- DNS health does not guarantee provider acceptance, reputation, deliverability, or inbox placement.

Run the scan after every DNS, selector, mode, or private-key change and wait for real DNS propagation. Snapshots created before source binding was introduced must also be rescanned once. A dispatch claim requires a usable snapshot no more than 24 hours old; unchecked, ambiguous, future-dated, stale, source-mismatched, or key-mismatched snapshots fail closed. Do not manually mark a domain healthy to bypass a failed snapshot.

## 7. Campaign schedules and activation

`campaigns.schedule_json` is interpreted in the campaign's IANA `timezone`.

An empty object allows every instant:

```json
{}
```

A bounded weekday window uses exact fields only:

```json
{
  "days": [1, 2, 3, 4, 5],
  "start": "09:00",
  "end": "17:00"
}
```

- Days are integers `0` (Sunday) through `6` (Saturday), unique and non-empty.
- Times use 24-hour `HH:mm`; start is inclusive and end is exclusive.
- Overnight windows are supported; a post-midnight portion belongs to the preceding configured start day.
- JSON is capped at 4 KiB and cannot contain extra fields.
- The evaluator uses the IANA timezone/DST rules available to the Node runtime and searches at most eight days for the next allowed minute.
- Invalid JSON, timezone, or impossible schedules block the claimed job as `dispatch_schedule_invalid`.

### Two independent live-delivery keys

Keep `LIVE_SENDS_ENABLED=false` while configuring or validating. A campaign is network-send eligible only when all of these are true at the same cycle:

```text
LIVE_SENDS_ENABLED=true
campaign.status='active'
campaign.approved_at IS NOT NULL
campaign.dry_run=false
```

The runtime flag is one key; the reviewed campaign state is the second. The dispatcher additionally requires active tenant/enrollment/lead/inbox state, a send-ready domain (`healthy` or warning-only `degraded`), a valid schedule, available quota, and no tenant suppression.

Dry run is durable: the worker renders and stores the preview material and stable Message-ID, records the prepared outbound state, does not construct SMTP transport, and defers the job to the next UTC day.

### Live activation checklist

1. Confirm a current restorable database snapshot.
2. Verify all required environment values and matching key versions in web and worker runtimes.
3. Run migrations and the complete verification gate.
4. Confirm tenant, campaign, enrollment, lead, inbox, and domain state from live database records.
5. Confirm suppression hashes use the current `SUPPRESSION_HASH_KEY` and test a known synthetic suppression.
6. Run a new DNS scan after provisioning the final local DKIM key. Require persisted `healthy` or explicitly review a send-ready `degraded` DMARC-monitoring warning; live dispatch will independently reject a snapshot whose source or RSA public key does not match.
7. Poll a test inbox successfully and confirm its cursor/auth state.
8. Run dispatch with `LIVE_SENDS_ENABLED=false`; inspect dry-run summary and persisted rendered material.
9. Set the campaign active/approved while leaving `dry_run=true`; repeat dry run.
10. Obtain explicit operator approval for the named campaign/inbox/recipient scope.
11. Set `dry_run=false`, then separately set `LIVE_SENDS_ENABLED=true` in the approved runtime.
12. Use a minimal first batch and monitor provider response, `unknown` deliveries, replies, suppressions, quota, and notifications.

To stop delivery, close both keys: set `LIVE_SENDS_ENABLED=false` and set campaign status to `paused` (or restore `dry_run=true`). Stop the scheduler while investigating. Messages already accepted by SMTP cannot be recalled.

## 8. Suppression and RFC 8058

Suppression identity is a keyed HMAC over a normalized email or E.164 phone number. The uniqueness boundary is `(tenant_id, identifier_type, identifier_hash)`:

- one suppression blocks every campaign and inbox in that tenant;
- it does not automatically suppress the same identifier in another tenant;
- raw identifiers are not required in the suppression row;
- adding a suppression updates matching lead/enrollment state and cancels queued/leased jobs;
- dispatch checks suppression again inside the delivery-preparation transaction.

Do not rotate `SUPPRESSION_HASH_KEY` casually. Existing hashes cannot generally be rebuilt because raw values are intentionally absent from the suppression ledger.

Every prepared message receives:

```text
List-Unsubscribe: <https://.../api/v1/unsubscribe?token=...>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
```

The same HTTPS URL is visible in the body. `GET` shows confirmation/status and never mutates, protecting against link scanners. RFC 8058 `POST` accepts only `application/x-www-form-urlencoded` with the exact bounded body `List-Unsubscribe=One-Click`; it does not redirect, requires no cookie, is idempotent, and creates tenant-wide email suppression.

## 9. Scheduling and monitoring

For an external scheduler, send a POST with the cron bearer secret. Never put the secret in the URL or logs.

```text
POST /api/v1/cron/dispatch?limit=25
Authorization: Bearer <secret manager reference>

POST /api/v1/cron/poll-inboxes
Authorization: Bearer <secret manager reference>
```

Interpret results rather than treating HTTP 200 as proof of delivery:

- dispatch summary separates accepted, rejected, unknown, dry-run, blocked, deferred, and errors;
- an inbox poll response may be 207 with partial success;
- provider acceptance is not recipient delivery;
- `unknown` delivery outcomes require manual reconciliation and must not be requeued automatically;
- inbox auth failures and oversized inbound messages create notifications.

The current MVP has no notification-delivery worker or dedicated health endpoint. Monitor scheduler exit/status, structured summaries, database worker/message state, and provider logs without recording secrets or message bodies.

## 10. Deployment

This repository contains no deployment or cron declaration and has not been deployed by these instructions.

Recommended release order for any Node-capable platform:

1. Keep `LIVE_SENDS_ENABLED=false`; stop/disable dispatch and inbox schedules.
2. Take a restorable Turso snapshot and record current secret versions.
3. Install exactly from the lockfile with `npm ci`.
4. Run `npm test`, `npm run lint`, `npm run typecheck`, and `npm run build` in the release environment.
5. Run `npm run db:migrate` once against the target database and verify its printed invariants.
6. Deploy the built web application behind HTTPS with the complete runtime environment.
7. Smoke-test `/login`, authenticated dashboard reads, a synthetic consent capture, certificate verification, DNS scan, cron 401 behavior without credentials, and dry-run dispatch.
8. Enable one scheduler path at a time while live sends remain disabled.
9. Follow the live activation checklist only under a separate approved send change.

A local `file:` database is not suitable for an ephemeral/serverless filesystem or multiple application instances. Use remote Turso/libSQL for those shapes.

## 11. Rollback

Application rollback and database rollback are separate decisions.

1. Set `LIVE_SENDS_ENABLED=false`, pause campaigns, and stop both scheduler paths.
2. Preserve logs and take another database snapshot before changing state.
3. Redeploy the previously verified application artifact with the compatible secret rings.
4. Prefer a forward compatibility fix when the migration is additive and the previous app can read it.
5. If database restoration is required, stop every writer, restore the pre-migration provider snapshot, and deploy the matching application version before restarting schedulers.
6. Re-run migration invariants, dashboard reads, consent verification, inbox polling, and dispatch dry run.
7. Restore live activation only through the full checklist.

Never improvise a down migration, delete Drizzle migration history, or remove historical encryption/signature keys as part of an application rollback. Those actions can strand credentials or make retained evidence permanently unavailable.
