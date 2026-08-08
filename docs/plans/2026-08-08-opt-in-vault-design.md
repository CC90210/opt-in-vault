# Opt-in Vault MVP Design

**Status:** Approved by CC's attached "FINAL SYSTEM MESSAGE" and refined for tenant isolation, outbound safety, and RFC 8058 correctness.

**Goal:** Build a private, multi-workspace outbound and consent-evidence platform that can replace the core Instantly/Smartlead workflow without Supabase while failing closed around suppression, credentials, and ambiguous delivery outcomes.

## Chosen approach

Opt-in Vault will ship as a modular Next.js 15 application with a shared Turso/libSQL database, thin Route Handlers, server-only application services, and two bounded worker entry points (dispatch and inbox polling). A persistent worker can call the same services later; HTTP handlers will never sleep for jitter or hold a database transaction open across SMTP, IMAP, DNS, or PDF work.

Three approaches were considered:

1. **Modular Next.js application plus bounded workers (chosen).** It matches the brief, is locally runnable, and can deploy as one app. Durable state lives in Turso; cron routes only execute bounded work.
2. **Separate web and worker services.** This is the best long-term shape for always-on IMAP and high volume, but adds a second deployment target before the MVP has proven demand.
3. **Queue/event platform.** This offers stronger retries but adds an external subscription and conflicts with the in-house mission.

The shared database is an MVP choice. Every owned row has a non-null `tenant_id`; same-tenant relationships use composite foreign keys; every repository receives tenant identity from an authenticated context; and isolation tests attempt forged cross-tenant references. The repository layer is kept narrow enough to route each tenant to its own Turso database later.

## Safety boundary

Opt-in Vault is the physical outbound chokepoint for this product. No SMTP call may exist outside `src/server/email/gateway.ts`. The Empire Python client calls Opt-in Vault; it does not introduce a second SMTP path.

Live delivery requires all of the following:

- `LIVE_SENDS_ENABLED=true` at runtime;
- an active campaign with an explicit approval timestamp;
- an active, verified sending inbox and domain;
- a healthy suppression lookup and a fresh pre-send recheck;
- available tenant, inbox, and recipient capacity;
- a durable claimed send job.

The default is dry-run. Missing configuration, database failure, unknown domain health, suppression lookup failure, or ambiguous state blocks delivery. No real inboxes or recipients are configured by the build or test suite.

## Authentication and secrets

- Tenant API keys are 256-bit random bearer keys. Only a prefix and keyed hash are stored.
- Browser consent capture uses a separate publishable site key with an origin allowlist; it cannot read or administer data.
- Dashboard login exchanges a valid tenant API key for a short-lived, signed, HTTP-only session cookie. Middleware is navigation UX only; every server action and route re-authorizes.
- Cron routes require `Authorization: Bearer <CRON_SECRET>` and fail closed when the secret is missing.
- SMTP, IMAP, OAuth, and optional local DKIM material are encrypted with AES-256-GCM. The ciphertext stores key version/nonce/tag, and associated data binds it to tenant, inbox, provider, and host. Host changes require credential replacement.
- SMTP/IMAP endpoints reject private, loopback, link-local, and non-approved ports to reduce SSRF and credential exfiltration risk.
- Raw API keys, credentials, OAuth tokens, unsubscribe tokens, and certificate share tokens never enter logs.

## Data model

The migration creates these groups:

- **Identity:** `tenants`, `tenant_api_keys`, `capture_sites`.
- **Sending:** `sending_domains`, `dns_checks`, `sending_inboxes`, `campaigns`, `sequence_steps`, `leads`, `campaign_enrollments`.
- **Durable delivery:** `send_jobs`, `delivery_attempts`, `outbound_messages`, `inbox_daily_usage`, `worker_runs`.
- **Inbound:** `imap_cursors`, `inbound_messages`, `reply_events`.
- **Compliance:** `consent_logs`, `consent_certificates`, `suppressions`, `suppression_events`, `unsubscribe_tokens`.
- **Operations:** `notifications`, `audit_events`, `rate_limit_buckets`.

Operational timestamps are integer Unix milliseconds. Human display converts at the edge. Status columns have SQLite `CHECK` constraints. Due-work and tenant ownership paths have explicit indexes.

Evidence and suppression records do not cascade on tenant deletion. Consent rows are insert-only through database triggers; corrections are appended as new events. Each consent event stores canonical JSON, its SHA-256 digest, and an HMAC signature/key version. This is a tamper-evident evidence record. It is not advertised as independent proof of identity or legal compliance.

## Dispatch state machine

Campaign enrollment creates one deterministic send job per due sequence step. Before SMTP, a short database operation:

1. claims one due job with a lease;
2. rechecks campaign/inbox/domain/live-send gates;
3. rechecks tenant-wide suppression;
4. reserves daily inbox capacity without exceeding the limit;
5. persists the rendered subject/body, stable `Message-ID`, opaque unsubscribe reference, and attempt record.

SMTP occurs after the transaction. A definitive success records provider acceptance and schedules the next step. A definitive rejection releases capacity and applies bounded backoff. A possibly-accepted result becomes `unknown`; it is never automatically resent. A stable message ID and immutable rendered content make reconciliation possible.

Jitter is persisted in `next_available_at` and `due_at` (180–450 seconds by default). HTTP code never sleeps. Enrollments stay pinned to their first inbox for thread continuity unless an explicit future failover policy changes that.

## RFC 8058 unsubscribe

Messages include an HTTPS `List-Unsubscribe` URI and the exact `List-Unsubscribe-Post: List-Unsubscribe=One-Click` header. Tokens are high-entropy opaque values stored only as hashes.

- `GET` displays status/confirmation and does not mutate, preventing security-scanner link fetches from unsubscribing people.
- `POST` requires no cookie or authorization, does not redirect, is idempotent, and immediately inserts tenant-wide suppression and cancels queued jobs.
- Local Nodemailer DKIM configuration explicitly signs both unsubscribe headers. Provider-managed DKIM inboxes must pass a DNS/health gate; the UI labels provider signing as externally managed rather than claiming cryptographic verification of a delivered message.

The message body also contains a visible unsubscribe link.

## Inbox reply processing

ImapFlow polls by UID, not unread state. Each inbox/mailbox stores `UIDVALIDITY`, last UID, and highest mod-sequence. Raw messages are bounded in size, parsed with MailParser, and deduplicated by `(inbox, uid_validity, uid)` before effects.

Replies first match `In-Reply-To`/`References` against stored outbound message IDs, with sender-address fallback only when unambiguous. Any genuine human reply pauses the enrollment before classification. Deterministic classifications are `unsubscribe`, `out_of_office`, `interested`, `not_interested`, `bounce`, and `other`; ambiguous replies remain paused for review. Inbound content is untrusted data and never becomes executable instruction.

## Consent capture and certificates

The public SDK captures the registered disclosure version, affirmative action, form URL, trusted-edge IP provenance, user agent, email/phone, controller, purpose, and server timestamp. It accepts an idempotency key and rejects origin/disclosure mismatches. Browser-supplied IP headers are not trusted.

Certificate PDFs are generated server-side from verified stored evidence. Normal export requires tenant authorization. External sharing uses a separate random, expiring, hashed share token. Responses are non-cacheable, non-indexable, and do not load remote resources. PDF output is labelled "Tamper-Evident Consent Evidence Record."

## DNS health

The DNS scanner stores snapshots for SPF, DKIM selector, DMARC, and MX. It distinguishes record presence from verified alignment. An inbox cannot send until its sending domain is marked healthy. The dashboard shows actionable failures without promising inbox placement.

## User interface

The dashboard uses an industrial evidence-vault direction: warm paper surfaces, near-black ink, oxidized green for verified controls, and safety orange for blocked work. The memorable element is a chain-of-custody rail that connects consent, suppression, delivery, and reply events.

Pages cover overview, campaigns, inboxes/domains, consent vault, and suppressions. Empty states are honest and actionable; no mock metrics are shipped. Server failures render diagnostics rather than plausible sample numbers.

## Verification

Vitest runs unit and integration tests against disposable local libSQL. The gate includes:

- migration execution and foreign-key checks;
- tenant-isolation and cross-tenant FK rejection;
- API/cron/session authentication;
- secret encryption/tamper rejection and log redaction;
- spintax/template/header-injection validation;
- atomic claim/quota/idempotency behavior;
- suppression/send race behavior;
- RFC 8058 GET/POST semantics and signed-header configuration;
- IMAP UID deduplication and reply effects;
- consent hash/signature verification and immutable triggers;
- PDF signature/magic-byte and non-cache headers;
- SDK and Python client request shape;
- ESLint, strict TypeScript, production build, and client-bundle secret scan.

Real SMTP, IMAP, OAuth, DNS mutation, outbound delivery, Turso production writes, and deployment are excluded from automated verification and remain operator-gated.

