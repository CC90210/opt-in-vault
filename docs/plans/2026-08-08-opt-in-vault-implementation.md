# Opt-in Vault MVP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Ship a locally verified Next.js 15/Turso MVP for multi-inbox sequencing, reply handling, consent evidence, certificates, DNS health, and tenant-wide suppression without live external effects.

**Architecture:** A modular Next.js application provides the dashboard and thin Route Handlers. Server-only services own Turso access, outbound transport, IMAP, DNS, cryptography, and PDF generation; bounded cron/CLI workers call those same services. All durable work is modeled as explicit state machines with tenant-scoped database constraints.

**Tech Stack:** Next.js 15.5.x, React 19, strict TypeScript, Tailwind CSS 4, Drizzle ORM, Turso/libSQL, Nodemailer, ImapFlow, MailParser, `@react-pdf/renderer`, Zod, Vitest.

---

### Task 1: Scaffold and verification harness

**Files:**
- Create generated Next.js base under repository root
- Create: `vitest.config.ts`
- Create: `src/test/setup.ts`
- Create: `.env.example`
- Modify: `package.json`, `tsconfig.json`, `.gitignore`, `README.md`

1. Generate the TypeScript/App Router/Tailwind/src-dir base and pin Next.js 15.
2. Add runtime and development dependencies plus `test`, `test:watch`, `typecheck`, `db:generate`, `db:migrate`, and worker scripts.
3. Configure Vitest with Node and jsdom projects where needed.
4. Add hardened secret ignores and placeholder-only environment documentation.
5. Run the empty harness, lint, and typecheck.

### Task 2: Database schema and executable migration

**Files:**
- Create: `src/db/schema.ts`
- Create: `src/db/client.ts`
- Create: `src/db/types.ts`
- Create: `drizzle.config.ts`
- Create: `drizzle/0000_opt_in_vault.sql`
- Create: `scripts/migrate.ts`
- Test: `src/db/schema.integration.test.ts`

1. Write failing tests for migration execution, required tables, constraints, immutable consent triggers, tenant composite references, and due-work indexes.
2. Execute tests to confirm the empty schema fails.
3. Define non-null tenant-owned tables, composite keys/FKs, `CHECK` constraints, and Unix-millisecond timestamps.
4. Add Drizzle client construction with `import "server-only"`, foreign keys enabled locally, and dependency injection for tests.
5. Generate/apply the migration to a disposable libSQL file, run `foreign_key_check`, and verify the failing tests turn green.

### Task 3: Auth, cryptography, and validation primitives

**Files:**
- Create: `src/server/auth/api-keys.ts`
- Create: `src/server/auth/session.ts`
- Create: `src/server/auth/cron.ts`
- Create: `src/server/security/encryption.ts`
- Create: `src/server/security/tokens.ts`
- Create: `src/server/security/network.ts`
- Create: `src/server/validation/*`
- Tests beside each module

1. Write failing tests for API-key hashing/scope lookup, signed sessions, fail-closed cron auth, AES-GCM round trip/tamper/AAD failure, opaque token hashing, unsafe host rejection, body limits, and CRLF rejection.
2. Implement the smallest primitives that pass.
3. Ensure tenant identity is returned by auth and never accepted from a public request body.
4. Re-run the focused and full test suites.

### Task 4: Consent capture, SDK, and evidence certificate

**Files:**
- Create: `src/server/consent/canonicalize.ts`
- Create: `src/server/consent/service.ts`
- Create: `src/server/certificates/render.tsx`
- Create: `src/app/api/v1/consent/log/route.ts`
- Create: `src/app/api/v1/certificate/[code]/route.ts`
- Create: `public/v1/optinvault.js`
- Create: `scripts/lib/optinvault_client.py`
- Tests: consent service/route/PDF/SDK/client tests

1. Write failing tests for origin/disclosure binding, replay idempotency, trusted IP parsing, canonical hash/signature verification, mutation rejection, protected/expiring certificate access, PDF magic bytes, and no-store headers.
2. Implement capture-site authentication and durable fail-closed evidence insertion.
3. Implement a self-contained browser SDK and a dependency-light Python client.
4. Render a text-only, remote-resource-free tamper-evident evidence PDF.
5. Run focused and integration tests.

### Task 5: Suppression and RFC 8058 unsubscribe

**Files:**
- Create: `src/server/suppression/service.ts`
- Create: `src/server/unsubscribe/tokens.ts`
- Create: `src/server/unsubscribe/service.ts`
- Create: `src/app/api/v1/unsubscribe/route.ts`
- Tests beside service and route

1. Write failing tests for email/phone normalization, tenant-wide uniqueness, cross-tenant isolation, queued-job cancellation, idempotent POST, non-mutating GET, invalid token rejection, and no redirect.
2. Implement the suppression transaction and unsubscribe token lifecycle.
3. Verify the POST accepts RFC 8058 form payload without cookies/auth and returns directly.
4. Run race/idempotency integration tests.

### Task 6: Templates, durable dispatcher, and outbound gateway

**Files:**
- Create: `src/server/templates/render.ts`
- Create: `src/server/dispatch/repository.ts`
- Create: `src/server/dispatch/service.ts`
- Create: `src/server/email/gateway.ts`
- Create: `src/server/email/nodemailer-transport.ts`
- Create: `src/app/api/v1/cron/dispatch/route.ts`
- Create: `scripts/worker-dispatch.ts`
- Tests beside modules

1. Write failing tests for deterministic spintax, variable escaping, header injection, due claims, lease recovery, daily caps, suppression races, stable message IDs/rendered content, 180–450 second persisted jitter, exact RFC 8058 headers, DKIM header coverage, dry-run behavior, and ambiguous-send quarantine.
2. Implement a single gateway boundary with an injectable transport.
3. Implement atomic claim/reservation and bounded batch execution without sleeping.
4. Add fail-closed cron auth and CLI one-cycle worker.
5. Prove no transport construction or `sendMail` call exists outside the gateway module.

### Task 7: IMAP reply listener and sentiment effects

**Files:**
- Create: `src/server/inbound/classify.ts`
- Create: `src/server/inbound/match.ts`
- Create: `src/server/inbound/service.ts`
- Create: `src/server/inbound/imap-client.ts`
- Create: `src/app/api/v1/cron/poll-inboxes/route.ts`
- Create: `scripts/worker-inboxes.ts`
- Tests beside modules

1. Write failing tests for UID deduplication, UIDVALIDITY reset, references-based matching, unambiguous sender fallback, auto-response headers, unsubscribe/OOO/interested/not-interested/other/bounce classes, and pause-before-classification effects.
2. Implement bounded read-only polling with mailbox locks, size limits, reconnect/backoff state, and token-safe errors.
3. Persist inbound mail metadata before applying effects; never execute content.
4. Create notification outbox rows for interested replies.

### Task 8: DNS health and sending gates

**Files:**
- Create: `src/server/dns/scan.ts`
- Create: `src/server/dns/service.ts`
- Create: `src/app/api/v1/domains/[id]/scan/route.ts`
- Tests beside modules

1. Write failing tests using an injected resolver for SPF, selector DKIM, DMARC, MX, alignment states, transient errors, and cross-tenant access.
2. Implement snapshot persistence and an explicit healthy/degraded/blocked result.
3. Connect domain health to the dispatcher preflight.
4. Label provider-managed DKIM honestly; do not claim delivered-message verification.

### Task 9: Authenticated operator dashboard

**Files:**
- Create: `src/app/login/*`, `src/app/(dashboard)/*`
- Create: `src/components/*`
- Create: `src/server/dashboard/queries.ts`
- Modify: `src/app/globals.css`, `src/app/layout.tsx`, `src/app/page.tsx`
- Tests: dashboard query isolation and component smoke tests

1. Write failing query tests that prove metrics are live, tenant-scoped, and never replaced by mocks.
2. Implement API-key login/session exchange and server-side route authorization.
3. Build overview, campaigns, inbox/domain, consent, and suppression pages using the evidence-vault visual system.
4. Add honest empty/error states, responsive navigation, accessible focus/order/contrast, and restrained motion.
5. Run UI smoke tests plus lint/typecheck.

### Task 10: Final integration, documentation, and proof

**Files:**
- Create: `vercel.json`
- Create: `SECURITY.md`
- Modify: `README.md`, `.env.example`
- Create/modify tests required by the end-to-end checklist

1. Add bounded cron declarations and document the persistent-worker alternative.
2. Document setup, migrations, dry-run seeding, OAuth/SMTP/IMAP configuration, DNS meaning, API/SDK use, retention/counsel boundaries, and operator activation gates.
3. Run fresh migration tests, unit/integration tests, lint, strict typecheck, production build, client-bundle native/secret scan, secret scan, and `git status`.
4. Run a cold independent spec/security/code review and fix every important finding.
5. Do not create a remote, push, deploy, connect real inboxes, or send mail without a separate operator-authorized action.

