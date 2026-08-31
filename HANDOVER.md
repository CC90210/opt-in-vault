# Opt-in Vault — AI Agent Handover & Integration Guide

> **Target Audience:** AI Coding Agents (Codex, Claude, Cursor, OpenCode) & Developers setting up, ingesting, or integrating Opt-in Vault for business units (e.g. Sunbiz, PropFlow, OASIS AI Solutions).

---

## 1. Executive Summary & Architecture

**Opt-in Vault** is a high-reliability, compliance-grade outbound campaign engine and tamper-evident consent-evidence repository. It replaces third-party tools like Instantly or Smartlead while providing verifiable legal compliance (TCPA, CASL, CAN-SPAM, GDPR) via cryptographic consent signatures and RFC 8058 one-click unsubscribe handling.
https://github.com/CC90210/opt-in-vault

### Core Stack
- **Framework:** Next.js 15 (App Router, React 19, Server Components & Server Actions)
- **Database:** Turso / libSQL with Drizzle ORM (Pure SQLite dialect, zero Supabase dependency)
- **Email Delivery:** Nodemailer (SMTP with mandatory TLS/STARTTLS + Local/Provider DKIM)
- **Inbound Polling:** ImapFlow (UID-based incremental sync + MailParser + AI classification)
- **Certificates:** `@react-pdf/renderer` (Server-side tamper-evident PDF evidence records)
- **Verification:** 100% test passing (358 vitest tests, strict TypeScript, ESLint clean, production build verified)

---

## 2. Drip Sequence Engine (Architecture & Lifecycle)

Opt-in Vault includes a built-in, multi-step drip sequence dispatcher that operates asynchronously via worker cycles.

### Database Model for Sequences
- `campaigns`: Parent campaign container (`status`, `schedule_json`, `timezone`, `jitter_min_seconds`, `dry_run`, `approved_at`).
- `sequence_steps`: Multi-step templates bound to a campaign (`step_order`, `delay_days`, `subject_template`, `body_template`).
- `leads`: Contact registry (`email_address`, `normalized_email`, `first_name`, `last_name`, `company_name`, `lawful_basis`).
- `campaign_enrollments`: Links a lead to a campaign (`current_step`, `next_send_at`, `status`, `inbox_id`).
- `send_jobs`: Bounded, leased execution jobs created per step (`due_at`, `status`, `attempt_count`, `rendered_subject`, `rendered_body`).

### Sequence Execution Lifecycle
```
[Lead Form Submit] ──> [Consent Sealed] ──> [Enrollment Created (Step 1, next_send_at=now)]
                                                            │
                                                            ▼
[Cron Worker: dispatch] <── (materializeDueEnrollments) ────┘
         │
         ├──> 1. Claims send_job with 120s lease (claimNext)
         ├──> 2. Renders step template with lead variables
         ├──> 3. Validates domain health, suppression, & inbox daily quota
         ├──> 4. Sends email via Gateway (SMTP + DKIM + RFC 8058 headers)
         └──> 5. Calls finishSuccessfulDelivery:
                    ├─ Paces inbox (next_available_at += jitter)
                    ├─ Queries sequence_steps for (step_order > current_step)
                    ├─ If Next Step Exists:
                    │     ├─ Calculates dueAt = now + (delay_days * 86400000) + jitter
                    │     ├─ Inserts next send_job (status='queued', due_at=dueAt)
                    │     └─ Updates campaign_enrollments (current_step=nextStepOrder, next_send_at=dueAt)
                    └─ If Final Step Complete:
                          └─ Sets campaign_enrollments.status = 'completed'
```

### Inbound Reply Handling for Drip Sequences
When `worker:inboxes` polls configured sending inboxes:
1. Matches incoming `In-Reply-To` / `References` headers against stored `outbound_messages.message_id`.
2. Upon matching a lead's reply, the enrollment status is **immediately paused** (`status='replied'`) to prevent further drip messages from sending automatically.
3. The message is classified (`interested`, `not_interested`, `unsubscribe`, `out_of_office`, `bounce`).

---

## 3. How to Deploy Opt-in Vault

### Requirements
- **Node.js:** v20.x or newer
- **Hosting:** Vercel (required for `CONSENT_TRUSTED_EDGE_PROVIDER=vercel` to verify real client IPs for compliance evidence)
- **Database:** Turso Database (LibSQL cloud) or local file (`file:./data/opt-in-vault.db`)

### Environment Setup (`.env.local`)
Copy `.env.example` to `.env.local` and set required 32-byte secret keys:

```dotenv
TURSO_DATABASE_URL=libsql://your-db.turso.io
TURSO_AUTH_TOKEN=your-turso-auth-token

NEXT_PUBLIC_APP_URL=https://optinvault.yourdomain.com
SESSION_SECRET=min-32-byte-secret-key-for-sessions-here
CAPTURE_SITE_KEY_PEPPER=min-32-byte-secret-key-for-sites-here
DISPATCH_LEASE_PEPPER=min-32-byte-secret-key-for-leases-here
UNSUBSCRIBE_TOKEN_SECRET=min-32-byte-secret-key-for-unsub-here
SUPPRESSION_HASH_KEY=min-32-byte-secret-key-for-suppression-here
CREDENTIAL_ENCRYPTION_KEY_V1=hex-encoded-32-byte-key
CONSENT_PAYLOAD_KEY_V1=hex-encoded-32-byte-key
CONSENT_SIGNATURE_KEY_V1=hex-encoded-32-byte-key
CRON_SECRET=min-32-byte-cron-authorization-secret

LIVE_SENDS_ENABLED=true
CONSENT_TRUSTED_EDGE_PROVIDER=vercel
```

### Migration Execution
```powershell
npm run db:migrate
```

### Worker Schedulers
Set up external cron jobs (e.g. Vercel Cron or GitHub Actions) triggering every 1–5 minutes:
- `POST https://optinvault.yourdomain.com/api/v1/cron/dispatch` (`Authorization: Bearer <CRON_SECRET>`)
- `POST https://optinvault.yourdomain.com/api/v1/cron/poll-inboxes` (`Authorization: Bearer <CRON_SECRET>`)

---

## 4. Business Unit Integration Guide (e.g. Sunbiz)

Integrating Opt-in Vault into a business unit like Sunbiz involves 3 steps:

### Step 1: Provision a Capture Site & Get Embed Snippet
Call `POST /api/v1/sites` with your Tenant API Key (`scopes: ["admin"]`):

```json
POST /api/v1/sites
Header: Authorization: Bearer <TENANT_API_KEY>

{
  "name": "Sunbiz Florida LLC Capture",
  "allowedOrigins": ["https://sunbiz.yourdomain.com"],
  "formUrlPattern": "https://sunbiz.yourdomain.com/start*",
  "disclosureVersion": "sunbiz-v1-2026",
  "disclosureText": "By submitting, I agree to receive compliance updates and automated sequence guidance.",
  "controller": "Sunbiz Automation Dept",
  "purpose": "Business formation & compliance outreach",
  "channels": ["email"]
}
```

**Response:** Returns `site_key` (`oiv_pk_...`) and the copy-paste JS snippet.

### Step 2: Embed Consent Capture on Frontend
Paste the generated snippet into the Sunbiz web form:

```html
<script src="https://optinvault.yourdomain.com/v1/optinvault.js"></script>
<script>
  async function onSubmitSunbizForm(formElement) {
    const consent = await window.OptInVault.capture({
      endpoint: "https://optinvault.yourdomain.com/api/v1/consent/log",
      siteKey: "oiv_pk_your_generated_site_key",
      disclosureVersion: "sunbiz-v1-2026",
      affirmativeAction: "form_submit",
      formUrl: window.location.href,
      email: formElement.email.value,
      idempotencyKey: crypto.randomUUID()
    });
    console.log("Consent sealed with SHA256:", consent.payloadSha256);
  }
</script>
```

### Step 3: Enroll Lead into Drip Sequence
When Sunbiz processes the form submission (via API or database script), insert the lead and campaign enrollment into Opt-in Vault:

```typescript
// 1. Insert or update Lead
await db.insert(leads).values({
  id: `lead_${randomUUID()}`,
  tenantId: SUNBIZ_TENANT_ID,
  emailAddress: leadEmail,
  normalizedEmail: leadEmail.toLowerCase().trim(),
  firstName: leadFirstName,
  companyName: leadCompany,
  status: "active",
  lawfulBasis: "consent",
  source: "sunbiz_web_form"
}).onConflictDoNothing();

// 2. Enroll into Sunbiz Drip Campaign
await db.insert(campaignEnrollments).values({
  id: `enrollment_${randomUUID()}`,
  tenantId: SUNBIZ_TENANT_ID,
  campaignId: SUNBIZ_DRIP_CAMPAIGN_ID,
  leadId: leadId,
  status: "pending",
  currentStep: 1,
  nextSendAt: Date.now() // Triggers immediate dispatch on next worker run
});
```

---

## 5. Verification Commands for Ingestion Agent

To verify full system integrity after cloning:

```powershell
npm run typecheck   # Must exit 0 with no TypeScript errors
npm run lint        # Must exit 0 with 0 errors and 0 warnings
npm test            # Must pass all 358 Vitest unit/integration tests
npm run build       # Must produce clean Next.js production output
```

All 51 test suites cover tenant isolation, DKIM key matching, RFC 8058 unsubscribe, tamper-evident consent PDF rendering, site key hashing, and sequence materialization.
