# Security policy

Opt-in Vault handles tenant credentials, recipient identifiers, consent evidence, and outbound email state. Treat every deployment as a security-sensitive system and fail closed when configuration or evidence is uncertain.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the repository owner through an established secure channel. Do not include live API keys, OAuth tokens, recipient data, consent payloads, or mailbox credentials in an issue, pull request, screenshot, or chat message. Include the affected component, reproducible steps using synthetic data, and the impact.

Only the current maintained revision is supported by this MVP. There is no public bug-bounty program or guaranteed response SLA.

## Security boundaries

### Tenant identity

- Tenant identity comes from a verified API key/session or a capture-site lookup; public request bodies cannot choose a tenant.
- Tenant API keys use the `oiv_sk_` format. Only their lookup prefix and an HMAC hash are stored.
- API-key records can be scoped, expired, and revoked. Required route scopes are checked server-side.
- Dashboard login accepts a tenant key with `dashboard:read`, then issues a signed session valid for at most 60 minutes.
- The session cookie is host-only (`__Host-`), `Secure`, `HttpOnly`, `SameSite=Lax`, and has no `Domain` attribute.
- Cron endpoints use a separate bearer secret of at least 32 bytes. A missing or weak secret fails authorization.

The schema adds tenant IDs to owned rows and uses composite same-tenant references on critical relationships. This is application/database isolation, not a claim that one shared database is equivalent to a separate database per tenant.

### Secret storage

Never commit `.env.local`, credential JSON, private keys, OAuth client files, local databases, or generated certificates. The repository ignores those paths, but ignore rules are not a substitute for review.

Use a production secret manager and generate a distinct value for every secret. Do not reuse any of these across environments or purposes:

- API-key peppers, session/cron secrets, dispatch lease pepper;
- unsubscribe token and suppression hash keys;
- inbox credential-encryption keys;
- capture-site, subject-hash, consent-signature, and consent-encryption keys;
- certificate share-token pepper.

Most HMAC/pepper values require at least 32 bytes. AES keys must resolve to exactly 32 bytes and may be encoded as 64 hexadecimal characters or canonical base64. Placeholder values in `.env.example` are deliberately not production secrets.

### Mail credentials and egress

- SMTP, IMAP, OAuth, and optional local-DKIM material live in one encrypted credential payload.
- AES-256-GCM authenticates the ciphertext and binds it to the tenant, inbox, provider, and normalized combined SMTP/IMAP host binding. Copying a ciphertext to another inbox or changing a bound host makes decryption fail.
- SMTP is restricted to implicit TLS on port 465 or required STARTTLS on port 587. IMAP requires implicit TLS on port 993. TLS 1.2 or newer and certificate validation are mandatory.
- Mail egress resolves and pins public addresses. Loopback, private, link-local, documentation, local-name, and unapproved-port targets are rejected to reduce SSRF and credential-exfiltration risk.
- The configured From address must exactly match the registered sending domain.

The application does not perform an interactive Google or Microsoft OAuth grant. Operators obtain and rotate provider credentials under the provider's rules, then provision the encrypted payload through a trusted administrative workflow.

### Outbound safety

Live SMTP requires both `LIVE_SENDS_ENABLED=true` and an active, approved campaign with `dry_run=false`. The dispatcher also rechecks tenant, enrollment, lead, inbox, domain, schedule, suppression, and quota state immediately before preparation.

- Suppressions are keyed hashes and apply across every campaign/inbox inside one tenant.
- Rendered content and Message-ID are persisted so retries cannot silently change material.
- A definitive rejection may retry with bounded backoff; a possibly accepted/ambiguous result becomes `unknown` and is never automatically resent.
- RFC 8058 messages contain both required headers and a visible HTTPS unsubscribe URL.
- Live delivery requires application-controlled local DKIM signing that covers both RFC 8058 headers. Provider-managed DKIM can be recorded for DNS visibility, but live transport creation fails closed because the application cannot prove header coverage.
- `GET /api/v1/unsubscribe` never mutates. The exact one-click form POST is idempotent and applies suppression transactionally.

Setting `LIVE_SENDS_ENABLED=false` and pausing active campaigns are the immediate containment controls. They cannot retract a message already accepted by a provider.

### Consent evidence

Consent capture binds an active publishable site key to an exact allowed origin, registered disclosure version, configured channel set, and form URL rule. It requires an idempotency key and rejects payloads that try to provide a tenant ID.

Evidence payloads are canonicalized, SHA-256 hashed, HMAC signed with a recorded key version, and encrypted with AES-256-GCM. Database triggers reject updates and deletes to `consent_logs`; corrections must be appended as new evidence.

This produces **tamper-evident evidence, not a legal shield**. It does not independently establish identity, authority, disclosure sufficiency, or lawful consent. Applicable law, counsel guidance, and provider rules still apply. The default route does not trust browser-supplied forwarding headers as IP evidence.

## Key rotation and destruction

Rotation is an operational migration, not an environment-variable rename.

1. Back up the database and current secret-manager versions.
2. Add the old value to the appropriate historical ring before activating a new version.
3. Deploy the new current key/version and verify reads, dispatch dry runs, inbox polling, and certificate generation.
4. Re-encrypt or re-hash records where the design permits it.
5. Remove a historical key only after no retained record or active token needs it.

Bounded rings fail closed:

- API-key pepper ring: at most 8 current-plus-historical versions; historical JSON at most 16 KiB.
- Inbox credential key ring: at most 8 current-plus-historical AES keys; historical JSON at most 32 KiB.
- Consent certificate encryption and signature rings: at most 8 historical entries each; each value at most 16 KiB.

Important non-ring rotations:

- Rotating `SESSION_SECRET` immediately invalidates every dashboard session.
- Rotating `CERTIFICATE_SHARE_TOKEN_PEPPER` invalidates existing share tokens.
- Rotating `UNSUBSCRIBE_TOKEN_SECRET` invalidates existing unsubscribe tokens.
- Rotating `SUPPRESSION_HASH_KEY` without a controlled re-hash makes existing suppression lookups inconsistent. The application does not retain the raw identifier needed for a general re-hash.
- Rotate `DISPATCH_LEASE_PEPPER` only while dispatch is stopped and outstanding leases have been reconciled.
- Rotating `CONSENT_SUBJECT_HASH_KEY` changes subject hashes and breaks continuity with older hashes.

`CONSENT_RETENTION_DAYS` records a deadline and the application refuses certificate/decryption use at or after that deadline. It does not delete rows or destroy keys automatically. Consent encryption/signature keys are shared by version, so destroying one version affects every evidence record using it. Key destruction must be an explicit, audited secret-manager action after all records on that version have expired and the operator's retention policy and counsel permit it. It is irreversible; immutable metadata/digests may remain while the encrypted payload and certificate become unavailable.

## Production requirements

- Serve the application only over HTTPS. Secure dashboard cookies and unsubscribe links depend on it.
- Use a durable remote Turso/libSQL database for ephemeral or multi-instance deployments. A local `file:` database is for local/single-host operation only.
- Apply migrations once before starting new application/worker code, and take a restorable database snapshot first.
- Run the web app, dispatch scheduler, and inbox scheduler with the same compatible secret versions.
- Keep `LIVE_SENDS_ENABLED=false` through migrations, key rotation, restoration, and smoke testing.
- Restrict database and deployment access to trusted operators and retain provider/audit logs without secret values.

There is no Supabase dependency, RLS policy, or Supabase backup to configure. Turso/libSQL and the application tenant checks are the data boundary for this MVP.

## Incident containment

For suspected credential exposure or incorrect delivery:

1. Set `LIVE_SENDS_ENABLED=false`, pause active campaigns, and stop both scheduler paths.
2. Revoke affected provider/API credentials at their issuer.
3. Preserve database/provider logs and record timestamps; do not edit immutable evidence.
4. Determine which key versions, tenants, inboxes, and messages were affected.
5. Rotate with the historical-key procedure above only after the scope is understood.
6. Restore service in dry-run mode and verify suppression, DNS, inbox, and certificate paths before considering live activation.
