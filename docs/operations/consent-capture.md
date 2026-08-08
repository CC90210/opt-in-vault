# Consent capture and retention operations

This guide documents the implemented public capture API, browser SDK, Python client, certificates, and retention boundary.

> Opt-in Vault creates tamper-evident evidence, not a legal shield. The caller remains responsible for the disclosure, affirmative action, identity/authority checks, lawful basis, retention policy, counsel guidance, and channel/provider rules.

## 1. Provision the capture site

There is no capture-site administration UI or public provisioning endpoint in the MVP. A trusted operator must create the tenant-scoped record through the controlled database workflow.

Each active capture site binds:

- a publishable key prefix/hash (`oiv_pk_…`, hashed with `CAPTURE_SITE_KEY_PEPPER`);
- one or more exact allowed HTTP(S) origins (maximum 100);
- a form URL rule;
- the current disclosure version and full disclosure text;
- controller, purpose, and configured channels (`email` and/or `sms`);
- active/paused/revoked state.

The full publishable key may be placed in browser code. It authorizes capture only; it cannot read evidence or administer a tenant. Never expose a tenant `oiv_sk_…` key in browser code.

Allowed origins are exact origins such as `https://www.example.invalid`—not arbitrary CORS wildcards. A form URL rule is either an exact URL or one trailing `*` prefix rule. The wildcard stays within the same origin and must not be treated as a general regular expression.

Before integrating, verify that the visible disclosure text shown to the person exactly corresponds to the registered `disclosure_version`. The SDK does not render a checkbox, validate your UI, or decide whether an interaction is legally sufficient.

## 2. Browser JavaScript SDK

Serve the checked-in self-contained client from the Opt-in Vault origin:

```html
<script src="https://vault.example.invalid/v1/optinvault.js"></script>
```

Call `capture` only after the actual affirmative action—not on page load or merely because a form became visible:

```html
<script>
  async function recordConsent(form) {
    return window.OptInVault.capture({
      endpoint: "https://vault.example.invalid/api/v1/consent/log",
      siteKey: "oiv_pk_REPLACE_WITH_PUBLISHABLE_SITE_KEY",
      disclosureVersion: "signup-disclosure-2026-08",
      affirmativeAction: "form_submit",
      formUrl: window.location.href,
      email: form.elements.email.value,
      idempotencyKey: crypto.randomUUID()
    });
  }
</script>
```

Supported options:

| Option | Required | Notes |
| --- | --- | --- |
| `siteKey` | Yes | Publishable `oiv_pk_…` key for the registered site. |
| `disclosureVersion` | Yes | Must exactly match the active capture-site record. |
| `affirmativeAction` | Yes | Lowercase identifier such as `form_submit`; this is caller-supplied evidence, not an independent UI verification. |
| `email` / `phone` | At least one | Email is normalized; phone must normalize to international E.164. Configured channel requirements still apply. |
| `endpoint` | No | Defaults to `/api/v1/consent/log` relative to the current page. Set it for a separate vault origin. |
| `formUrl` | No | Defaults to `location.href` and must match the registered form rule. |
| `occurredAt` | No | Defaults to the browser's current ISO timestamp; cannot be more than five minutes in the future. |
| `idempotencyKey` | No | Defaults to `crypto.randomUUID()`. Supply a stable key when retrying the same user action. |

The SDK uses CORS with `credentials: omit`, refuses redirects, sends no tenant ID/admin secret, and returns the JSON response. A remote capture endpoint must use HTTPS; plain HTTP is accepted only for loopback development (`localhost`, `127.0.0.1`, or `::1`). It does not automatically retry; the integration owns retry timing and must reuse the same idempotency key for the same action.

## 3. Python client

The dependency-free repository client is `scripts/lib/optinvault_client.py`; it is not published as a package. A server-side integration can import it from a checkout or vendor the reviewed file:

```python
from scripts.lib.optinvault_client import OptInVaultClient

client = OptInVaultClient(
    "https://vault.example.invalid",
    site_key="oiv_pk_REPLACE_WITH_PUBLISHABLE_SITE_KEY",
    timeout=10.0,
)

result = client.log_consent(
    origin="https://www.example.invalid",
    disclosure_version="signup-disclosure-2026-08",
    affirmative_action="form_submit",
    form_url="https://www.example.invalid/signup",
    email="person@example.invalid",
    idempotency_key="signup-event-00000001",
)
```

The Python client requires an explicit Origin, requires HTTPS except on loopback, validates the base URL and headers, limits a response to 1 MiB, and converts HTTP/network/JSON failures to `OptInVaultError`. It does not infer the end user's IP address.

## 4. Direct API contract

### Request

```text
POST /api/v1/consent/log
Content-Type: application/json
Origin: https://www.example.invalid
Idempotency-Key: signup-event-00000001
X-OptInVault-Site-Key: oiv_pk_REPLACE_WITH_PUBLISHABLE_SITE_KEY
```

`Authorization: Publishable <site-key>` is accepted as an alternative to `X-OptInVault-Site-Key`; if both are present they must be identical. The exact media type is `application/json` (parameters such as a charset are allowed). The UTF-8 JSON body is read incrementally, capped at 32 KiB even when `Content-Length` is absent, and may contain only:

```json
{
  "disclosure_version": "signup-disclosure-2026-08",
  "affirmative_action": "form_submit",
  "form_url": "https://www.example.invalid/signup",
  "occurred_at": "2026-08-08T12:00:00.000Z",
  "email": "person@example.invalid"
}
```

Use `phone` instead of or in addition to `email` when the capture site is configured for SMS. A body containing `tenant_id` or `tenantId` is rejected.

### Response

A new record returns 201; an idempotent replay returns 200 with `created: false` and the original evidence identifiers:

```json
{
  "created": true,
  "consent_id": "<opaque consent ID>",
  "certificate_code": "<opaque certificate code>",
  "payload_sha256": "<64-character digest>",
  "signature_hmac": "<64-character HMAC>",
  "signature_key_version": 1,
  "received_at": "2026-08-08T12:00:00.000Z",
  "retention_expires_at": "2027-08-08T12:00:00.000Z"
}
```

Operational error codes include invalid request/site, inactive site, origin/form/disclosure mismatch, unavailable trusted source, rate limiting, idempotency conflict, and evidence verification failure. A rate-limited request returns HTTP 429 with `Retry-After`; missing verified source evidence returns HTTP 503 with `source_unavailable`. Do not turn a rejected capture into a local “success” record; surface or queue the failure with the same idempotency key.

### Idempotency

The idempotency key is 8–128 characters from the accepted identifier alphabet. Replaying the same action returns the stored record after decrypting and verifying it. Reusing a key for materially different evidence returns `idempotency_conflict`.

### Public capture rate limit

The production route uses three durable one-minute fixed windows. Each verified source is capped at 25 requests per active tenant/site across both new captures and completed retries. New captures also share a 120-request tenant/site backstop, so distributed sources cannot create unbounded writes. Completed idempotent retries do not consume that new-capture allowance, but each idempotency key is independently capped at 10 retries. The applicable source-plus-aggregate or source-plus-replay counters are checked and advanced atomically.

Limiter bucket identities are HMACs and do not contain raw email, phone, IP, site ID, or idempotency text. A blocked source does not consume the aggregate allowance, and database/decision uncertainty stops capture before evidence persistence.

Expired bucket rows are indexed by `expires_at`, but the MVP has no automatic pruning job. Include bounded expired-row pruning in controlled database maintenance and monitor table growth; pruning old buckets does not alter immutable consent evidence.

## 5. What the evidence contains

The service normalizes and binds the registered site to a canonical JSON document containing:

- schema, tenant, and capture-site identifiers;
- normalized email and/or phone plus a tenant-bound subject hash;
- controller, purpose, configured channels;
- registered disclosure version and full disclosure text;
- affirmative-action label and form URL;
- request Origin, user agent, occurred/received timestamps;
- request fingerprint and retention deadline;
- trusted network provenance supplied by the configured trusted-edge resolver.

The production route currently supports only a deployment directly on Vercel. It requires `CONSENT_TRUSTED_EDGE_PROVIDER=vercel`, verifies Vercel's `VERCEL=1` runtime marker, and accepts only one public address from `x-vercel-forwarded-for`. It ignores ordinary `x-forwarded-for` input, comma-separated chains, and private/reserved addresses. Without this verified source, capture returns `source_unavailable` before site lookup or persistence. A self-hosted or separately proxied deployment needs a new, provider-specific trusted-edge adapter; do not imitate Vercel's marker or header.

The canonical document is:

1. SHA-256 hashed;
2. HMAC signed with `CONSENT_SIGNATURE_KEY` and its version;
3. encrypted with AES-256-GCM using `CONSENT_ENCRYPTION_KEY` and its payload version;
4. bound by associated data to tenant, consent ID, capture site, resource type, and field;
5. inserted into an immutable `consent_logs` row.

Database triggers reject update and delete operations on consent rows. Corrections or withdrawals must be appended as new records/events; never rewrite the original evidence.

## 6. Certificates

`GET /api/v1/certificate/{code}` renders a remote-resource-free PDF only after it decrypts the canonical payload and verifies canonical encoding, SHA-256, HMAC, and key versions.

Normal access requires the same **active** tenant through a valid session/API key with `admin`, `consent:read`, or `certificate:read`; API-key verification honors the configured current/historical pepper ring. External sharing, when separately provisioned, uses:

```text
Authorization: Share <opaque share token>
```

Share tokens are random, stored only as hashes, expiring, and revocable. Do not put a share token in a query string. Certificate responses are non-cacheable/non-indexable and return 404 for invalid, unauthorized, revoked, expired-share, or retention-expired access so record existence is not disclosed.

## 7. Retention and key destruction

`CONSENT_RETENTION_DAYS` is a positive number of days applied to the server receive time for every new capture. The resulting deadline is stored in both metadata and the canonical payload.

At or after the deadline:

- idempotent replay refuses to decrypt/verify the expired record;
- certificate download is unavailable;
- immutable row metadata/digests can remain visible to authorized operational queries.

The deadline does **not** automatically delete rows or destroy secret-manager keys. There is no retention worker in this MVP.

Consent keys are shared by version, not generated per evidence row. `CONSENT_ENCRYPTION_KEYS_JSON` and `CONSENT_SIGNATURE_KEYS_JSON` allow certificate access to older retained versions (maximum 8 historical entries per ring, with each value capped at 16 KiB). Keep an old encryption and signature key until every record using that version has reached its approved retention deadline.

Destroying/removing an encryption key makes every payload on that version irrecoverable. Removing its signature key prevents HMAC verification. This is irreversible and does not delete the immutable metadata, subject hash, SHA-256 digest, or signature stored in the database.

An approved destruction operation should therefore:

1. inventory all records grouped by payload/signature key version and latest retention deadline;
2. confirm with the data owner and counsel that no hold or longer obligation applies;
3. take and govern any required audit proof without copying plaintext evidence unnecessarily;
4. remove the old values from every web/worker secret store and historical ring;
5. verify that current-version capture/certificates still work and old-version certificates fail closed;
6. record who approved/performed the action, version IDs, timestamp, and verification outcome.

Do not destroy keys merely because application code was rolled back. Keep application rollback and evidence-retention decisions separate.

## 8. Legal and provider boundary

Opt-in Vault records what the configured integration submitted and detects later mutation of the stored canonical evidence. It does not verify that:

- the person was who they claimed to be;
- the person had authority to consent for another party;
- the disclosure or user experience met every applicable legal standard;
- a consent remains valid for every future purpose/channel/jurisdiction;
- an email/SMS provider permits the proposed traffic;
- an evidence record alone will satisfy a regulator or court.

Have qualified counsel approve disclosures, affirmative-action design, retention/destruction policy, and withdrawal handling. Follow current provider acceptable-use, anti-abuse, OAuth, and unsubscribe requirements. Preserve the exact UI/disclosure version and integration release that produced each event so the evidence can be interpreted later.
