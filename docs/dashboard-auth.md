# Dashboard authentication foundation (default off)

This milestone implements only local dashboard authentication. No frontend,
payment-history BFF, operator API-key storage, accounts, or credentials are
provisioned. Existing payment Bearer authentication is independent of cookies.
All payments remain simulator-only. Migration 004 is additive and is applied by
the existing startup migration runner, even when the feature is disabled.

## Configuration and routes

DASHBOARD_ENABLED defaults to false (routes return the normal 404).
When enabled, DASHBOARD_PUBLIC_ORIGIN must be an exact HTTPS origin with no
trailing slash, path or credentials. No localhost HTTP cookie exceptions exist.
DASHBOARD_TRUSTED_PROXIES defaults to empty: Express ignores forwarded IPs.
Only independently verified proxy IPs/CIDRs may be configured, comma-separated.
No hop-count, named-network or catch-all setting is accepted. Do not guess Render
proxy networks or enable this on staging until its ingress topology is reviewed.
Without trust configuration a proxied deployment shares the ingress IP limit;
this fails conservatively rather than trusting attacker-controlled headers.
If an approved proxy chain forwards untrusted header values, resolve that before
use. Only list boundaries under infrastructure control; no network-wide trust.

Same-origin endpoints under /dashboard-api/auth:

- GET /csrf: issues a 10-minute pre-auth session and session-bound CSRF token;
  existing valid sessions receive a rotated CSRF token. Cross-origin/cross-site
  requests are rejected. Browser same-origin policy protects the response.
- POST /login: exact Origin, pre-auth cookie, X-CSRF-Token and strict JSON
  {username,password}. Success consumes the pre-auth token once and returns a
  fresh authenticated cookie and CSRF token. Duplicate concurrent submissions
  cannot create two authenticated sessions from one pre-auth token.
- GET /me: minimal user/operator identity and viewer role; updates idle activity.
- POST /logout: exact Origin and matching CSRF token required; deletes session
  and expires the cookie. Never use GET logout.

Cookies are __Host-vaultx_session, Secure, HttpOnly, SameSite=Lax, Path=/, with
no Domain. Authenticated cookies last at most 8 hours; database checks enforce
30-minute idle and 8-hour absolute expiry. All auth responses use no-store.
Session and CSRF verifiers use SHA-256 of independent 256-bit random tokens.
Raw tokens appear only in their intended cookie/CSRF responses, never logs or
artifacts. CSRF tokens belong in in-memory request state, not URLs. A CSRF refresh
rotates the token; concurrent browser tabs must handle a refused stale token.
No CORS, JWT, localStorage authentication or password reset API is introduced.

Passwords use Argon2id (19 MiB, two iterations, parallelism one), independent
salts, 15–128 characters, without password trimming or arbitrary composition
rules. Usernames are lowercased ASCII identifiers. Unknown accounts undergo a
dummy verification. Invalid credentials, disabled users, missing memberships
and suspended operators produce generic authentication failures. A random dummy
verifier is initialized lazily; first-use latency is not a timing-proof guarantee.
Parameter benchmarking and load testing remain necessary before broader access.

## Abuse controls and invalidation

PostgreSQL atomic fixed-window counters: 30 login requests per client IP and
5 valid-shaped attempts per normalized username per 15 minutes; CSRF issuance
is limited to 60 per IP per 15 minutes. Limits persist across process restarts.
Blocked IPs cannot allocate additional account buckets. Account throttling can
be abused to temporarily deny a known user's login; there is no permanent lockout.
No CAPTCHA/email service is added. At most two Argon2 login verifications execute
per app router, with no password work queue. Rate-limit failures return 429 and
conservative Retry-After. Database failure refuses authentication with sanitized
503 errors, never a fallback in-memory session or limiter.

Every identity lookup rechecks user status, membership identity, operator status,
auth_version and expiry. Removal deletes sessions via foreign keys. Membership
updates, password/status changes and operator suspension invalidate sessions via
triggers. Recreating a membership must use a fresh UUID. Existing in-flight
requests cannot be retroactively canceled; this foundation exposes no payment
reads or writes. Password recovery also explicitly deletes all user's sessions.

## Administrator creation and recovery design — not an executable workflow

No public registration, default admin password, seeded user or admin HTTP role.
Administrative access is separate from dashboard viewer access. Before any real
account is created, approve an authenticated infrastructure-admin workflow:

1. Independently verify the intended environment and use a dedicated migration/
   administration identity through verified database transport.
2. Receive the initial password through hidden local input, not CLI arguments,
   environment variables, SQL literals, command history or logs. Use the shared
   hashDashboardPassword function; never use an online hashing site.
3. In one parameterized transaction, create the user and a viewer membership
   for the independently verified active operator. No operator key is needed.
4. Deliver the initial password over an approved separate confidential channel;
   require administrator-mediated replacement if disclosure is suspected. A
   self-service password-change UI is not part of this release. Prefer having
   the user supply a password privately in the approved workflow.

Recovery must verify the person's identity out of band using the organization's
existing administrative procedure. Do not treat a username, email assertion, or
an existing operator API key as recovery proof. In one transaction replace the
hash, increment auth_version, delete all user sessions, and write a sanitized
audit event with actor/user IDs and outcome only. Triggers also invalidate sessions
on password/status changes. Never print plaintext or hashes. Do not delete/recreate
an operator, modify its API keys, or disable CSRF/session checks for recovery.
No break-glass web account exists. Until a separately approved, tested private
admin workflow and audit process exist, real account creation/recovery remains
blocked. Tests create synthetic users only in verified disposable databases.

## Deployment and remaining limitations

No Render access or changes are authorized by this package. Dashboard stays off.
Runtime database TLS and privilege assurance remain unresolved (see
read-only-history.md); startup still uses a migration-capable runtime identity.
Before deployment, separate schema-owner/migration permissions from runtime
SELECT on users/memberships/operators, required session DML and limiter DML.
Treat password verifiers as sensitive. Review trigger execution permissions when
splitting roles; do not grant runtime password/account administration.
Schema-owner authority is not dashboard administrator authority.

An approved bounded maintenance job must remove expired sessions and limiter
buckets (retaining only policy-approved audit metadata); no background service or
maintenance endpoint is added here. Fixed-window limits and IP limits are not
DDoS protection. MFA, durable admin audit infrastructure, breached-password checks,
load testing and operational alerting remain later hardening work. Secure cookies
require a real HTTPS origin; do not bypass local browser protections.

Validation: disposable PostgreSQL integration tests, Argon2 unit tests, existing
payment regressions, native Windows Argon2/DPAPI/parser CI. No staging tests.
