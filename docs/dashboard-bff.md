# Read-only dashboard BFF (default off)

This milestone adds server-side reads only. There is no frontend, provisioning,
new database migration, real credential, or Render change. Existing Bearer API,
idempotency and simulator-only restrictions are preserved.

## Routes and boundaries

- GET /dashboard-api/payments and /dashboard-api/payments/ return history.
- GET /dashboard-api/payments/:paymentId returns one UUID-identified payment.
- GET /dashboard-api/status returns only status, gateway availability, database
  reachability, provider=simulator and realPaymentsEnabled=false.

These routes require the existing dashboard session cookie. Every request
rechecks user status, membership identity/version, operator status and session
expiry through the shared atomic session validator. The deployment's configured
operator must match the session membership; there is no browser-selected tenant.
The server key is authenticated against PostgreSQL on every request and must
belong to that operator with exactly read_only permission. Revoked, unknown,
mismatched and write-enabled keys fail closed. No credential is cached as valid.

The internal request carries a process-signed restriction binding its exact GET
path, Bearer-key hash, expected operator, read_only permission and ten-second
expiry. The payment API verifies the proof and includes operator/permission
constraints in the same SQL authentication lookup that supplies the operator ID
used to select payments. Moving a key or changing its scope between the BFF check
and API lookup therefore denies the read. A valid proof never replaces a valid,
active Bearer key. Browser-supplied reserved restriction headers are rejected;
no incoming headers are reused for signing. Partial, altered, expired or
method/path/key-mismatched proofs fail closed. Signed health reads enforce the
same credential restrictions; ordinary public /health remains public.

No ownership-immutability migration is necessary to close this race: payment SQL
uses the operator captured by the constrained authentication lookup, even if
privileged maintenance changes ownership afterward. Rotation/schema behavior
is unchanged. The process-local signing secret is generated in memory, never
configured, persisted or exposed; it is not an operator credential. Multiple
Node workers with independent secrets would fail closed and are unsupported
without a separately reviewed shared capability mechanism.
As with existing authentication, in-flight requests are not retroactively
canceled; revocation takes effect at subsequent authentication boundaries.

Only explicitly defined GET operations exist. HEAD and other methods return
405; undefined reads return 404. Browser Authorization, Cookie, CSRF, Host and
other headers are never forwarded upstream. Dashboard cookies never authorize
payment creation or simulation on the original /payments API. No CORS or generic
proxy is added. These GET operations need no CSRF mutation token; existing
login/logout CSRF controls remain mandatory and unchanged.

History uses the same strict query validator as the payment API: limit 1–100
(default 25), offset 0–10000 (default 0), optional status and uppercase currency.
Unknown/repeated parameters, operatorId, URL overrides and malformed UUIDs are
rejected. Detail/status accept no query parameters. Offset pagination retains its
existing non-snapshot behavior during concurrent inserts.

## Fixed internal destination

The BFF calls the real existing payment router using Node's native HTTP client,
not duplicated payment SQL or an external Render URL. Destination is always
127.0.0.1 and the same validated PORT used by the application listener. The server
explicitly binds 0.0.0.0 so IPv4 loopback is available. Paths are built from a
closed operation union: /payments with known query fields, /payments/:uuid, or
/health. There is no upstream URL environment variable, dynamic host, generic
method or browser-header forwarding. A private Agent does not inherit global
proxy configuration. Redirects are never followed and requests never retry.

This keeps HTTP within the same trusted container and avoids Render DNS, public
TLS and cold-start loops. It does not weaken browser HTTPS or PostgreSQL TLS.
No database connection/transaction is held while waiting for the internal HTTP
response. This is tested with a one-connection pool. This avoids a nested-request pool deadlock. The deployment must retain
this single-service topology; a split service or untrusted local sidecar needs a
new transport review. Failure to reach loopback fails closed, with no fallback.

Upstream requests have a 2-second inactivity timeout and 5-second total deadline.
Responses are limited to 256 KiB of actual bytes and must be JSON. Network errors,
redirects, bad bodies and unexpected statuses become fixed sanitized errors;
upstream messages/headers/cookies are never forwarded. Detail 404 is generic;
upstream 401/403 makes the BFF unavailable. Success payloads are projected through
schemas that permit only documented payment fields, enforce provider=simulator,
validate pagination and check the requested detail ID. Unknown fields are stripped.
All mounted BFF responses, including errors, use Cache-Control: no-store.

Status's database=reachable means the session and key queries succeeded during
that request; it is not a backup, migration, permissions, TLS or capacity audit.
The upstream /health response must satisfy the simulator-only contract. Status
exposes no hostname, credentials, database URL, key identifier or raw exceptions.

## Configuration and later approval

Both DASHBOARD_ENABLED and DASHBOARD_BFF_ENABLED default to false. BFF enablement
requires the authentication gate plus:

- DASHBOARD_PUBLIC_ORIGIN: the existing exact approved HTTPS origin.
- DASHBOARD_OPERATOR_ID: the independently verified operator UUID (nonsecret).
- DASHBOARD_READ_ONLY_API_KEY: a dedicated server-side secret for that operator.

Missing/invalid settings refuse configuration. Runtime credential mismatch,
revocation or incorrect permission refuses reads even if configuration passed.
Keep LIVE_MODE_ENABLED=false and ALLOWED_PROVIDERS=simulator. Do not put the key
in VITE_* variables, browser storage, URLs, source, logs or artifacts. Named secret
fields are redacted defensively; the BFF never logs config or upstream bodies.

No existing staging key is changed or reused automatically. The existing staging
payment-test credential is not a substitute for a dedicated read-only key.
Issuing that key and preparing a real dashboard user require separate approval
and a reviewed administrator workflow; this PR provides no new provisioning tool.

Before real enablement: approve the credential/account workflow, verify actual
runtime database TLS and privileges and trusted ingress topology, and complete
an HTTPS browser cookie/CSRF check. Supertest manually supplies cookies; passing
these tests does not establish browser enforcement. See dashboard-auth.md for
that evidence boundary and existing session/recovery/maintenance limitations.
No deployment or staging payment/read is authorized by this change.

## Validation

Disposable PostgreSQL integration tests use synthetic helper-issued keys,
synthetic users and hashed sessions plus a real IPv4-loopback gateway listener.
They cover history/trailing slash, detail, status, two operators, disabled users,
suspension/removal/expiry, revoked/mismatched/write-enabled credentials, invalid
inputs, forbidden methods, unchanged Bearer behavior and output privacy.
Transport unit tests cover the fixed destination/headers, both timeout paths,
redirects, response-size bounds, invalid JSON/content types, aborts and errors.
No real credentials or database settings are used by tests or CI.

## Availability and cancellation boundaries

The BFF admits at most four active requests per router with no waiting queue.
A shared per-pool read gate admits at most four DB leases, including queued
acquisitions. Acquisition waits are limited to 750 ms; timed-out acquisitions
retain their admission slot until settled, and late clients are released without
executing SQL. This prevents accumulating replacement queue entries. Runtime
pool size remains ten; payment-write authentication and transactions retain
existing behavior and are not subject to this read gate.

Key authentication for GET/HEAD, payment list/detail and internal health use
read-only transactions with 1500 ms statement timeout, 500 ms lock timeout and
2500 ms total lease deadline. Total deadline destroys the client on a stalled
network/driver, rather than returning an uncertain client to the pool. Dashboard
session activity is deliberately writable authentication metadata: its existing
5000/2000 ms SQL/lock deadlines remain, with a 6000 ms total lease deadline.
Local settings reset on commit/rollback; uncertain connections are discarded.
Overload and DB failures return sanitized 503 responses. No global migration,
write timeout or persistent DB setting is changed.

Browser disconnect aborts the internal HTTP request; BFF admission is released.
HTTP timeout/disconnect does not issue PostgreSQL CancelRequest. Already-running
SQL may finish until server statement timeout or connection closure; completed
work cannot be reversed. A session-activity COMMIT already sent may persist even
if its acknowledgement is lost. Pure payment-read transactions never change
payment records. No automatic retry occurs. Queued DB acquisitions cannot be
removed individually through pg's public promise API; their retained bounded
slots are released when acquisition resolves/rejects. These controls limit
per-process pressure, not distributed denial of service or all legacy write
pressure on the pool.

A user disabled or reassigned after initial BFF authentication may receive one
already-authorized response for the original operator; tests pin this boundary.
The next request is rejected, and data from the new operator is never substituted.
Operator suspension or key revocation before upstream authentication denies the
in-flight read because that boundary rechecks both. No lock is held across HTTP.

Deterministic test barriers pause between BFF validation and actual upstream
payment authentication for ownership/scope/revocation changes. Additional tests
cover in-flight user/membership/suspension, forged restrictions, real lock and
statement cancellation, total-deadline connection disposal, exhausted pools and
late acquisitions, disconnect recovery, admission overflow, malformed output,
PATCH/OPTIONS/TRACE rejection, sanitized DB errors and secret-free logs. HTTPS
browser, staging TLS/grants and administrative enablement prerequisites remain.
