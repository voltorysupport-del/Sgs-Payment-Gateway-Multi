# Read-only operator payment history

Migration 003 adds a constrained `permission` column to existing API keys.
Existing keys default to `read_write`, preserving payment creation, simulator
completion and idempotency. `read_only` keys can use GET/HEAD payment routes but
receive 403 on all other methods before payment handlers execute. Revocation
and operator suspension remain effective. Scopes are server-side database
metadata, never accepted from request headers or bodies.

`GET /payments` returns `{ payments, pagination: { limit, offset, hasMore } }`.
Defaults: limit 25, offset 0. Limits: 1–100; offset: 0–10000. Optional filters:
status (pending/succeeded/failed/cancelled), currency (three uppercase letters).
Unknown/repeated/invalid query parameters return 400. Results are always scoped
to the authenticated operator, newest created_at then UUID first. Offset pages
are bounded but not snapshots: concurrent inserts may shift pages. This is a
small staging history API, not a bulk export interface. Detail reads retain the
same operator-scoped 404 behavior. No key hashes are returned.

No existing staging key is changed. No new provisioning workflow or frontend
is introduced. Do not put operator keys into browser code or browser storage.
A future dashboard should use server-side credential handling and authenticated
user sessions. Read-only scopes prevent payment mutations, not disclosure of
that operator's payment history.

## Runtime PostgreSQL TLS and privilege policy review

The runtime pool currently delegates TLS to DATABASE_URL and node-postgres.
It does not independently require verified TLS. Administrative CLI TLS settings
do not configure the web pool. This review did not inspect Render secrets,
connect to Render, or prove the deployed runtime's TLS or privileges.

For remote external connections, require certificate and hostname verification
against approved CA roots (verify-full); never use no-verify or disable Node TLS
verification. Render internal endpoints have different certificate constraints
(see staging-provisioning.md). Do not silently apply the external CLI policy to
an internal runtime URL: establish an approved private-network/TLS policy first.
No runtime transport setting is changed by this milestone to avoid silently
breaking or downgrading the deployed connection. Runtime TLS assurance remains
an explicit deployment blocker for broader access/production.

The current server applies migrations before listening using its runtime login.
Migration 003 therefore needs table-owner/ALTER capability during migration.
For a least-privilege production deployment, separate a migration owner from the
runtime login. The desired runtime grants are SELECT on operators/API keys and
SELECT, INSERT, UPDATE on payments; no DELETE, schema CREATE, ALTER or operator
key administration. A dedicated provisioning login should hold its separate
operator/key privileges. Application read-only scope is not a PostgreSQL role:
the shared runtime pool still supports legacy write-enabled credentials.
This separation requires a separately approved migration/deployment change;
do not revoke privileges from the current startup login without changing startup
migration execution first. No grants or credentials are changed here.

Verify effective grants, ownership, search_path and TLS in an approved read-only
infrastructure review before production. Keep LIVE_MODE_ENABLED=false and only
the simulator provider enabled. Tests use disposable local PostgreSQL only.
