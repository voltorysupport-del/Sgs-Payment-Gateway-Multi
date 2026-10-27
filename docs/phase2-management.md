# Phase 2: merchant lifecycle foundation

This development-only increment builds on merged management code at
`6348b6716fa3153d01902b8eaf8e891b9c8c9aad`. It does not complete or enable a
production PSP. The operator is still the merchant tenant; a submerchant user is
a restricted person inside that tenant, not a financial child organization.

## Implemented gateway behavior

- Existing owner principals, separate owner origin/cookie, MFA assurance and
  fresh-MFA write checks remain authoritative. No viewer or machine key can
  substitute for owner authentication.
- An authorized owner can create a merchant without creating a machine key,
  person, password or session. Creation and its public revision are audited in
  the same transaction. Owner screens call these real contracts.
- Administrator invitation **intent** requires the new exact
  `platform.clients.bootstrap_admin` grant, not `platform.clients.manage`.
  Intent has a 24-hour expiry, tenant, intended username and explicit ceiling.
  Responses contain a public invitation ID, `status: pending` and
  `activationEnabled: false`. There is no usable invitation secret or activation
  endpoint. A pending record never authenticates anybody.
- Merchant-management reads and reducers reuse hashed dashboard sessions and
  the canonical client permission catalog, entitlements and grant tables.
  Management profiles record provenance; profile/role labels grant no authority.
  Membership identity, existing viewer behavior and machine API keys are retained.
- Merchant administrators can inspect their own members, terminal inventory and
  audit, record bounded submerchant invitation intent, and disable/withdraw read
  grants from only their own sponsored restricted members. They cannot modify
  themselves, other administrators, other sponsors' users or other tenants.
- Merchant screens use these APIs with the existing client authentication
  controller, same-origin requests, CSRF and conservative ambiguous-write handling.
  They do not fabricate successful activation or terminal assignment controls.

## Routes

| Realm  | Method and route                                             | Authority                                                                                                |
| ------ | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| Owner  | `POST /owner-api/clients`                                    | `platform.clients.manage`, fresh MFA, CSRF                                                               |
| Owner  | `POST /owner-api/clients/:id/administrator-invitations`      | `platform.clients.bootstrap_admin`, fresh MFA, CSRF                                                      |
| Client | `GET /merchant-api/me`                                       | Current active merchant-administrator subject only                                                       |
| Client | `GET /merchant-api/members`                                  | `client.users.read`                                                                                      |
| Client | `GET /merchant-api/terminals`                                | `client.terminals.read`                                                                                  |
| Client | `GET /merchant-api/audit`                                    | `client.audit.read`                                                                                      |
| Client | `POST /merchant-api/invitations`                             | `client.users.manage_subaccounts` and `client.permissions.delegate`, requested rights within own ceiling |
| Client | `POST /merchant-api/members/:id/disable`                     | `client.users.manage_subaccounts`, own sponsored restricted target, expected version, CSRF               |
| Client | `POST /merchant-api/members/:id/grants/:permission/withdraw` | `client.permissions.delegate`, same target restrictions, expected version, CSRF                          |

List pages have `limit` 1–50, `offset` 0–10000 and deterministic ordering. Only
GET/POST are recognized by the merchant router; HEAD and other methods deny.
Browser fields never select the authoritative merchant, principal or role.

## Migration 007 and invariants

`007_merchant_lifecycle.sql` is additive and seeds no accounts or credentials.
It expands the exact client catalog, adds immutable merchant profiles and pending
invitation history, terminal inventory, constrained issuer/source references and
append-only merchant audit. New administrative codes are not backfilled into
existing viewers or old tenant ceilings. New merchants get explicit ceilings,
not human grants. Machine key verification/scopes and payment idempotency are
unchanged.

New root grant provenance references an actual owner and a merchant-admin
profile. New delegated grants reference the sponsor's exact same-tenant grant;
only payment/status reads are delegable in this foundation. Sponsor eligibility,
current authority, enabled ceilings and source are rechecked on evaluation.
Runtime INSERT privileges on authority tables are not granted. The only profile
and grant issuers currently exercised are separately guarded disposable fixtures;
this is not a production bootstrap or activation ceremony.

Issuing nonlegacy grants advances membership authorization versions and deletes
prior sessions. Reductions permanently revoke affected dependent grants and
invalidate their sessions. Re-enabling a ceiling, sponsor or merchant cannot
restore withdrawn grants. Old legacy source remains limited to its original two
read codes and its trusted migration/fixture boundary; there is no HTTP legacy
grant issuer.

Merchant commands use one bounded READ COMMITTED transaction. The immutable
tenant comes from the session probe and is rechecked after locks. Acquisition is
exclusive advisory tenant pre-gate, policy row, UUID-ordered users, memberships,
operator, ordered grants and sessions. Wall-clock expiry is checked after waits.
No lock spans hashing, external HTTP or browser interaction. Existing owner
commands take their owner-realm gate/session before the tenant gate; merchant
commands never acquire owner locks, so the reverse edge is absent. CSRF/logout
and cleanup do not acquire policy gates after session locks.

Sensitive writes and mandatory management-read audit commit atomically; audit or
session-refresh failure rolls back the command. Audit records contain bounded
public identifiers/revisions/action summaries, not credentials, invitation
secrets, passwords or full payloads. Uncertain outcomes are errors, never an
automatic mutation retry. Expected-version checks serialize stale mutations.

## Deliberately closed boundaries

The current payment BFF and signed loopback contract are **operator-wide**, with
one configured read-only key. They cannot yet enforce terminal restrictions.
Consequently profiled submerchant subjects are denied payment access through
that BFF even if they have a payment-read grant. Merchant-administrator profiles
use canonical permission evaluation; existing unprofiled viewers keep their
original read behavior. The standalone preview's terminal-aware behavior is not
evidence that the gateway supports terminal-scoped payment queries.

`terminal_ids` in pending invitations express intent only. Persisted per-user
terminal assignments, payment-to-terminal attribution, a signed terminal-aware
handoff and associated races must be reviewed before gateway submerchant payment
access or human simulator writes are enabled. No human payment-write permission
is added by this migration. Existing Bearer simulator behavior is preserved.

Invitations are deliberately one-shot intent: their immutable unrevoked record
reserves `(operator, username)`, including after expiry. There is no automatic
replacement, cancellation, resend or restoration. A duplicate does not create
another account; unavailable/conflict outcomes require inspection, not blind
retry. A reviewed lifecycle protocol is required before enabling delivery.

## Gates and deployment prerequisites

Keep `LIVE_MODE_ENABLED=false`, `ALLOWED_PROVIDERS=simulator`,
`DASHBOARD_ENABLED=false`, `DASHBOARD_BFF_ENABLED=false`, `OWNER_ENABLED=false`
and new `MERCHANT_MANAGEMENT_ENABLED=false`. The latter requires existing client
authentication configuration, refuses production mode and mounts `/merchant`
and `/merchant-api` only for explicitly configured development/tests. No gates
are enabled by this change.

Separate reviewed decisions still block real enrollment/activation: owner
custody and MFA enrollment, recovery quorum/evidence, administrator bootstrap
approval provenance, invitation secret custody/delivery/acceptance and safe
credential reset. No default account, recovery bypass or account issuer is
provided. Revoking an issuing owner's later platform rights does not implicitly
erase independently established merchant-admin provenance; any desired cascade
requires an explicit lifecycle policy.

Production also still requires separate migration and least-privilege runtime
credentials, verification-only runtime startup, verified PostgreSQL TLS identity,
actual restricted-role deployment tests and independent audit retention. The
existing startup migration behavior is not converted into a production privilege
model by this increment. Never run these migrations against external databases
as a test or use table-owner tests as proof of deployed least privilege.

## Validation and next increments

Tests use the guarded disposable PostgreSQL 17 runner: `npm run test:isolated`.
For actual local HTTPS browser regressions use `VAULTX_BROWSER_TESTS=true` with
installed Chromium/Playwright. `npm run typecheck`, `npm run lint`,
`npm run format:check`, `npm run build`, both dependency audits and the secret
scan remain required. Native Windows CI covers DPAPI/parser/auth client and
frontend regressions; Linux CI runs the full disposable database suite. Windows
database integration is not claimed unless an actual Docker-capable runner runs
it.

The separate `local-preview-phase2` package is an independent, memory-only demo:
owner creates a merchant, merchant invites/assigns bounded terminal rights,
submerchant explores synthetic transactions and simulator outcomes, and
revocation removes access. It implements no production auth bypass and imports
no gateway/database/credential code. New merchants start with no invented
financial history. Unimplemented withdrawals/refunds/settlement/cascading are
labeled unavailable rather than returned as fabricated gateway reports.

Review the gateway foundation and independent preview separately. Neither is
merged or deployed by this task. After review, the next gateway milestone should
settle activation/provenance policy and implement a constrained single-use
invitation acceptance flow with synthetic tests; terminal-scoped payment reads
then require their own authorization-handoff review. Global financial reports,
owner enrollment/recovery and real financial/provider integrations remain later
work rather than implied by the preview.
