# Phase 4A — Trusted simulator terminal attribution

This prerequisite does **not** enable submerchant payment reads, terminal-scoped
BFF access, account activation, or any new human payment-write permission. All
feature gates remain default-off; live mode remains disabled and only simulator
payments are supported.

## Creation and authorization

`POST /payments` accepts optional `terminalId` (UUID, normalized to lowercase),
with the existing `amountMinor`, `currency` and `Idempotency-Key`. An existing,
active operator's unrevoked **read_write machine credential** is still required.
The operator comes exclusively from Bearer authentication. A terminal ID requests
an association; it grants no authority. Unknown fields including `operatorId`
are rejected. Read-only credentials and dashboard sessions cannot create payments.

A new attributed payment requires an existing, active terminal belonging to the
same authenticated operator. Missing, suspended and foreign terminals produce the
same sanitized 400 `invalid_terminal`. There is no provider parameter: the insert
always writes `simulator`, and the existing provider CHECK remains intact.

The response DTO remains unchanged, including existing list/detail/BFF schemas.
Canonical attribution is persisted in PostgreSQL; this increment exposes no new
terminal filter, payment count or terminal-aware read API.

## Idempotency, immutability and lifecycle

Request identity is `(operator, idempotency key, amount, currency, terminal-or-NULL)`.
Changing, adding or removing the terminal on an existing key returns 409. A
transaction-scoped advisory lock serializes same-operator/key helper calls;
existing unique constraints remain the final database duplicate defense. Different
keys proceed independently (a hash collision may conservatively serialize them).

Exact retries return the original record, including after terminal suspension.
They do not represent new creation or reactivation. New keys against suspended
terminals fail. A terminal's current state never rewrites payment history.

The INSERT trigger checks the same-tenant active terminal **FOR SHARE** through
COMMIT; KEY SHARE would not block status changes. A concurrent suspension wins
first => creation waits and refuses; creation wins first => its payment commits
before suspension completes. No application retry is performed after errors or
ambiguous COMMIT acknowledgements. A caller can reconcile using the same request
identity and existing idempotency semantics. There is no automatic retry loop.

A database UPDATE trigger permanently prohibits changing a payment's operator or
terminal, including attributing historical NULL records. The composite FK uses
RESTRICT on deletion/ownership changes of referenced terminals. Suspension is
allowed, does not delete attribution, and prevents new attributed creation. The
current terminal model has only active/suspended, no separate revocation state:
use suspension to disable eligibility; no revocation-management endpoint is added.
Deleting an unreferenced terminal makes it unavailable. Moving a referenced
terminal to another operator is refused by the FK.

## Migration 009 and operational review

`009_payment_terminal_attribution.sql` adds nullable `payments.terminal_id` with
**no default, UPDATE, inference or backfill**, a composite FK referencing existing
`merchant_terminals(id,operator_id)`, the attribution guard, and a partial index on
`(operator_id,terminal_id,created_at DESC,id DESC)` for future scoped reads. All
historical rows retain NULL and remain excluded from any future terminal scope.

The existing migration runner serializes bootstrap with its dedicated advisory
lock and applies this entire file plus ledger entry transactionally. ALTER TABLE
requires strong locks; ordinary index construction scans/locks the payment table.
Use a maintenance window for a large deployment. Migration-local lock timeout is
5 seconds and statement timeout 60 seconds: contention or an oversized scan fails
and rolls back rather than silently skipping a constraint. An operator can assess
and approve a separate rollout plan for larger datasets; no external migration
was executed for this PR. Tests verify populated 008 upgrade and DDL rollback.

No database role or GRANT is created/expanded. Migration credentials need DDL
rights. Runtime payment writers need INSERT/SELECT on the new payment column and
SELECT on terminal identity/status. PostgreSQL FOR SHARE also requires UPDATE on
at least one terminal column; a production least-privilege rollout must explicitly
account for that requirement (or approve a separately reviewed narrower database
function). No SECURITY DEFINER is introduced: the guard is SECURITY INVOKER with
qualified tables and a pinned search path. Existing broad runtime/migration-role
separation limitations are not solved by this prerequisite; do not grant terminal
management privileges indiscriminately to a read-only dashboard role.

There is no supported automatic down migration. A transactional migration failure
preserves schema 008 and existing data. After successful migration, preserve the
column, constraints and attribution history. An older binary cannot implement the
new terminal-aware idempotency contract: stop payment writes before any binary
rollback and obtain a reviewed compatibility plan; never drop the column to make
an old binary run.

## Validation

Use disposable PostgreSQL only: `npm run test:isolated -- --check`. Include browser
regressions with the existing `VAULTX_BROWSER_TESTS=true` configuration and a local
Chromium installation. New tests cover generic terminal refusal, canonical tenant
binding, immutable history, NULL preservation, duplicate/mismatched idempotency,
and explicit PostgreSQL lock barriers in both suspension/creation orders. Existing
submerchant denial, signed BFF, invitation, WebAuthn and simulator tests remain.

Terminal assignments, reassignment/revocation policy, scoped status semantics and
signed terminal-aware authorization at the final payment-query boundary remain
Phase 4 follow-up work. No access is widened by this migration or creation option.
