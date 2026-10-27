# Phase 4B — Terminal-scoped read authorization foundation

This backend-only increment does not enable production submerchant access or add
any dashboard UI. `TERMINAL_SCOPED_READS_ENABLED=false` is the default. Setting it
true is rejected in production and requires the existing dashboard, BFF and
merchant-management gates in development/test. The final API independently checks
these conditions even for a programmatically constructed configuration. Existing
feature gates, simulator-only providers and live-mode restrictions are unchanged.

## Canonical authority and compatibility

Migration 010 creates `merchant_terminal_assignments` and an append-only assignment
audit. No assignment, account, API key, entitlement or permission is seeded or
inferred from old records. Existing users with no canonical assignment stay
ineligible for scoped reads. Historical NULL-attributed payments stay excluded.
Existing merchant administrators and unprofiled legacy viewers retain their
existing operator-wide read contracts; existing machine keys remain independent.

Only the existing verified invitation acceptance transaction creates assignments:

1. Existing enrollment code rechecks live issuer/sponsor authority, tenant status,
   current entitlement ceilings, permanent grants and active same-tenant terminals
   under the exclusive tenant gate. WebAuthn registration and token consumption
   remain mandatory; registration still creates no authenticated session.
2. The immutable acceptance audit binds the consumed invitation to its user. A
   unique partial index prohibits a second accepted-user event for an invitation.
3. Each assignment references the exact invitation, canonical membership and
   same-operator terminal. Its guard verifies consumed-token/accepted-user evidence,
   matching submerchant profile/sponsor, intended username/terminal, live delegated
   grant and enabled ceiling. Assignment creation and all audit/version updates
   commit atomically with acceptance; any failure rolls the whole activation back.

There is no assignment-management HTTP endpoint, policy-mutation CLI, arbitrary
reassignment API or production account provisioning. A different terminal requires
separately authorized immutable intent/lifecycle work; a browser request cannot
grant an assignment. Runtime readers must not have assignment INSERT or policy
UPDATE privileges. Schema owners/superusers remain outside the application threat
boundary, as in the existing architecture.

## Revocation and lifecycle

Assignments have immutable identity/source/time. The only update is one-way
revocation at statement time with an allowlisted cause. No no-op history rewrite,
undelete, reactivation or duplicate membership/terminal assignment is supported.
Every insertion/revocation advances the membership authorization version, deletes
its sessions through existing triggers, and atomically inserts immutable audit
with database actor, cause and the actual membership/policy revisions. Existing
merchant management audit retains the initiating human action for grant/membership
changes. Terminal status has no new administration endpoint: a future endpoint
must add authenticated actor/correlation evidence before being enabled.

Terminal suspension permanently revokes its assignments. Reactivation never
restores them. Payment/status grant revocation, including existing sponsor and
entitlement cascades, also revokes assignments. Either read-grant withdrawal
conservatively ends both terminal-scoped read paths. Disabled membership/user or
suspended operator loses session/grant authorization under the existing protocol.
Referenced terminals cannot be deleted; terminal identity/operator reassignment is
now refused even without historical payments. Historical payment attribution is
never rewritten. Missing, suspended, foreign or unassigned terminals cannot pass
the final query predicates.

## Signed BFF handoff and final SQL boundary

The browser sends only its secure session cookie and validated read query/UUID.
The BFF derives identity and scope from PostgreSQL, never browser headers, role
claims, tenant selectors or terminal IDs. It signs the fixed GET path, API-key
hash, expected operator, required read_only permission, expiry and a bounded
principal context: user, membership, hashed session verifier, authorization
versions and canonical ordered terminal IDs. The verifier is internal sensitive
metadata: never returned, stored in browser state/URLs or logged. The existing
process-local HMAC and fixed loopback destination remain; multi-process loopback
load balancing is unsupported and fails closed.

The payment API still requires ordinary valid Bearer authentication. Restrictions
can only reduce that authority, never grant it. Removing/changing context, path,
key, method or expiry invalidates the MAC. External internal-authorization headers
are rejected by the BFF. Signed contexts are rejected while the gate is off.

For scoped list/detail/status reads, one bounded database transaction:

- Takes the shared tenant pre-gate, policy row, then user/membership/operator locks
  in the existing order; rechecks signed authorization versions and active status.
- Evaluates current canonical grants, sponsor authority and enabled entitlements;
  requires an actual submerchant profile and the endpoint-specific read permission.
- Locks terminal rows in UUID order, then assignment rows in terminal order;
  compares the whole current active scope against the signed scope (no truncation).
- Locks the exact session, then the same-operator read_only unrevoked key. **After
  all lock waits**, checks session versions, idle/absolute expiry and server-side
  current WebAuthn proof. Password-only, revoked-factor and rotated sessions fail.
- Materializes rows with explicit operator AND simulator AND terminal predicates,
  plus an EXISTS check against that membership's live assignment and active
  same-tenant terminal directly inside the payment SQL. NULL is never in scope.
  Filters, deterministic ordering and LIMIT+1/OFFSET apply only after authorization.

A guessed, foreign, NULL-attributed or unassigned payment UUID produces the same 404. No operator-wide count or total is exposed; hasMore reflects only eligible
rows. Offsets are not a snapshot across requests. Scoped status requires the same
live principal/assignment checks and client.status.read; it returns only the
existing generic simulator/availability DTO, no terminal/payment/global counts.
All BFF responses remain sanitized and no-store, with existing timeout/size bounds.

## Lock ordering and revocation linearization

Every assignment/terminal policy mutation must take the **exclusive** tenant
pre-gate before locking policy/identity/resource rows. Defensive triggers verify
ownership but never acquire a late gate from a row trigger. Existing management
and enrollment already use that gate. Tests/maintenance follow the same protocol.
The gate excludes readers while policy reduces; supplemental terminal/assignment
locks are acquired in explicit row classes rather than relying on join row marks.
Logout/CSRF/cleanup do not acquire terminal/assignment locks in reverse order.
Machine-key changes remain fenced by the final SHARE lock through materialization.

A read admitted before revocation may finish its materialization; revocation
waits for that transaction. After revocation commits, a new or delayed handoff
fails versions/session/live scope. Data already materialized can arrive over the
network after revocation acknowledges; neither HTTP timeout nor revocation can
recall bytes already authorized. No database lock is held over loopback HTTP.
The final read has existing four-request pool admission, 750ms acquisition,
500ms lock, 1500ms statement and 3500ms total deadlines. Timeouts roll back/discard
connections; there is no automatic read/write retry or mutation on read failure.

## Migration and runtime prerequisites

010 is additive and transactional with 5s DDL-lock / 60s statement bounds. It
creates constrained assignments, audit, indexes and invoker-rights triggers with
qualified tables and pinned search paths. Existing data/grants are preserved.
A duplicate historical acceptance event causes migration failure rather than
silently choosing a user. Tests verify populated 009 upgrade and atomic rollback.
The standard runner serializes migrations; no external migration was executed.
There is no automatic down migration. Preserve assignment/revocation/audit history
and disable all ingress before any separately reviewed old-binary rollback: old
binaries do not understand this authorization contract.

No production role grants/TLS changes are made. Runtime read queries need table
SELECT and PostgreSQL row-lock privileges (UPDATE on at least one column). For
terminal/assignment row locks, a separately reviewed role policy can use only the
immutable id column rather than granting status/revocation writes; guards refuse
identity changes. Do not grant policy DML or DDL ownership to a dashboard reader.
Existing runtime/migration-role separation and certificate/hostname-verified TLS
remain deployment prerequisites; CLI preflight is not proof of runtime TLS.

## Validation and deferred scope

Use only `npm run test:isolated -- --check` with the existing disposable database
guards; browser regressions additionally use the existing Chromium configuration.
Security tests use real synthetic WebAuthn signatures and invitation consumption,
not a browser MFA flag. They cover tenant/terminal/NULL isolation, signed tampering,
pagination, active/expired sessions, factor/key/sponsor/grant/entitlement changes,
one-way revocation, audit failure rollback and explicit lock barriers both within
the SQL transaction and across BFF-to-upstream admission. Existing simulator,
idempotency, admin/viewer, browser and Windows regressions remain mandatory.

Production enablement, a submerchant UI, historical assignment linking, terminal
administration/reassignment, real enrollment/delivery, payment writes and live
providers require separate review and approval. None are enabled by this PR.
