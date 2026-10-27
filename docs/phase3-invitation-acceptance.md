# Phase 3: synthetic invitation acceptance and passkey authentication

This increment is **not permission to enable enrollment or provision accounts**.
Keep `PHASE3_ENROLLMENT_ENABLED=false`, `DASHBOARD_ENABLED=false`,
`DASHBOARD_BFF_ENABLED=false`, `OWNER_ENABLED=false`,
`MERCHANT_MANAGEMENT_ENABLED=false`, `LIVE_MODE_ENABLED=false` and
`ALLOWED_PROVIDERS=simulator`. No migration or test targets an external database.

## Scope and approved policy

The existing merchant invitation is immutable authority **intent**, not an account
or credential. Migration 008 adds token lifecycle, short-lived ceremonies,
passkeys and append-only enrollment audit alongside it. It never rewrites 007
intent, seeds accounts/grants, issues API keys, or restores revoked authority.
Existing one-user/one-membership and viewer-role constraints remain unchanged.
Legacy viewers retain password-only read behavior. Every merchant-profile subject
requires verified WebAuthn assurance for dashboard payment/status permissions;
merchant administration, including identity/directory/audit, requires it too.
Subject-only `/dashboard-api/auth/me`, CSRF and logout remain available without
privileged assurance. The existing password login response means authenticated
identity, **not** authorization to use management or BFF operations.

Enrollment token issuance is deliberately a **synthetic test-only internal helper**
(`issueSyntheticInvitationToken`). It independently verifies the disposable
PostgreSQL database name, authenticated login and random test-cluster marker,
not just `NODE_ENV`. There is no issuance/delivery HTTP endpoint, CLI, email,
external delivery adapter or production policy-mutation tool. It returns a raw
random token only to the trusted in-memory test caller. Never log it or put it in
a URL, browser storage, screenshot, artifact, message or audit row.

## Flow and API contracts

All new routes are POST, same-origin, CSRF-protected, `Cache-Control: no-store`,
with a 16 KiB JSON cap, early Origin/query rejection, existing normalized IP
limiter (30 attempts per 15 minutes) and two concurrent verification operations
per router. RP ID is exactly the configured HTTPS dashboard origin's hostname,
never request Host, forwarded Host, browser input or a parent domain.

| Route below `/dashboard-api/auth/passkeys` | Session                                       | Body and result                                                                   |
| ------------------------------------------ | --------------------------------------------- | --------------------------------------------------------------------------------- |
| `/enrollment/options`                      | Existing anonymous pre-auth cookie + CSRF     | `{invitationToken,password}`; registration options, opaque random user handle     |
| `/enrollment/verify`                       | Same anonymous cookie + CSRF                  | `{credential}`; `{enrolled:true,privilegedAccess:false}`; clears pre-auth cookie  |
| `/authentication/options`                  | Existing password-authenticated cookie + CSRF | `{}`; owned credential allow-list and fresh authentication options                |
| `/authentication/verify`                   | Same password-authenticated cookie + CSRF     | `{credential}`; rotates cookie and CSRF, returns `{authenticated:true,csrfToken}` |

The gate requires development/test merchant dashboard configuration and refuses
production. There is no activation UI in this increment: the HTTPS browser test
exercises the real browser API against disposable localhost infrastructure.
The existing dashboard does not yet present a passkey prompt. A later reviewed UI
must perform this second authentication step; it must not interpret password login
or registration as privileged authorization.

1. An already-authorized immutable invitation has one 256-bit random token, stored
   only as SHA-256. Its lifetime is at most 15 minutes and no later than intent
   expiry. A unique invitation FK prevents replacement or automatic resend.
2. Enrollment options bind a five-minute challenge hash, pending Argon2id password
   verifier and opaque future user ID to that token and anonymous session. No user,
   membership, grant or active session exists yet. One ceremony per session bounds
   allocations; expired ceremonies are removed in existing bounded maintenance.
3. Registration uses `@simplewebauthn/server` 13.3.3, ES256, required resident key
   and user verification, exact origin/RP ID and challenge. Cross-origin/top-origin
   ceremonies are rejected. Attestation is `none`: this is not hardware provenance
   or enterprise device attestation. UV is enforced on verification, not merely
   requested in options; actual resident-key browser behavior is tested, not a
   server claim that an authenticator honored a preference.
4. One transaction revalidates live authority, creates the existing user,
   membership/profile and canonical grants, installs the verified public key,
   consumes challenge/token, removes pre-auth session and writes audit. Failure
   rolls everything back. Registration never issues an authenticated session.
5. Existing Argon2id login creates only a password session. Fresh WebAuthn
   authentication requires UV, exact challenge/origin/RP, owned public key,
   matching user handle when supplied, and signature/counter verification.
   Challenge consumption, counter CAS, session rotation and audit commit together.
   The original password session's absolute eight-hour deadline is preserved.
6. Every privileged session admission rechecks active user/member/tenant,
   authorization versions and an unrevoked owned passkey bound to that session.
   Merchant writes additionally require WebAuthn verification within five minutes.
   A factor insertion/revocation advances the existing user's `auth_version` and
   invalidates all sessions and their pending ceremonies. Membership/grant/tenant
   invalidation continues through existing triggers. No caller-supplied MFA flag
   or permission assertion is trusted.

## Authorization, locks and replay

Authority snapshots are additional fences, never substitutes for live checks.
Acceptance rechecks current owner bootstrap permission/enrollment/status or the
sponsor's active administrator profile and current effective manage/delegate/read
rights. Tenant status, enabled ceilings, active same-tenant terminals and intent
expiry are checked again. Policy/issuer versions and exact sponsor grant IDs must
still match token issuance, so withdrawing and restoring a ceiling or replacing a
revoked grant cannot revive an old token.

Lock order: for owner invitations, shared owner policy gate/policy/principal/grant
rows first; then exclusive tenant advisory gate, policy row, ordered users,
memberships, operator, ordered grants and sessions; token, pre-auth session and
ceremony last. Team invitations use the tenant sequence directly. This matches
existing management reducers. Authentication takes the exclusive tenant gate
before identity locks, then session, ceremony and passkey counter. No locks span
password hashing, signature verification, delivery or browser interaction.
Transactions have existing admission/acquisition, statement, lock and total
limits; errors are generic. A timed-out/disconnected commit may be ambiguous:
**do not automatically retry, replace tokens or create another account**.

A consumed/revoked token cannot be rewritten, unrevoked, reconsumed or replaced.
An expired token is unusable. Failed verification leaves no partially active
account. An unused valid challenge can be resubmitted after an invalid response
within its lifetime and limits; a committed acceptance/authentication cannot be
replayed. A duplicate enrollment can never create a second user through that
intent. Revocation is an internal transaction primitive, not a public authorized
mutation surface. No invitation reset/resend or factor reset/recovery exists.

Terminal IDs remain immutable intent linked to the activated user through audit.
Submerchant payments stay **entirely denied** by the existing operator-wide BFF,
even after MFA. Explicitly terminal-restricted administrator intent is refused,
rather than silently acquiring operator-wide reads. There is no new terminal
assignment, terminal-aware payment query, human simulator write or payment change.

Audit stores only public invitation/user/operator IDs, fixed action codes and
server timestamps (`token.issued`, `token.revoked`, `invitation.accepted`,
`passkey.authenticated`). No token, challenge, credential response, password or
key is included. Rejections use generic errors, not tenant-specific diagnostics.
Audit and lifecycle history are immutable under ordinary SQL mutations; schema
owners can still disable triggers. External audit durability and least-privilege
runtime deployment remain prerequisites, not guarantees supplied by a trigger.

## Migration and validation

Migration 008 is additive and transactional. Populated-007 upgrade/rollback tests
verify existing users, memberships, machine key hashes/scopes, grants and intent
remain byte-for-byte equivalent. It deliberately does not grandfather privileged
password sessions into MFA assurance. Existing merchant subjects without an
enrolled factor fail closed; no recovery/bootstrap bypass is provided. Rolling
application code back after accepting accounts is unsafe because older code does
not enforce MFA: disable gates first and require a separately reviewed rollback.
No down migration or external migration command is included.

Local validation:

```text
npm ci
npm run test:isolated -- --check
npm run build
npm audit --omit=dev
npm audit
npm run secrets:scan
```

The isolated runner creates and verifies disposable PostgreSQL 17, never uses
`DATABASE_URL`, and now checks all eight migrations and zero leftover enrollment
records. Linux HTTPS browser tests additionally require Chromium/OpenSSL and
`VAULTX_BROWSER_TESTS=true` (the existing CI config supplies them).
Cryptographic tests use real synthetic ES256 signatures/CBOR and the actual
verifier. The browser test uses a Chromium CTAP2 virtual authenticator with UV,
real HTTPS cookies/CSRF, actual enrollment/password login/assertion/session rotation
and replay denial. A self-signed certificate exception is confined to that
localhost test; application TLS verification is unchanged. Existing management
UI tests use explicitly guarded schema-owner assurance fixtures; those are not
claimed as proof of cryptographic verification.

## Remaining production blockers

- Independently review these authorization/lock/session changes before merge.
- Approve real invitation custody/delivery, issuance authorization/step-up,
  operational expiry handling and administrative account custody before any real
  enrollment. No existing real accounts or credentials are changed here.
- No self-service recovery, factor reset, replacement or bypass. Lost passkeys
  cannot be recovered in this increment; any such ceremony needs separate approval.
- Owner authentication/bootstrap/recovery remains its separately disabled
  foundation. This increment does not create or activate owners.
- Add a reviewed passkey enrollment/login UI and test real supported Windows
  Hello/security keys, OS prompts, device loss and browser cancellation. A virtual
  authenticator does not prove physical device or human-presence behavior.
- Verify production PostgreSQL TLS, least-privilege runtime versus migration
  credentials, audit retention, proxy configuration and session/limiter capacity.
- Terminal-scoped payment data and external providers remain out of scope.

## Final PR #29 security review

Reviewed the complete published diff at
`c52e69222fa3a61bc96fc02417164c1fc833db7c`, including the existing auth,
management, BFF, machine payment routes, migration guards and library verifier.
The original Linux and native Windows workflow runs both completed successfully.
The focused correction does not enable gates or change payment behavior.

Confirmed findings and corrections:

| Severity | Affected code                                                                                | Reproduction and smallest correction                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| -------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Medium   | `src/enrollment/service.ts` acceptance; `migrations/008_invitation_webauthn.sql` token guard | A valid token could expire between admission and the final consumption UPDATE. A test-only PostgreSQL trigger waits until the actual token deadline after admission and before user INSERT; original code incorrectly commits activation. The consumption row trigger now rechecks token **and intent** expiry with `clock_timestamp()` after UPDATE lock waits. Failure rolls back the entire user/member/grant/passkey/ceremony/audit transaction. Direct SQL expired-token consumption is also rejected. Expiry linearizes at the guarded consumption transition, not at the later COMMIT acknowledgement. |
| Low      | `src/enrollment/routes.ts` dispatch                                                          | Express matches mixed-case and trailing-slash routes, but exact string dispatch selected the wrong ceremony or refused a valid one. Original `/passkeys/ENROLLMENT/options/` returned 400. Normalize matched paths once; the regression exercises all four matched alias endpoints with real signed responses, session rotation and no secret logging. No authorization bypass was observed from the old mismatch.                                                                                                                                                                                            |
| Low      | `src/enrollment/policy.ts`, `src/enrollment/service.ts` capacity reservation                 | Admission allowed a tenant with exactly 1,000 members to add member 1,001, leaving future merchant operations outside their existing supported size. Return the already locked member count and reject acceptance at capacity under the exclusive tenant gate. The regression fills a synthetic tenant to 1,000, proves no extra account/token consumption and verifies existing management still works.                                                                                                                                                                                                      |

Validation also exposed an existing expired-challenge fixture precision defect:
two independent `clock_timestamp()` evaluations could exceed the five-minute
schema bound by microseconds. The fixture now uses one `statement_timestamp()`;
the schema constraint and expired-challenge rejection are unchanged.

No critical/high defect or additional authorization bypass was identified in the
reviewed paths. Specific checks:

- Tokens remain random/hash-only, one-shot and unrewriteable; live issuer/sponsor
  authority, policy versions, exact sponsor grants, active tenant, ceilings and
  terminal restrictions are rechecked under the gates. No restore/regrant path
  revives old tokens or grants. Admin terminal-restricted intent remains refused;
  submerchant payment reads remain denied.
- WebAuthn verifies the exact challenge (ultimately matched to the session-bound
  DB hash), origin, RP hostname, owned credential, optional user handle, UV and
  signature. Counter updates use CAS; non-increasing nonzero counters fail.
  All-zero counters remain supported by the verifier for authenticators that do
  not implement counters; single-use challenges/session rotation still prevent
  replay. Attestation `none` supplies no physical-device provenance guarantee.
- Password-only/legacy merchant sessions are denied at every merchant read/write
  route and BFF list/detail/status. Client cookies cannot authenticate the machine
  payment API or owner realm. Subject-only identity/CSRF/logout and legacy viewer
  read compatibility remain intentional. Tests use valid transport/Origin/CSRF so
  denials reach the actual authorization boundary.
- Authentication rotates cookie/CSRF without extending the original absolute
  expiry. Merchant writes require five-minute assurance. Factor changes advance
  user auth versions and invalidate sessions/challenges; status/grant changes use
  the existing invalidation triggers. New regressions cover stale write assurance,
  counter rejection and renewed assertion without session resurrection.
- Owner gate/rows precede the tenant gate. Ordered identities/grants precede
  sessions; session precedes ceremony and passkey updates. Cleanup/CSRF/logout do
  not acquire identity/policy locks after session locks. No new lock-order cycle
  was identified for supported application paths. SQL/lock/admission/total limits
  bound availability failures. Arbitrary privileged SQL outside the documented
  protocol is not a supported mutation path.
- Migration 008 remains unmerged, additive and transactional; populated-007 and
  rollback tests are preserved. No earlier migration is rewritten. History/audit
  guards remain invoker-rights with pinned paths and qualified table references.
  Restricted viewer roles cannot mutate the new enrollment tables.

Remaining **enablement** blockers are unchanged: there is no production token
issuer/delivery or enrollment UI, recovery/reset is unavailable, actual physical
passkey-device testing is outstanding, and production runtime database TLS,
least-privilege role grants/function access and external audit retention have not
been validated. Current startup still runs migrations using the configured pool;
this is not a production migration/runtime role split. All feature gates must
remain off. A lost COMMIT acknowledgement is ambiguous: do not automatically
retry, replace tokens, reset factors or bypass history. None of those limitations
is permission to activate this default-off increment after a development merge.
