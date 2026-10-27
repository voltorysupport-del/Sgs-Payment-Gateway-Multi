# Phase 4C — Secure submerchant payment dashboard

The existing read-only dashboard at `/dashboard/#/payments` now serves both
operator-wide viewers and terminal-scoped submerchants. The merchant entry point
links to it after authentication; submerchants do not enter the administrator
workspace. This is the existing React/Vite interface and dark-blue design, not a
parallel authentication system or an alternate payment API.

Everything remains simulator-only and disabled by default. Terminal reads still
require the Phase 4B non-production gate and existing dashboard/BFF/merchant gates.
Production terminal-read activation is refused. No account, enrollment, credential,
external migration, Render access, deployment or payment write is performed here.
No migration, dependency, new endpoint or new feature gate is introduced.

## Small compatible identity contract addition

`GET /dashboard-api/auth/me` adds a safe display descriptor:

```json
{ "readAccess": { "scope": "terminal", "payments": true, "status": false } }
```

It describes only the authenticated subject's workspace label and currently
available read screens. It contains no terminal IDs, grant metadata, policy
versions, session verifier, key or signed internal context. The existing role
remains `viewer`. Password-only privileged identities have no available protected
reads; current server WebAuthn proof is still required.

This addition prevents two UI errors: presenting operator-wide wording to a
submerchant, and automatically requesting status for a payment-only user. The
client accepts its absence for compatibility with the previous operator-viewer
DTO. These fields control presentation only: a forged or altered browser value
cannot authorize any BFF request. All records still pass the unchanged Phase 4B
session/key/signed-handoff/canonical-assignment/SQL checks. Backend tests verify
the descriptor cannot expose private handoff fields and cannot bypass MFA/gating.

## Read behavior and sensitive state

- Payment list, validated filters, bounded offset pagination, page-only summaries,
  detail and status reuse the existing sanitized GET BFF contracts. The browser
  never computes terminal authorization, sends tenant/terminal selectors or sees
  an operator API key. Server-denied views issue no data request.
- The shared protected-read hook binds data to the current route/filter/revision,
  aborts superseded requests and ignores late responses. Detail routes are keyed
  by payment ID. Changing views cannot show a previous record under a new ID.
- Successful visible reads schedule one revalidation after 15 seconds, with no
  overlapping automatic requests. Background success preserves keyboard focus;
  initial/manual loads show progress. Failure clears the data and stops polling.
- 401 closes the session view; 403 or an ambiguous/network/server failure closes
  all protected records until an explicit session check. These observed failures
  notify other tabs using the existing secret-free channel. A 400 filter error
  or non-enumerating 404 detail remains an inline empty/error view.
- Logout and cross-tab auth changes close the workspace before confirmation.
  Hidden/page-hide views clear protected state; pageshow/visibility restoration
  rechecks the server. Session/version guards prevent an old read failure from
  closing or repopulating a different authenticated workspace.

**Revocation observation limit:** server SQL revocation is immediate at the
Phase 4B linearization boundary; a browser cannot know an out-of-band database
change instantaneously without push notifications. An active view detects it on
its next read (15-second scheduling interval plus the existing 12-second client
request bound, subject to browser scheduling), focus/pageshow reconciliation or
an auth notice. It clears immediately when denial/uncertainty is observed. Data
already authorized/materialized cannot be recalled, and this is not a claim of
securely erasing browser heap memory or every browser's BFCache screenshot.
There is no new realtime/push infrastructure or browser credential storage.

## Responsive and accessible UI

The shared table retains status, currency-aware integer-minor-unit display,
timestamps, page indicators and sanitized details. Record IDs are links so mobile
users can open a detail without scrolling to the final column. The table's named,
keyboard-focusable scroll region and caption explain horizontal scrolling.
Navigation, skip link, focus management, labels, non-color-only status badges,
loading/empty announcements and actionable denied states remain available.
Currency formatting falls back to explicit minor units if the browser lacks the
currency enumeration API; it does not assume every currency has two decimals.

Screenshots below are entirely synthetic, generated from real local BFF/SQL reads
and a Chromium virtual authenticator. No staging data or credentials are present.

- [Desktop payment list](screenshots/phase4c-payments/desktop.png)
- [Mobile payment list](screenshots/phase4c-payments/mobile.png)
- [Payment detail](screenshots/phase4c-payments/detail.png)
- [Access unavailable](screenshots/phase4c-payments/denied.png)

## Validation and remaining checks

Run `npm run test:isolated -- --check` with the existing disposable PostgreSQL
safeguards. Include `VAULTX_BROWSER_TESTS=true` and the existing local Chromium
configuration for real HTTPS browser flows. Unit tests cover capability-aware
navigation, errors, stale-response disposal, bounded/non-overlapping refresh and
focus-safe updates. Database tests cover safe identity metadata and password-only
read denial. Browser tests enroll/authenticate with actual synthetic UV proofs,
exercise cancellation, pagination/details/back navigation, hidden/foreign/NULL
payment IDs, cross-tab logout, revocation, disabled memberships, default-off
access, desktop/mobile overflow, keyboard navigation and axe including contrast.

JSDOM accessibility tests exclude contrast; real Chromium axe checks it. Automated
checks do not establish manual screen-reader usability, physical Windows Hello/
security-key interoperability, Safari/Firefox behavior or every BFCache first
frame. Those remain explicit release checks. Runtime verified PostgreSQL TLS,
least-privilege/migration-role separation and deployment migration review remain
outstanding production prerequisites. This PR does not authorize deployment,
real enrollment, real providers or feature enablement.
