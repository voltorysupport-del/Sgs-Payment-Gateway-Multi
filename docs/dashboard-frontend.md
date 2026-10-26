# VaultX Pay read-only dashboard

This React/TypeScript/Vite frontend uses the existing Express authentication and BFF. It adds no database migration, account provisioning, payment writes, or external services. All flags remain off by default. Nothing in this PR deploys or enables a dashboard.

## Views and API contract

- `/dashboard/#/`: overview with at most ten recent payments. Counts explicitly describe **this page**, never operator-wide aggregates or balances.
- `/dashboard/#/payments`: server pagination (10 records, offsets 0–10000), status and uppercase three-letter currency filters.
- `/dashboard/#/payments/:uuid`: immutable payment detail, with currency minor-unit formatting and timestamps in the viewer's local timezone.
- `/dashboard/#/status`: only the gateway's confirmed simulator/connectivity snapshot. Database reachability is not production readiness.
- Unauthenticated users see a login screen. There is no signup, account editing, provisioning, or payment mutation UI.

`GET /dashboard-api/auth/me` supplies username, user ID, operator ID and viewer role. It does **not** supply an operator display name; we display its authoritative ID. Login obtains a pre-authentication CSRF token from `/dashboard-api/auth/csrf`, then posts username/password to `/dashboard-api/auth/login` with `X-CSRF-Token`. Logout gets a fresh CSRF token and posts to `/dashboard-api/auth/logout`. Browser-generated Origin and existing server controls remain authoritative.

All payment/status data comes only from the three existing same-origin BFF GET routes. No frontend operator selectors, Bearer credentials, server-key configuration, generic proxies, or mutation calls are introduced. Zod validates every successful response, including simulator-only providers, pagination bounds/matching offsets and detail IDs. Non-success bodies and internal errors are never displayed or logged.

## Sessions and browser security

The existing server owns its Secure/HttpOnly/SameSite=Lax `__Host-` cookie, CSRF, revocation and expiry. Neither tokens nor passwords enter browser storage, URLs, logs, analytics or artifacts. CSRF values exist only during the request sequence. Password fields reset after every login attempt. The client sends cookies to same-origin paths only, rejects redirects and uses a 12-second deadline for read requests; no automatic write retries. Cookie-setting CSRF/login/logout sequences deliberately remain pending until the transport and body settle, because aborting a fetch cannot roll back a server commit or already processed Set-Cookie header.

Sensitive data lives only in React memory. App-owned authentication phases are checking, anonymous, authenticated, login, logout and blocked. Starting logout synchronously removes identity and unmounts protected views. Automatic visibility/history/channel revalidation cannot restore identity during a pending mutation or an unconfirmed outcome. Successful logout invalidates every older identity check and clears identity unconditionally. Failed/unconfirmed logout requires the explicit **Check session again** action before any workspace can return; that action reads the authoritative server session and does not retry the mutation.

Login ownership does not belong to the login screen. Hiding/returning while login is pending never produces a replacement login form or a second submission. Late cookie responses must settle before reconciliation or another mutation. Identity responses and expiry callbacks are bound to a coordinator generation so old screens cannot overwrite newer session state. Cleanup/restart of the React owner reconciles a settled operation rather than invoking it again.

The native Web Locks API serializes authentication cookie/CSRF sequences and identity reads across the origin's tabs. A current HTTPS browser supporting Web Locks is required for login/logout; unsupported browsers fail closed for these writes. BroadcastChannel sends only fixed `auth-start`, `auth-changed`, or `auth-unconfirmed` notices, never usernames, operator IDs, passwords, tokens, or CSRF values. Other tabs revalidate after the origin lock becomes available. Login and logout both notify peers. A stale login form checks the shared server session under the lock before submitting credentials, avoiding repeated attempts against an already authenticated cookie. Without BroadcastChannel, Web Locks still serialize mutations, and visibility/pageshow revalidation supplies the fallback.

A cookie request that never settles retains the lock and leaves authentication pending, potentially blocking other tabs. This is an intentional fail-closed availability tradeoff, not cancellation or confirmed logout. The UI tells the user to wait rather than retry. Closing a tab/connection does not undo a server-side commit; a newly opened dashboard must verify the authoritative session. Notifications are advisory; server authorization remains authoritative. Already delivered data in another visible tab without notifications cannot be retroactively withdrawn. No heartbeat is introduced.

The public shell has no private data. Static files are served only when **both** existing dashboard flags are enabled. HTML/assets and existing APIs use `Cache-Control: no-store`. No service worker is installed. Dedicated CSP permits scripts, styles and connections from self only; no inline scripts, eval, frames, external fonts, images, analytics or CDNs. No HTML rendering of untrusted values. Normal React escaping is retained. No source maps are published for the frontend. Vite does not load `.env` files and there are no frontend environment variables.

Browsers and operating systems can retain pixels, browser history and memory; cache headers cannot erase screenshots or guarantee physical-device privacy. Existing authenticated data already delivered cannot be retroactively withdrawn. No heartbeat silently extends idle sessions: inactive visible pages discover expiration on their next API request; hiding/returning clears and revalidates. Accessibility checks are automated, supplemented by responsive screenshots; they do not replace assistive-technology and keyboard usability review.

## Build, test and hosting

Use Node.js 24 and `npm ci`.

- `npm run build`: backend TypeScript plus Vite production assets into `dist/dashboard-ui/`.
- `npm start`: existing single Express service serves `/dashboard/` and all APIs on its existing port. No second service, new CORS policy or proxy is needed.
- `npm run typecheck`, `npm run lint`, `npm run format:check`.
- `npm run test:frontend`: component/API-client/accessibility tests with synthetic responses. These are isolated client tests, not a mock authorization implementation.
- `npm run test:isolated -- --check`: full guarded disposable PostgreSQL suite including existing auth, authorization and payments; no staging access. `npm test` builds assets before the suite.
- Optional real browser suite: `npx playwright install --with-deps chromium`, then set `VAULTX_BROWSER_TESTS=true` for the isolated test command. Linux CI enables it explicitly. A preinstalled local Chromium can be selected through test-only `VAULTX_CHROMIUM_EXECUTABLE`.

The browser test uses ephemeral localhost HTTPS, disposable PostgreSQL, synthetic passwords/operators/keys and the **real** auth/BFF/payment API. A test-only browser context accepts the ephemeral self-signed localhost certificate; application TLS behavior is unchanged. It checks real Chromium cookie attributes, login/logout, pagination, filters, foreign-record denial, expiry, status, axe (including contrast), and narrow-screen overflow. Screenshots contain synthetic fixture data only. This demonstrates localhost HTTPS browser behavior, **not** actual Render proxy, certificate, cookie, TLS or network configuration. Windows CI independently exercises frontend flows and existing native DPAPI/regression tests. Windows does not run the Docker-backed browser integration suite.

Hash routing intentionally avoids a broad SPA fallback: unknown asset/API routes remain genuine 404/401 responses. `/dashboard` redirects to `/dashboard/`; fragments never reach the server. A Vite development server alone is not a functional authenticated dashboard; use a built same-origin Express service with synthetic local HTTPS fixtures for full authentication. Never weaken Secure cookies or Origin validation for local HTTP convenience.

## Later staging prerequisites — separate approval required

No Render settings are changed. Keep `LIVE_MODE_ENABLED=false`, `ALLOWED_PROVIDERS=simulator`, `DASHBOARD_ENABLED=false`, `DASHBOARD_BFF_ENABLED=false` until separately approved.

Before a later deployment: approve this PR and deployment; use `npm ci --include=dev && npm run build` (build tools are development dependencies) and `npm run start`; verify database migrations 001–004 are present, PostgreSQL TLS certificate verification and least-privilege grants satisfy the existing backend policy; verify exact HTTPS `DASHBOARD_PUBLIC_ORIGIN` and independently established `DASHBOARD_TRUSTED_PROXIES` (never blanket trust); provision an authorized dashboard user/membership and **dedicated read-only** server credential through separately reviewed administration, then privately set `DASHBOARD_OPERATOR_ID` and `DASHBOARD_READ_ONLY_API_KEY`. The existing staging issuance key must not be copied to frontend code or substituted if write-enabled.

The current BFF supports one configured operator per deployment and one Node process for its private signed loopback authorization. Keep that deployment topology. No new schema or database permissions are required by this frontend. Complete an actual staging HTTPS browser smoke test, cookie/Origin/proxy verification, and account recovery review before enabling access. Those checks have not been performed by this PR.

## Corrective authentication regression coverage

Coordinator/component tests deterministically cover logout/revalidation overlap with and without BroadcastChannel, stale reads and expiry callbacks, hidden pending login, duplicate submissions, ambiguous committed login, failed logout barriers, explicit reconciliation, origin-wide lock serialization, stale login forms, unsupported lock capability and React-owner cleanup/restart. Cookie-sequence tests verify the read timeout never aborts a pending cookie response.

The disposable HTTPS Chromium flow holds **real committed** login/logout responses before headers reach the browser, exercises hide/show/history events, checks protected tables never return during logout, tests BroadcastChannel and no-channel fallbacks across shared-cookie tabs, switches between two synthetic users in the same operator, injects a logout network failure, revokes a synthetic user, and asserts focus after login/logout/expiry. Login accessibility runs at desktop and mobile widths; the form has its own visible H1. All existing payment history/filter/detail/isolation regressions remain.
