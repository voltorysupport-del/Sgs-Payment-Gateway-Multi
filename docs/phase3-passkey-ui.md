# Phase 3 passkey enrollment and sign-in UI

This default-off increment uses the merged Phase 3 invitation/WebAuthn API and
existing client session controller. It adds no account issuer, authentication
realm, migration, owner bootstrap, email delivery, recovery/reset or payment write.
Keep all existing feature flags off; `LIVE_MODE_ENABLED=false` and
`ALLOWED_PROVIDERS=simulator` remain enforced. Do not enable real enrollment from
these instructions. Production activation is still refused by the Phase 3 gate.

## Screens and server contract

The existing `/merchant/` and `/dashboard/` sign-in pages offer **Accept a test
invitation**. There is no invitation link parameter, token URL or token-bearing
route. The user enters a synthetic private value and matching passwords into the
form, then completes the browser's passkey creation prompt. Registration still
returns no authenticated session or privileged access. The user subsequently signs
in with the invited username/password and explicitly selects **Verify passkey**.

`GET /dashboard-api/auth/me` retains its existing subject-only identity/role and
adds a server-derived `authentication` object:

- `passkeyRequired`: an existing merchant profile requires WebAuthn assurance.
- `passkeyVerified`: the session references its subject's current unrevoked
  passkey, with the current user authentication version.
- `passkeyFresh`: that verified assurance is within the existing five-minute
  privileged-write window.
- `passkeysEnabled`: the existing development/test ceremony routes are enabled.

The UI requires this metadata; missing/malformed metadata fails closed. This DTO
is navigation guidance, not permission authority. Every management/BFF request
still uses the existing server-side permission, tenant, status, session and MFA
checks. A successful browser API call alone never opens the workspace: the
controller re-reads the current session and verifies the same subject/operator and
server assurance. Merchant administration requests fresh assurance; the read-only
viewer dashboard retains its existing compatible read behavior. The backend's
submerchant payment denials and machine API-key behavior are unchanged.

New browser logic only uses fixed same-origin API paths, existing CSRF acquisition,
secure HttpOnly host cookies and existing Web Locks/BroadcastChannel coordination.
All credential forms have fixed POST actions: if JavaScript event handling is
unavailable after rendering, native submission cannot place secrets into a GET
URL and is refused by the existing CSRF/JSON requirements.
WebAuthn options are validated and binary fields converted locally. User
verification is required, registration attestation remains `none`, and RP ID must
match the page hostname. Origin, signature, challenge freshness/ownership, UV,
revocation and counters remain server-verified. No third-party authentication SDK
or new dependency is introduced.

## Privacy and cancellation

Invitation/password fields are cleared before asynchronous submission and when
leaving/hiding the form. Values/challenges/credential responses exist only
transiently in memory and required HTTPS request bodies; they are never put into
URLs, application logs, analytics, local/session storage or BroadcastChannel.
JavaScript strings/request buffers cannot be guaranteed physically zeroed by the
runtime. The authenticator intentionally owns the private passkey; the application
never receives its private key. Native password-manager/passkey behavior is outside
application browser storage and remains under browser/user control.

| Outcome                                          | Safe next step                                                                                                                                                                                                       |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unsupported HTTPS/WebAuthn/Web Locks environment | Controls are disabled; use a supported secure browser. No fallback or MFA bypass.                                                                                                                                    |
| Known invalid/expired/used invitation            | Generic error; fields stay cleared. Contact the administrator rather than inferring account/tenant details.                                                                                                          |
| Cancelled enrollment prompt                      | No verification request is sent. A manually restarted enrollment first discards the old anonymous session/ceremony through existing CSRF logout, under the shared Web Lock. It does not replace an invitation token. |
| Cancelled or rejected authentication prompt      | No automatic assertion retry. Sign out and perform a fresh password login to obtain a new ceremony. The cancelled challenge is not reused or silently reset.                                                         |
| Network failure starting options                 | No account verification was submitted. The user may explicitly start again; no automatic retry.                                                                                                                      |
| Uncertain enrollment verification response       | Keep the UI blocked. An anonymous session check cannot prove whether enrollment committed; no invitation resubmission is offered. Contact the administrator.                                                         |
| Uncertain authentication/logout response         | Protected views close. Explicitly check the server session before continuing; no automatic mutation retry.                                                                                                           |
| Session, account or grant invalidation           | Existing session checks remove protected screens; reauthenticate only through the current server rules.                                                                                                              |

Cancel browser prompt aborts only the native authenticator operation. It does not
abort a submitted cookie-changing/verification HTTP request: that must settle to
avoid late-cookie/session races. App-owned operations outlive screen transitions.
The existing controller checks session changes across tabs and on visibility/page
restoration. Reloading discards in-memory warnings; immutable server token
consumption still rejects replay and prevents duplicate accounts. No persistent
secret or token-specific recovery journal is added. A cancelled registration can
leave an unregistered credential in a native authenticator; the app cannot delete
or recover native credentials and supplies no factor-management bypass.

## Tests and review assets

The complete isolated suite creates verified disposable PostgreSQL 17 only:

```text
npm run test:isolated -- --check
npm run test:frontend
npm audit --omit=dev
npm audit
npm run secrets:scan
```

HTTPS browser tests additionally use the existing `VAULTX_BROWSER_TESTS=true`
configuration with installed Chromium/OpenSSL. They exercise the **built UI**,
real CSRF/cookies and the actual server verifier with a CTAP2 UV virtual
authenticator. Coverage includes enrollment, password-only denial, cancellation,
fresh login/retry, passkey verification, cross-tab logout, server revocation,
unsupported browsers, lost COMMIT acknowledgement, same-origin traffic,
secret-free storage/logs, keyboard focus, mobile overflow and real-browser axe
checks including contrast. Component tests do not claim to establish browser
cookie behavior; their axe contrast rule is disabled because jsdom cannot render.

Screenshots are captured before any invitation/password input, or after those
forms have been cleared/unmounted. Review images contain exclusively synthetic
public account data. No traces, HAR files, recordings, credentials or certificates
are included. CI uploads the existing synthetic dashboard screenshot artifact.

Remaining blockers before enabling real use: independent security review,
production database TLS/least-privilege deployment, approved real invitation
custody/delivery/issuance, physical Windows Hello/security-key and supported browser
verification, owner/bootstrap policy and separately approved lost-factor recovery.
A virtual authenticator does not prove real device enrollment, OS prompt behavior
or hardware attestation. All existing gates remain disabled by default; no Render
access, external migration, real enrollment or payment execution is authorized.

## Reviewed synthetic screenshots

Captured from the tested built UI. Invitation/password fields are blank in the
form images; the workspace images show disposable synthetic identities only.

- [Invitation acceptance](screenshots/phase3-passkeys/enrollment.png)
- [Password-only verification gate](screenshots/phase3-passkeys/verification.png)
- [Verified merchant workspace](screenshots/phase3-passkeys/merchant.png)
- [Read-only dashboard on mobile](screenshots/phase3-passkeys/mobile.png)
