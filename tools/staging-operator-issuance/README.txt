VaultX Pay - SINGLE-USE FIRST STAGING ISSUANCE
Pinned reviewed CLI: 245752b6722a1a1d0f21d3a21a86564f29da25a2.

DO NOT RUN until you have separate approval for the actual Render connection and
issuance. Download and extract the COMPLETE ZIP, then double-click Start-Issuance.cmd.
Requires approved Node.js 24. No build, npm install, Git, SQL editing, manual environment
configuration, administrator elevation or .ps1 script execution is needed.

Fixed target: vaultx_pay_staging; VaultX Pay Staging Test Operator; staging-e2e.
Encrypted delivery: %LOCALAPPDATA%\VaultXPay\Secrets\initial.vaultx-key.json
Real payments remain disabled; no payments, deployments, migrations or Render settings
are performed. Only the original reviewed CLI function implements issuance.

All answers are hidden, without stars. Type READONLY for the initial status check;
enter the SAME verified external hostname and authenticated login, then privately
paste the external URL. No credentials enter command arguments, OS environment,
files or logs. Credentials necessarily exist briefly in memory. Do not use recorded,
transcribed/shared/debugged sessions or compromised endpoints/clipboard monitors.
Node/CMD and native DPAPI must be allowed by your organization; no policy bypass,
Unblock-File, elevation or reduced TLS verification is provided.

The worker checks identity, session_user, marker, PG17, strict verified TLS, operator/
key absence and delivery/attempt/receipt absence. It then shows the final checkpoint:
ISSUE STAGING-E2E ONCE
Typing that exact phrase authorizes ONE invocation. Enter, Ctrl+C, a wrong phrase,
disconnection or timeout cancels/stops. No DB write occurs before this confirmation.
The worker rechecks the database and filesystem immediately after confirmation,
creates an exclusive, flushed public attempt record, then invokes runStagingCli from
the exact pinned source ONCE with ensure / staging-e2e / the fixed delivery filename.
No retry, rotate, revoke, fallback filename or alternate operator code is supported.

The successful result requires action=issued, matching public IDs in the DPAPI file,
and an active operator with exactly one matching active key verified by read-only
PostgreSQL queries. The wrapper never decrypts, prints or reads the raw API key or
DB key verifier. It inspects the encrypted file envelope and public metadata only.
A public, exclusive metadata receipt is written only after verification.

Single-use guards (no credentials/raw keys):
initial.vaultx-key.json.issuance-attempt.json
initial.vaultx-key.json.issuance-result.json
Any existing delivery/attempt/receipt, including an incomplete attempt record, stops
this package, even if copied/extracted again. Files are never automatically removed
or overwritten. Cancellation before recording an attempt creates no attempt record.
A crash between recording the attempt and invocation can consume the attempt without
issuing. This is intentional: at-most-once invocation across restarts is safer than
an automatic retry. Do not delete these guards to retry.

COMMIT/file delivery cannot be atomic. A timeout, disconnect, error, malformed CLI
output, missing receipt or failed verification is an UNVERIFIED outcome, not proof
of rollback. Preserve the encrypted key and all public records. Obtain a separately
approved read-only reconciliation of DB/file IDs before any next action. An active
key with lost/unusable delivery cannot be recovered from its hash; a separately
approved rotation may be needed. Never blindly retry or change operator code.

The wrapper's absence checks and original CLI transaction are separate. Avoid other
administrators issuing for staging-e2e concurrently. The original transaction,
idempotency/advisory locks, unique operator code and exclusive file creation remain
unchanged. A concurrent change can force STOP, including after an actual commit;
there is no general distributed exactly-once guarantee under crashes/network loss.

Integrity checks reject altered, missing or extra package files. Hash manifests
protect against accidental changes, not a malicious distributor rewriting both code
and hashes; use authenticated GitHub artifacts and the published ZIP digest.
Windows CI is credential-free: it tests controller behavior with injected fake CLI/
query clients and invalid synthetic ciphertext, plus real native DPAPI fixtures.
It never invokes the real issuance CLI or opens a DB/network connection. The actual
uploaded artifact is downloaded and revalidated before publication is reported.
--validate-only runs native synthetic DPAPI checks only, with no credentials/DB.
