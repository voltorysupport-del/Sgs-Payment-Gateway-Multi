VaultX Pay - FIRST OPERATOR PREPARATION ONLY
Pinned application commit: 245752b6722a1a1d0f21d3a21a86564f29da25a2.

Extract the COMPLETE approved ZIP and double-click Start-Preparation.cmd.
Requires approved Node.js 24; no build, Git, SQL editing, npm install, environment
configuration, administrator elevation or PowerShell script execution is needed.

The package automatically verifies Node and integrity, checks the intended key
file is absent, and runs 3 credential-free native DPAPI tests using the exact pinned
application delivery implementation. Tests use deliberately invalid synthetic
credential text in disposable temporary files, then remove them. No valid operator
API key is generated. A DPAPI failure stops before requesting Render credentials.
Inline PowerShell commands implement existing Windows DPAPI; no .ps1 is included,
no execution policy is bypassed, and no machine/security settings are changed.
If endpoint controls prohibit Node, CMD, Add-Type or DPAPI, STOP for approved IT help.

Default intended delivery location, NOT CREATED by this program:
%LOCALAPPDATA%\VaultXPay\Secrets\initial.vaultx-key.json
Only missing VaultXPay/Secrets parent directories may be created. Existing files
(including symlinks) are preserved and cause STOP. No real credential is written.

At the hidden prompts, type READONLY, enter the SAME independently verified external
hostname and authenticated login used in the successful preflight, then privately
paste the rotated external connection URL. The previous preflight did not retain
these values; nothing is requested in chat. All replies are hidden, with no echo.
Enter submits, Backspace edits, Ctrl+C cancels. Redirected credential input is refused.
Do not use recorded/transcribed/debugged/shared sessions. Input crosses a private
child stdin pipe, never argv, environment or a saved credential file. Credentials
briefly exist in memory; this does not protect against a compromised machine,
clipboard recorder, administrator or process dump.

Reused pinned code: production/simulator-only configuration, staging host/login/DB
validation, strict TLS and same-connection session_user/marker verification, and
native DPAPI delivery. Reviewed TS source is compiled during package build, not on
your laptop. The package contains only required original library modules, not the
CLI/server entry point, migration runner or an issuance command.

IMPORTANT: the original CLI status operation takes advisory/row locks including
SELECT FOR UPDATE, which is incompatible with strict READ ONLY. This package uses
the original configuration and identity functions followed by parameterized plain
SELECTs in a READ ONLY transaction. Read-only session defaults, TLS 1.2+, certificate
and hostname verification, SNI, timeouts, marker, PostgreSQL 17 and session login
checks remain. No plaintext/local mode, trial write or database repair is provided.
The required provisioning configuration flag is confined to a local config object,
not exported to process.env or passed to a provisioning operation.

Results:
READY_FOR_SEPARATE_PROVISIONING_APPROVAL: staging-e2e is absent in this read snapshot.
STOP_OPERATOR_ALREADY_EXISTS: inspect public IDs/revocation flags; never issue or
rotate automatically. STOP_EXISTING_OPERATOR_REQUIRES_REVIEW: identity/suspension
conflict; no changes made. Other failures are sanitized STOP, never proof of absence.
No hashes, raw keys, operator names from the DB, passwords or URLs are displayed.
The status snapshot can change; the later approved issuer must recheck everything.
This program ALWAYS stops before any issuance. It has no ensure/rotate/revoke option.

If an earlier attempt may have been interrupted, preserve existing protected files
and reconcile database/file IDs through an approved read-only review. Never delete
a file, change operator code, or blindly retry to work around an ambiguous outcome.

SHA256SUMS.json covers all bundled files. It detects accidental changes, not a
malicious distributor replacing both code/hashes; use authenticated GitHub artifacts.
Runtime packages/licenses are bundled from the pinned lockfile. No application or
provider code is started. Windows tests and downloadable artifact require separate
publication approval; a local Linux result is not evidence of native DPAPI success.
