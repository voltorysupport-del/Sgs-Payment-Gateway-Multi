VaultX Pay evidence-linked RECOVERY-01 - SEPARATE EXECUTION APPROVAL REQUIRED
Application CLI pinned to 245752b6722a1a1d0f21d3a21a86564f29da25a2.

DO NOT RUN under publication/testing approval. Actual Render connection and exactly
one recovery-01 issuance need separate explicit approval. Node.js 24 is required.
After that approval: extract the complete ZIP and double-click Start-Recovery-01.cmd.
No build, Git, SQL, environment setup, administrator elevation or .ps1 is required.

The ORIGINAL issuance package remains blocked by its ORIGINAL record. This recovery
package must find, read and validate that same original record (no deletion, rename,
overwrite, marker editing, --ignore-attempt flag or alternate operator/delivery).
Required timestamp: 2026-10-25T15:08:36.036Z; target vaultx_pay_staging / staging-e2e;
original state ATTEMPT_STARTED_DO_NOT_RETRY; pinned application 245752b.
The original fingerprint is not known to the cloud assistant: the approved local
run captures it without writing the original, presents it at confirmation, rechecks
it before invocation and after verification, and stores it in NEW recovery records.
No claim is made to compare against a historical fingerprint not supplied/stored.

All replies are hidden. Type READONLY for the mandatory fresh status check, enter the
verified external hostname/login, then paste the private external URL. At the final
checkpoint inspect the original fingerprint/time and fixed target, then type:
AUTHORIZE RECOVERY-01 FOR STAGING-E2E
There are no more questions after confirmation; all target/absence checks run again
immediately before the one CLI invocation. Enter/wrong phrase/Ctrl+C cancels before
invocation. After invocation cancellation/disconnect cannot promise rollback.

Fresh guards: verified TLS chain/hostname/SNI/TLS1.2+, session_user, database and marker,
PG17, absent operator and keys, zero provisioning sessions, absent delivery and old
receipt, unchanged original evidence, no recovery-01 journal/receipt. Simulator-only
flags and real-payments-disabled configuration are fixed. No automatic repair.

Fixed encrypted delivery remains:
%LOCALAPPDATA%\VaultXPay\Secrets\initial.vaultx-key.json
NEW public-only records in the same folder:
initial.vaultx-key.json.recovery-01.attempt.jsonl
initial.vaultx-key.json.recovery-01.result.json
The journal is exclusively created and flushed before invocation, linked to the
original SHA256 and timestamp. Presence consumes recovery-01 even if CLI was never
called. It cannot be retried, overwritten or auto-deleted. Do not remove guards.
The original record and any original attempt/receipt/delivery are never replaced.

The CLI is the unchanged reviewed runStagingCli function, called once with ensure,
staging-e2e and the fixed delivery path. Original transactions/idempotency/locks,
secure random key generation, hash storage and DPAPI delivery remain unchanged.
No rotation/revocation/migration/payment/provider or deployment action exists.
Success requires validated public metadata, stable DPAPI envelope and read-only DB
verification of one matching active key for the expected active operator. No actual
key is decrypted/printed by this package. The receipt contains only public IDs.

Diagnostics retain controlled phases, attempted true/false/unknown, CLI status and
an allowlisted static category: CONFIGURATION/TARGET/OPERATOR/KEY/DELIVERY or generic
DATABASE_OR_INTERNAL_FAILURE/UNCLASSIFIED_CLI_FAILURE. No raw DB/OS errors, SQL,
connection strings, passwords, key material or verifiers are logged. IPC errors
before the CLI are separately recognizable. A CLI success followed by verification
failure stays distinct from CLI failure/rollback. SQLSTATE is unavailable when the
unchanged CLI itself swallowed it; generic failures cannot prove a specific cause.

Files/DB COMMIT are not atomic. Any unverified outcome preserves both generations of
records and stops. Concurrent external administrators can race absence checks and
COMMIT; coordinate one admin. No general distributed exactly-once guarantee exists.
Never retry, switch operator code, change filename, rotate or revoke automatically.

Database URL crosses a private stdin pipe and is passed as an in-memory CLI config
object, never OS environment, argv, file or console output. Credentials necessarily
exist briefly in memory. Avoid shared/recorded/debugged/transcribed sessions or
compromised endpoints/clipboard capture. Follow company application-control policy;
no PowerShell policy bypass, Unblock-File or elevation is provided. Inline DPAPI
commands are used as in the reviewed CLI; failures stop rather than weaken policy.

CI uses synthetic invalid credentials, fake CLI/query clients and disposable fixture
files only. It byte-checks fixture originals, exercises Windows IPC boundaries and
native DPAPI in normal/Restricted-policy tests, uploads/downloads the ZIP and repeats
validation. It never invokes actual issuance or connects to a DB/Render. Native IPC
fixtures test process behavior, not a real DB transaction. --validate-only is a
credential-free native DPAPI self-test, not a staging check or issuance operation.
SHA256SUMS.json/provenance identify package content; obtain the authenticated GitHub
artifact (30-day retention), not an untrusted bundle rewriting both code and hashes.
