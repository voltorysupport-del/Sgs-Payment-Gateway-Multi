VaultX Pay READ-ONLY staging preflight - schema basis 245752b

This package is separate from the application repository. It requires only Node.js
24 already installed on Windows. No Git, PostgreSQL client, npm install, Docker,
repository location, SQL authoring, or code editing is needed.

After your separate approval for the actual Render check: extract the complete ZIP to a
private folder and double-click Start-Preflight.cmd. Do not run from inside the ZIP.
The program asks for explicit READONLY consent, the independently verified full
external staging hostname and PostgreSQL authenticated login, then the private URL
in a hidden prompt. Never send the URL to chat or include it in command arguments.
The URL is passed to Node over a private stdin pipe, not the environment or a file.

Do not use a shared/recorded/transcribed/debugged session. Never print credentials.
The package validates its file hashes and refuses inherited Node debugging/loader
options or NODE_TLS_REJECT_UNAUTHORIZED=0. Hashes detect accidental changes, not a
malicious distributor. Obtain the ZIP through the approved authenticated GitHub
artifact location and compare its published checksum when required by policy.

Windows PowerShell 5.1 and PowerShell 7-compatible language constructs are used.
Start-Preflight.cmd invokes Windows PowerShell 5.1. No execution policy is changed,
no Unblock-File is run, and TLS verification is never disabled. If company policy
blocks the unsigned launcher, STOP and obtain the organization's approved signing
or execution method. Do not bypass policy or run as administrator to work around it.

The only database SQL consists of SELECT, BEGIN READ ONLY and ROLLBACK. A read-only
session default protects queries as well. No application entry point, migrations,
provisioning functions, real provider, or arbitrary user-provided SQL is executed.
PostgreSQL enforces no application/schema writes in the transaction. The database
account may retain write privileges for future provisioning: this tool inspects
those privileges but does not exercise them or make the account read-only globally.
No marker changes, operator or key creation, trial writes, or metadata repairs occur.
Ordinary database connection/audit/statistics activity is not disabled.

Remote TLS requires verified certificate chain and hostname, TLS 1.2+, and SNI.
There is no plaintext/local test mode in the distributed checker. Numeric IP
substitution, Render short internal names, wrong target fields, and insecure URL
SSL options are rejected. Only vaultx_pay_staging and PostgreSQL 17 qualify.

PASS means the read-only identity, marker, schema existence, migration ledger and
catalog privilege checks passed. It does NOT authorize provisioning. STOP means do
not provision or repair anything automatically. Constraints/triggers, concurrent
changes and actual future writes cannot be fully proven by read-only inspection.

Package validation workflow:
- Offline configuration checks reject missing consent, wrong identity fields, wrong
  database, internal/IP endpoints, and insecure SSL options without opening sockets.
- Seven isolated query-driver simulations cover readiness and failure conditions,
  with SQL allowlist, TLS, rollback and secret-output assertions. No DB records exist.
- Windows PowerShell 5.1 and PowerShell 7 execute the actual launcher in ValidateOnly
  mode, including a private UTF-8 input pipe and paths containing spaces/ampersands.
- Tampered/missing files and unsafe Node options must fail closed.
- The GitHub run is the source of the actual validation result; no Render database
  or operator/key provisioning is part of this workflow.

The -ValidateOnly launcher switch runs credential-free local checks only. It never
loads the PostgreSQL driver or opens a database connection. Runtime dependencies
and their license files are bundled from the project's locked dependency versions.
The package SHA256SUMS.json detects accidental changes; authenticated GitHub access
provides distribution provenance. The artifact expires after 30 days. Never use an
untrusted replacement bundle or weaken an organization's script execution policy.
