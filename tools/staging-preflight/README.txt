VaultX Pay READ-ONLY staging preflight - Node.js launcher
Schema and safety basis: merged commit 245752b.

Requires Node.js 24 already approved and installed on Windows. No PowerShell script,
Git, SQL editing, npm install, repository checkout, PostgreSQL client or Docker is
needed. No .ps1 file is included and no PowerShell execution policy is changed.

After separate approval for the actual Render check: extract the COMPLETE ZIP into
a private folder and double-click Start-Preflight.cmd. Do not run from inside the
ZIP. All replies are hidden (no characters or asterisks), including consent, host
and login, so accidentally pasting a URL into a wrong prompt does not display it.
Type READONLY at the consent prompt, then enter the independently verified full
EXTERNAL hostname and authenticated PostgreSQL login. Paste the private external
staging URL only at the final prompt. Never send it to chat. Enter submits;
Backspace edits; Ctrl+C cancels. Unsupported control/escape keys stop the run.

The launcher uses Node's raw console mode to disable echo; it restores the previous
mode on completion, cancellation, EOF and input errors. Redirected/noninteractive
credential input is refused. Use a normal authorized Windows terminal, not an IDE
output pane, shared/recorded/debugged session or terminal transcript. The private
URL travels over a child-process stdin pipe, never argv, environment, a saved URL
file, terminal output or command history. Credentials necessarily exist briefly
in process memory; this does not protect against a compromised administrator,
machine, clipboard monitor, process dump or external keyboard recording.

Start-Preflight.cmd refuses Node preload/debug/unsafe TLS/native-driver variables
BEFORE Node starts, without expanding or printing their values. Node rechecks its
runtime and file integrity before reading any input. The package rejects missing,
modified or extra files. SHA256SUMS.json detects accidental changes, not a malicious
distributor replacing both code and hashes. Use the authenticated GitHub artifact
and its published ZIP digest. Vendored pg dependencies and licenses are included.

This does not override enterprise security controls. Node and CMD must themselves
be permitted by your organization's policy. If application control/SmartScreen or
endpoint security blocks the package, STOP and ask your authorized IT administrator
for an approved method. Do not unblock files, change execution policy, disable
protection, or run as administrator to work around it.

Database SQL is unchanged: SELECT, BEGIN READ ONLY and ROLLBACK only. Read-only
session defaults, timeouts, parameterized queries and a read-only transaction
remain enforced. No application startup, migrations, provisioning functions, real
provider, arbitrary SQL or trial writes execute. No operator or API key is created;
no marker, schema, records or permissions are changed. Normal connection/audit/
statistics activity is not disabled. The account may have write privileges, but
this checker only inspects those privileges and never exercises them.

Remote TLS requires verified certificate chain and hostname, TLS 1.2+ and SNI.
There is no plaintext mode. Internal short names, numeric IP substitutions, wrong
identity fields and insecure SSL URL options are refused. Exact database name
vaultx_pay_staging, authenticated session_user, PostgreSQL 17, staging marker,
migration ledger, required tables/columns and catalog privileges are checked.

PASS covers these read-only prerequisites, not permission to provision. STOP means
do not provision or automatically repair anything. Read-only catalog inspection
cannot prove every trigger/constraint, concurrent change or future successful write.

CI uses synthetic non-credentials and disposable temporary files only, without any
network/database connection. It tests the Node launcher and pipe on Windows,
hidden-console input behavior with simulated TTY events, cancellation/echo/UTF-8,
fail-closed integrity/runtime/TTY controls, and unchanged SQL/TLS rules. It uploads,
downloads and revalidates the actual artifact. Simulated TTY tests verify the input
logic; they do not emulate every Windows Terminal/endpoint-security configuration.
An extra Windows CI check runs the Node launcher under Restricted PowerShell policy
using an inline host command, without executing any PowerShell script file.

Credential-free validation can be run with: node launcher.js --validate-only
That mode verifies integrity and the private UTF-8 pipe, but never loads pg or
opens a socket. It cannot perform the Render check or consume private credentials.
The GitHub artifact expires after 30 days. Actual Render execution still requires
your separate approval; publishing/testing this package never connects to Render.
