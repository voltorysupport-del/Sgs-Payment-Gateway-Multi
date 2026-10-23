# Staging operator and API-key provisioning

This is a trusted administrator's local command, not an HTTP administration API.
It creates **VaultX Pay Staging Test Operator**, normally with code `staging-e2e`,
using the existing operators/API-key tables and authentication format. It never
enables real payments, calls a provider, or creates database migrations.

No actual Render credentials are included or provisioned by this change. All
automated verification uses a freshly created disposable PostgreSQL cluster.

## Before connecting to staging

1. Review and merge/deploy through your normal approval process. This command is
   available after `npm ci --include=dev` and `npm run build`; its entry point is
   `node dist/cli/staging-operator.js` (`npm run staging:operator -- ...`).
2. Independently identify the staging database host and database username from
   your approved infrastructure inventory. The database must be named exactly
   **vaultx_pay_staging**. Never designate a production database as staging.
3. Have the database owner verify the target and set this nonsecret designation
   once, using their existing trusted PostgreSQL administration connection:

   ```sql
   SELECT current_database(), current_user;
   -- Continue ONLY if this is the intended staging database.
   COMMENT ON DATABASE vaultx_pay_staging IS 'vaultx-pay:staging';
   ```

   This is database metadata, not a new application table or schema migration.
   The provisioning CLI cannot set the marker itself. It checks the marker using
   the PostgreSQL catalog on the same connection used for provisioning. A marker
   is an administrator's designation, not cryptographic proof of infrastructure
   identity; trusted administrators must never copy it to production.

4. Ensure application migrations 001 and 002 have already run on staging through
   the existing startup workflow. The CLI refuses a missing/incompatible schema
   instead of applying migrations. Give the administrator only the privileges
   needed to read/write operators and API keys. PostgreSQL superuser is not needed.

If PostgreSQL command-line tools are installed, an administrator can open a
password-prompted TLS connection without putting credentials in command history:

```bat
set "PGSSLMODE=verify-full"
psql -h YOUR_STAGING_HOST -U YOUR_STAGING_DATABASE_USER -d vaultx_pay_staging -W
```

Use the SQL above only after independently verifying the connection. Do not use
a URL containing a password as a command-line argument. Remote CLI connections
require certificate validation; use a trusted TLS hostname and, when necessary,
`NODE_EXTRA_CA_CERTS` pointing to an approved CA certificate. Do not disable TLS
verification. Only the literal loopback host `127.0.0.1` permits plaintext for
local disposable/staging infrastructure.

## Beginner-friendly Windows CMD setup

Install Node.js 24, clone this repository, and open **Command Prompt (CMD)** in
the repository directory. Build first:

```bat
npm ci --include=dev
npm run build
npm run staging:operator -- --help
```

Set these nonsecret values in CMD, substituting the independently verified host
and database username. Render's project label Staging is separate from NODE_ENV;
use NODE_ENV=production for runtime safety:

```bat
set "NODE_ENV=production"
set "VAULTX_ENVIRONMENT=staging"
set "ALLOW_STAGING_OPERATOR_PROVISIONING=true"
set "STAGING_DATABASE_HOST=YOUR_STAGING_HOST"
set "STAGING_DATABASE_USER=YOUR_STAGING_DATABASE_USER"
set "LIVE_MODE_ENABLED=false"
set "ALLOWED_PROVIDERS=simulator"
set "SIMULATOR_CONTROLS_ENABLED=false"
mkdir "%LOCALAPPDATA%\VaultXPay\Secrets"
powershell -NoProfile
```

You are now inside a PowerShell child session of CMD. Paste the following
**PowerShell** commands. The URL prompt is hidden; it is not part of command
history and does not get saved in a file. Obtain the URL privately from your
approved secret store. Do not use a recorded/shared terminal session:

```powershell
$secret = Read-Host 'Private staging DATABASE_URL' -AsSecureString
$env:DATABASE_URL = [Net.NetworkCredential]::new('', $secret).Password
$initial = Join-Path $env:LOCALAPPDATA 'VaultXPay\Secrets\initial.vaultx-key.json'
npm.cmd run staging:operator -- ensure --key-file $initial
npm.cmd run staging:operator -- status
```

The default operator code is `staging-e2e`. To isolate another test operator, add
`--operator-code staging-your-team` consistently to every command. Codes must
start with `staging-` and use lowercase letters, digits, underscores, or hyphens.
The tool will not rename an existing unrelated operator or reactivate a suspended
operator. Suspended operators can still be inspected and have keys revoked.

**The raw key is never printed.** On Windows, the explicit delivery file contains
Windows DPAPI ciphertext protected for the administrator's current Windows user
account. It cannot simply be moved to another user/machine and decrypted. Keep a
protected backup or use an approved credential manager. Do not commit the file,
upload it to a PR, attach it to a ticket, or open it in a logging tool.

The command prints only operator/key IDs, revocation metadata, and the action.
It never prints the URL, password, verifier, raw key, or database error details.
No print-key option exists. Do not run with external environment tracing enabled.

## Test payments without displaying the key (PowerShell)

In the same administrator session, decrypt into memory and use the key directly
as an HTTP header. Substitute only the public staging application URL below.
The loop creates and verifies both successful and failed simulated payments:

```powershell
Add-Type -AssemblyName System.Security
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$record = Get-Content -LiteralPath $initial -Raw | ConvertFrom-Json
$bytes = [Convert]::FromBase64String($record.ciphertext)
$plain = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
$credential = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
$headers = @{ Authorization = ('Bearer ' + $credential.apiKey) }
$base = 'https://YOUR-STAGING-SERVICE.onrender.com'
foreach ($outcome in @('succeeded', 'failed')) {
    $creationHeaders = $headers.Clone()
    $creationHeaders['Idempotency-Key'] = [guid]::NewGuid().ToString()
    $payment = Invoke-RestMethod -Method Post -Uri "$base/payments" -Headers $creationHeaders -ContentType 'application/json' -Body '{"amountMinor":1000,"currency":"EUR"}'
    $null = Invoke-RestMethod -Method Get -Uri "$base/payments/$($payment.id)" -Headers $headers
    $body = @{ outcome = $outcome } | ConvertTo-Json -Compress
    $null = Invoke-RestMethod -Method Post -Uri "$base/payments/$($payment.id)/simulate" -Headers $headers -ContentType 'application/json' -Body $body
    $verified = Invoke-RestMethod -Method Get -Uri "$base/payments/$($payment.id)" -Headers $headers
    if ($verified.status -ne $outcome) { throw 'Unexpected simulated payment state.' }
    $verified | Select-Object id, status, provider
}
```

Retrieval reads PostgreSQL. Automated integration tests additionally assert the
persisted status directly in SQL. Do not enable verbose HTTP tracing or print
`$headers`, `$credential`, `$plain`, or `$env:DATABASE_URL`. A failed REST call can
be investigated by safe request IDs, not by dumping request headers.

## Safe retries, rotation, and revocation

`ensure` creates one operator and one initial key. If an active key already
exists, retries return metadata without creating another key or rewriting the
delivery file. If only revoked keys exist, `ensure` refuses; use an explicit
rotation. Concurrent invocations serialize by operator code and row locks.

Use the public key **ID**, not the raw key, from `status` output. Still in
PowerShell, replace OLD_KEY_UUID with that ID:

```powershell
$replacement = Join-Path $env:LOCALAPPDATA 'VaultXPay\Secrets\replacement.vaultx-key.json'
npm.cmd run staging:operator -- rotate --key-id OLD_KEY_UUID --key-file $replacement
npm.cmd run staging:operator -- status
npm.cmd run staging:operator -- revoke --key-id KEY_UUID_TO_REVOKE
```

Rotation atomically revokes the specified old key and inserts one replacement.
Retrying with the same old key ID returns the same replacement metadata, even
when the original delivery path already exists. It never creates another key for
the same rotation. A later rotation must explicitly identify the newer key.
Revocation is idempotent and constrained to the selected staging operator. A key
ID from a different operator is refused. The CLI does not revoke unrelated active
keys as a side effect of rotation.

New issuance requires an explicit absolute `--key-file` path outside this
repository. Existing files and symlink destinations are never overwritten. Linux
requires a directory owned by the current user with no group/other access and
creates a mode-0600 plaintext credential file; Windows encrypts with current-user
DPAPI before writing. Linux administrators should move credentials into an
approved secret manager and protect filesystem/backups accordingly. There is no
plaintext delivery fallback if Windows DPAPI fails.

Delivery is flushed to disk before database commit. A delivery error rolls back
database issuance and old-key revocation. Filesystem and database commits cannot
be atomic: an interruption or ambiguous commit can leave a protected delivery
file for a rolled-back or committed key. **Do not blindly retry with another
operator code or delete the file.** Run `status`, compare key IDs, and verify
authentication. If necessary, explicitly rotate to a new delivery filename.
Raw keys cannot be recovered from PostgreSQL; only hashes are stored.

When finished, clear the child session and return to CMD:

```powershell
Remove-Item Env:DATABASE_URL
Remove-Variable credential, headers, plain, secret -ErrorAction SilentlyContinue
exit
```

The authorization flags are opt-in controls for a trusted database administrator,
not a replacement for database credentials, network access controls, TLS, or
review. Database owners can alter database names/designations; the tool cannot
protect against a malicious privileged administrator deliberately disguising
production as staging.

## Verification and scope

```sh
npm run test:isolated -- --check
npm audit --audit-level=high
npm run secrets:scan
```

Tests create a staging-named database **inside the same disposable local
PostgreSQL cluster** as the existing test database. Both use synthetic credentials
and are destroyed with the container. The runner verifies both databases have
two migrations and zero remaining operators, API keys, or payments. The CLI
itself always refuses `vaultx_pay_test`, development, and production database
names. Its `.env` loading is disabled; all configuration must be explicit.

Windows DPAPI invocation/error handling is covered by mocked process tests. The
full suite and POSIX delivery run on Linux; native Windows DPAPI/ACL behavior must
also be checked by a trusted administrator on their Windows machine before use.
No schema migrations, Render changes, real credentials, or real payments are part
of this task.
