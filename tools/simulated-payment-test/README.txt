VaultX Pay FIRST SIMULATED PAYMENT - SEPARATE EXECUTION APPROVAL REQUIRED
API contract reviewed at commit 245752b. Existing staging-e2e key only.

After separate approval, extract the complete Windows ZIP and double-click
Start-Simulated-Payment.cmd. Node.js 24 required. Use the SAME Windows account/laptop
that owns the existing DPAPI key. No build, Git, SQL, environment setup, API-key
provisioning/rotation/revocation or .ps1 script execution is needed.

Provide the independently verified staging app HTTPS origin (...onrender.com), NOT
a PostgreSQL URL. The package reads %LOCALAPPDATA%\VaultXPay\Secrets\initial.vaultx-key.json
without changing it. DPAPI plaintext is captured through a private pipe, used in
memory as an Authorization header, never printed, saved, passed as argv or stored
in environment variables. Never upload the encrypted file or decrypted credentials.
No database credential is needed. No key/attempt/receipt file is overwritten.

All prompts are hidden. READONLY permits health/authentication checks. The final
phrase RUN ONE SIMULATED PAYMENT permits one amountMinor=100 EUR simulator payment.
The test checks unauthenticated 401, authenticated 404 for a fresh nonexistent UUID,
creates a pending payment, replays the same idempotency key to require the same ID,
retrieves pending state, simulates succeeded, and retrieves persisted succeeded state.
Retrieval uses the existing DB-backed API; no direct PostgreSQL connection is made.

Server environment is NOT changed. You must confirm the approved deployment still
uses reviewed simulator-only code with LIVE_MODE_ENABLED=false. /health's false
flag is checked but is not independent attestation of deployed environment/code.
The client rejects any non-simulator payment response. No real provider integration
or payment credentials are packaged. The client cannot make an untrusted server safe.

TLS chain/hostname verification and TLS1.2+ are mandatory; HTTPS Render origins only,
no URL credentials, paths/query/fragments, custom domains or numeric IP substitutions.
No redirects, retries, proxy fallback, certificate bypass, elevated execution or
security-policy changes are offered. Authentication never follows a redirect.
Stop for approved IT help if Node/CMD/DPAPI/network access is blocked by policy.

Before the first payment write, a NEW exclusive nonsecret journal is flushed:
%LOCALAPPDATA%\VaultXPay\SimulatedTests\first-simulated-payment.attempt.jsonl
It contains target origin, public IDs, idempotency nonce, amount/currency and stages,
never the key. Existing journal stops further writes. Cancellation before consent
creates no journal/payment. A network error after POST is not proof of rollback.
Preserve the journal and any displayed payment ID; do not blindly rerun, use a new
idempotency key or delete files. No payment cleanup/cancellation is automated.

One simulated record remains in PostgreSQL, no real money moves. Only success is
performed in the first real smoke test; failure scenarios are tested offline.
Automated validation uses synthetic transport/DPAPI fixtures, never staging. Native
DPAPI validation and downloadable artifact publication require their own approval.
No claimed Windows result should be inferred from a Linux skip.

Health connectivity diagnostics
Only unauthenticated GET /health permits 120 seconds socket inactivity and a
150-second overall deadline for Render cold starts. All other deadlines remain
15/30 seconds. No request is automatically retried. Error categories contain no
raw network messages. DNS, TLS_CERTIFICATE, TLS_HANDSHAKE, CONNECTION_POLICY,
CONNECTION_REFUSED, CONNECTION_RESET, CONNECT_TIMEOUT, SOCKET_IDLE_TIMEOUT and
REQUEST_DEADLINE distinguish common causes without proving a specific cause.
This direct HTTPS client does not inherit browser/system proxy settings; a
corporate proxy or trust-store difference may require administrator diagnosis.
Never disable TLS verification or corporate security controls to resolve it.
A failed HEALTH check creates no payment journal. Any pre-existing journal
remains protected and must never be removed or bypassed. A new real staging
execution requires separate approval even when writesAttempted was false.
