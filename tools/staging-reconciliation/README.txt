Read-only VaultX Pay issuance reconciliation
Publication/testing approved; actual Render/laptop reconciliation requires separate approval.

Do not run issuance again or delete/rename/move/unblock/overwrite any encrypted
file, attempt record or receipt. Do not upload the Secrets folder or its files.
The original invocation must have finished before interpreting absence as final.
Use the SAME original Windows account/profile and laptop for DPAPI recovery.

After separate publication/Windows-validation approval, then separate read-only
Render-access approval, extract the complete ZIP and use Start-Reconciliation.cmd.
Node.js 24 required. No SQL, Git, environment setup, builds or .ps1 files required.
All answers are hidden. Supply verified external host/login/URL privately.
No provisioning, rotation, revocation, payment or schema/marker repair exists here.

No intended directory, key file, attempt, receipt or report file is created/written.
Only existing default files are read, with symlink/size checks. Missing/partial/
unreadable files are reported. Only UUIDs, validated timestamps, fixed-state/target
matches and booleans are displayed. Ciphertext and arbitrary file contents are not.

Private DPAPI decryption occurs locally under CurrentUser through an inline command;
no execution-policy bypass/elevation/Unblock-File is provided. Raw plaintext stays
inside the captured child process. A SHA256 verifier is compared in Node memory to
the database verifier. Neither verifier, raw key, decrypted credential nor errors
are printed/saved/uploaded. A matching verifier plus matching IDs and an active
operator/key establishes local recoverability without sending a payment or using
the raw key against an HTTP service. DPAPI failure is not proof of permanent loss:
wrong Windows profile, damaged file, policy or missing master keys can cause it.

The Render session uses the pinned 245752b guards, verified TLS, read-only session
options, repeatable-read READ ONLY transaction and rollback. It reads operator/
key public metadata plus the private verifier for in-memory comparison only.
It also counts same-login provisioning sessions; a nonzero count makes final
interpretation unsafe. Local file digests before/after detect concurrent changes.
Missing/no-match/unreadable is not permission to retry or rotate.

Evidence guide:
- Receipt matching DB/file plus recoverable active key: committed and verified;
  investigate only reporting/cleanup/IPC failure; never issue again.
- Delivery matching committed active key but no receipt: committed, verification
  or receipt step interrupted/failed. Preserve files and use existing key privately.
- Delivery exists but no matching committed row: possible rollback after delivery,
  unfinished operation, wrong snapshot/profile or subsequent external change.
- Active row with missing/unreadable delivery: key exists; raw secret is not
  recoverable from its DB hash. Check the original authorized profile/approved
  backup/security-quarantine evidence; any remediation needs separate approval.
- Attempt record means only that the invocation boundary was recorded, not that
  CLI execution or COMMIT succeeded. Its absence does not globally prove no issuance.

A malicious/compromised endpoint/clipboard/process dump is outside this tool's
protection. Stop if corporate controls block Node/CMD/DPAPI; do not weaken policy.
Windows CI validates only synthetic fixtures. It is not proof of recovery of your
actual file or of real staging database state. Publication and tests never connect
to Render or access your laptop. Approval for actual reconciliation is separate.
