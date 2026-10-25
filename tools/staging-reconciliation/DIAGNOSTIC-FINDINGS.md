The original launcher at commit `01742b488c6307ef497e65539ff67640ef5b1c48`
collapses worker outcomes in its child `close` handler. Success is retained only
with exit code zero; cancellation is retained; everything else becomes a fresh
`STOP_OUTCOME_UNVERIFIED_DO_NOT_RETRY` object. This drops `attempted: false` and a
more specific `STOP_BEFORE_ISSUANCE` result. The worker's top-level error handler
also emits the generic outcome for failures before its invocation controller.

The validation reproduces the original close-handler code directly from its Git
object, without editing the original package, invoking issuance or opening a DB.
It demonstrates ambiguity in the message, not the cause of the real failed run.

Possible earlier failures include configuration/TLS/login/marker checks, missing or
existing delivery/attempt paths, confirmation expiry and connection errors. After
an attempt record is flushed, failure can occur before the CLI runs, during its
transaction/DPAPI delivery, after COMMIT during metadata/envelope verification,
during public receipt creation, or during child reporting/cleanup. Do not assume
any generic failure means rollback. A valid receipt matching DB/file narrows the
failure toward reporting/cleanup; committed matching delivery without a receipt
narrows it toward post-COMMIT verification/receipt failure. Incomplete/missing or
stale evidence prevents a definitive classification.

The pinned CLI flushes encrypted delivery before COMMIT. Therefore a committed
active key with no usable local delivery requires review of the original Windows
profile/path, approved backups, security/quarantine evidence or later changes.
No deletion, retry, rotation, revocation, quarantine restoration, policy change or
other remediation is performed or authorized by this reconciliation package.
