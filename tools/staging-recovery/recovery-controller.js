/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, module */
// Execution requires separately approved, evidence-linked recovery-01 authorization.
const fs = require('node:fs'),
  crypto = require('node:crypto');
const { publicOutcome } = require('./diagnostics.js');
const PHRASE = 'AUTHORIZE RECOVERY-01 FOR STAGING-E2E';
function originalEvidence(destination, approvedHash) {
  const original = destination + '.issuance-attempt.json';
  const stat = fs.lstatSync(original);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16384) throw Error();
  const bytes = fs.readFileSync(original),
    digest = crypto.createHash('sha256').update(bytes).digest('hex');
  if (!/^[a-f0-9]{64}$/.test(approvedHash) || digest !== approvedHash) throw Error();
  const v = JSON.parse(bytes.toString('utf8'));
  if (
    v.result !== 'ATTEMPT_STARTED_DO_NOT_RETRY' ||
    v.operatorCode !== 'staging-e2e' ||
    v.database !== 'vaultx_pay_staging' ||
    v.applicationCommit !== '245752b6722a1a1d0f21d3a21a86564f29da25a2' ||
    v.startedAt !== '2026-10-25T15:08:36.036Z'
  )
    throw Error();
  return digest;
}
function absent(file) {
  try {
    fs.lstatSync(file);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  throw Error();
}
async function recoverOnce({
  destination,
  approvedOriginalHash,
  readOnlyCheck,
  confirm,
  beforeCli = () => {},
  invokePinnedCli,
  verifyIssued,
}) {
  const journal = destination + '.recovery-01.attempt.jsonl',
    receipt = destination + '.recovery-01.result.json';
  let descriptor,
    phase = 'ORIGINAL_EVIDENCE_VALIDATED',
    attempted = false,
    cliStatus,
    reason;
  function record(value) {
    fs.writeSync(descriptor, JSON.stringify(value) + '\n');
    fs.fsyncSync(descriptor);
  }
  async function check() {
    originalEvidence(destination, approvedOriginalHash);
    for (const file of [destination, destination + '.issuance-result.json', journal, receipt])
      absent(file);
    const result = await readOnlyCheck();
    if (
      result.identityVerified !== true ||
      result.tlsVerified !== true ||
      result.operatorAbsent !== true ||
      result.keysAbsent !== true ||
      result.possibleIssuanceSessions !== 0
    )
      throw Error();
  }
  try {
    await check();
    phase = 'READ_ONLY_CHECKED';
    if ((await confirm(PHRASE)) !== PHRASE) {
      reason = 'CONFIRMATION_CANCELLED';
      throw Error();
    }
    phase = 'CONFIRMED';
    await check();
    descriptor = fs.openSync(journal, 'wx', 0o600);
    record({
      phase: 'RECOVERY_RECORDED',
      recoveryId: 'recovery-01',
      priorAttemptSHA256: approvedOriginalHash,
      priorAttemptTimestamp: '2026-10-25T15:08:36.036Z',
      operatorCode: 'staging-e2e',
      database: 'vaultx_pay_staging',
    });
    phase = 'RECOVERY_RECORDED';
    // The original marker is a mandatory precondition, not removed or ignored.
    originalEvidence(destination, approvedOriginalHash);
    try {
      await beforeCli();
    } catch {
      reason = 'WORKER_NOT_READY_BEFORE_CLI';
      throw Error();
    }
    phase = 'CLI_CALL_STARTED';
    record({ phase });
    attempted = true;
    let response;
    try {
      response = await invokePinnedCli([
        'ensure',
        '--operator-code',
        'staging-e2e',
        '--key-file',
        destination,
      ]);
    } catch {
      reason = 'CLI_EXCEPTION';
      throw Error();
    }
    cliStatus = response.status;
    reason = response.reason;
    if (cliStatus !== 0) {
      phase = 'CLI_RETURNED_FAILURE';
      record(publicOutcome({ phase, attempted, cliStatus, reason }));
      throw Error();
    }
    phase = 'CLI_RETURNED_SUCCESS';
    record({ phase, cliStatus });
    // Adapter must reuse strict metadata/DPAPI-envelope and read-only DB verification.
    let verified;
    try {
      verified = await verifyIssued(response.metadata);
    } catch {
      reason = 'POST_CLI_VERIFICATION_FAILED';
      throw Error();
    }
    if (verified !== true) {
      reason = 'POST_CLI_VERIFICATION_FAILED';
      throw Error();
    }
    originalEvidence(destination, approvedOriginalHash);
    phase = 'METADATA_VERIFIED';
    record({ phase });
    const metadata = require('./issuer.js').validateMetadata(response.metadata);
    const fd = fs.openSync(receipt, 'wx', 0o600);
    try {
      fs.writeFileSync(
        fd,
        JSON.stringify({
          recoveryId: 'recovery-01',
          result: 'RECOVERY_VERIFIED',
          priorAttemptSHA256: approvedOriginalHash,
          ...metadata,
        }) + '\n',
      );
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    phase = 'RECEIPT_WRITTEN';
    record({ phase });
    return {
      ...publicOutcome({ phase, attempted, cliStatus, result: 'RECOVERY_VERIFIED' }),
      ...metadata,
    };
  } catch {
    const outcome = publicOutcome({ phase, attempted, cliStatus, reason });
    if (descriptor !== undefined)
      try {
        record(outcome);
      } catch {
        /* Never retry issuance to repair diagnostics. */
      }
    return outcome;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}
function captureOriginal(destination) {
  const stat = fs.lstatSync(destination + '.issuance-attempt.json');
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16384) throw Error();
  const bytes = fs.readFileSync(destination + '.issuance-attempt.json');
  const hash = crypto.createHash('sha256').update(bytes).digest('hex');
  originalEvidence(destination, hash);
  return hash;
}
module.exports = { captureOriginal, originalEvidence, recoverOnce, PHRASE };
