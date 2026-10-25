/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, module */
const fs = require('node:fs'),
  crypto = require('node:crypto');
const CONFIRM = 'ISSUE STAGING-E2E ONCE';
function files(destination) {
  return {
    attempt: destination + '.issuance-attempt.json',
    receipt: destination + '.issuance-result.json',
  };
}
function assertAbsent(destination) {
  for (const file of [destination, ...Object.values(files(destination))]) {
    try {
      fs.lstatSync(file);
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      throw error;
    }
    throw new Error('Existing delivery or single-use record.');
  }
}
function writeExclusive(file, value) {
  const descriptor = fs.openSync(file, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, JSON.stringify(value, null, 2) + '\n');
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}
function validateMetadata(value) {
  const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
  if (
    value?.action !== 'issued' ||
    value.operatorCode !== 'staging-e2e' ||
    !uuid.test(value.operatorId) ||
    !uuid.test(value.keyId) ||
    !Array.isArray(value.keys) ||
    value.keys.length !== 1 ||
    value.keys[0].keyId !== value.keyId ||
    value.keys[0].revokedAt !== null
  )
    throw Error();
  return { operatorId: value.operatorId, keyId: value.keyId, operatorCode: 'staging-e2e' };
}
function verifyEnvelope(destination, metadata) {
  const stat = fs.lstatSync(destination);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536) throw Error();
  const text = fs.readFileSync(destination, 'utf8');
  const envelope = JSON.parse(text);
  if (
    envelope.format !== 'vaultx-dpapi-v1' ||
    envelope.operatorId !== metadata.operatorId ||
    envelope.keyId !== metadata.keyId ||
    typeof envelope.ciphertext !== 'string' ||
    !/^[A-Za-z0-9+/]+=*$/.test(envelope.ciphertext) ||
    Object.keys(envelope).sort().join(',') !== 'ciphertext,format,keyId,operatorId'
  )
    throw Error();
  return crypto.createHash('sha256').update(text).digest('hex');
}
async function executeOnce({
  destination,
  precheck,
  confirm,
  invoke,
  verify,
  onAttempt = () => {},
}) {
  let attempted = false;
  try {
    assertAbsent(destination);
    await precheck();
    if ((await confirm()) !== CONFIRM)
      return { result: 'CANCELLED_BEFORE_ISSUANCE', attempted: false };
    // No further questions. Recheck absence/identity immediately before invocation.
    assertAbsent(destination);
    await precheck();
    assertAbsent(destination);
    writeExclusive(files(destination).attempt, {
      result: 'ATTEMPT_STARTED_DO_NOT_RETRY',
      operatorCode: 'staging-e2e',
      database: 'vaultx_pay_staging',
      applicationCommit: '245752b6722a1a1d0f21d3a21a86564f29da25a2',
      startedAt: new Date().toISOString(),
    });
    attempted = true;
    onAttempt();
    // Exactly one CLI call in a normal confirmed run. Never loop or retry.
    const metadata = validateMetadata(
      await invoke(['ensure', '--operator-code', 'staging-e2e', '--key-file', destination]),
    );
    const envelopeDigest = verifyEnvelope(destination, metadata);
    await verify(metadata);
    if (verifyEnvelope(destination, metadata) !== envelopeDigest) throw Error();
    const result = {
      result: 'ISSUED_AND_METADATA_VERIFIED',
      ...metadata,
      verifiedAt: new Date().toISOString(),
    };
    writeExclusive(files(destination).receipt, result);
    return result;
  } catch {
    // Even a definite failure consumes the attempt once its record exists.
    const recordExists = fs.existsSync(files(destination).attempt);
    return {
      result:
        attempted || recordExists ? 'STOP_OUTCOME_UNVERIFIED_DO_NOT_RETRY' : 'STOP_BEFORE_ISSUANCE',
      attempted: attempted || recordExists,
    };
  }
}
module.exports = { CONFIRM, files, assertAbsent, executeOnce, validateMetadata, verifyEnvelope };
