/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, process, module, __dirname, Buffer */
const fs = require('node:fs'),
  path = require('node:path'),
  crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
function publicId(value) {
  return typeof value === 'string' && UUID.test(value) ? value.toLowerCase() : null;
}
function inspect(file) {
  try {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536)
      return { public: { exists: true, readable: false }, hash: null };
    const bytes = fs.readFileSync(file),
      hash = crypto.createHash('sha256').update(bytes).digest('hex');
    try {
      return {
        public: { exists: true, readable: true },
        value: JSON.parse(bytes.toString('utf8')),
        hash,
      };
    } catch {
      return { public: { exists: true, readable: true, validJson: false }, hash };
    }
  } catch (error) {
    if (error.code === 'ENOENT') return { public: { exists: false }, hash: null };
    return { public: { exists: null, readable: false }, hash: null };
  }
}
function metadata(file, type) {
  const result = { ...file.public };
  const v = file.value;
  if (!v) return result;
  result.validJson = true;
  if (type === 'delivery') {
    result.dpapiEnvelope = v.format === 'vaultx-dpapi-v1';
    result.operatorId = publicId(v.operatorId);
    result.keyId = publicId(v.keyId);
  } else {
    result.expectedTarget = v.operatorCode === 'staging-e2e';
    result.expectedState =
      v.result ===
      (type === 'attempt' ? 'ATTEMPT_STARTED_DO_NOT_RETRY' : 'ISSUED_AND_METADATA_VERIFIED');
    if (type === 'attempt') {
      result.expectedDatabase = v.database === 'vaultx_pay_staging';
      result.expectedApplication =
        v.applicationCommit === '245752b6722a1a1d0f21d3a21a86564f29da25a2';
    } else {
      result.operatorId = publicId(v.operatorId);
      result.keyId = publicId(v.keyId);
    }
    const date = v.startedAt || v.verifiedAt;
    if (
      typeof date === 'string' &&
      /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(date) &&
      Number.isFinite(Date.parse(date))
    )
      result.timestamp = date;
  }
  return result;
}
function unsealVerifier(ciphertext) {
  return new Promise((resolve, reject) => {
    if (
      typeof ciphertext !== 'string' ||
      !/^[A-Za-z0-9+/]+=*$/.test(ciphertext) ||
      ciphertext.length > 65536
    ) {
      reject(Error());
      return;
    }
    // Plaintext never leaves this private child process: emit only a verifier and IDs
    // over a captured pipe, never inherited console output. Never log the verifier.
    const script = `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security;
    [Console]::InputEncoding=[Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);
    $bytes=[Convert]::FromBase64String([Console]::In.ReadToEnd());
    $plain=[Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);
    $record=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json;
    if($record.apiKey -isnot [string]){throw 'Invalid payload'};
    $validKeyShape=$record.apiKey -cmatch '^vxp_[a-f0-9]{64}$'; $validEnvironment=$record.environment -eq 'staging';
    $sha=[Security.Cryptography.SHA256]::Create();
    $verifier=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($record.apiKey))).Replace('-','').ToLowerInvariant();
    [Console]::Out.Write((@{operatorId=$record.operatorId;keyId=$record.keyId;verifier=$verifier;validKeyShape=$validKeyShape;validEnvironment=$validEnvironment}|ConvertTo-Json -Compress));`;
    const child = execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { windowsHide: true, timeout: 15000, maxBuffer: 16384 },
      (error, stdout) => {
        if (error) {
          reject(Error());
          return;
        }
        try {
          resolve(JSON.parse(stdout));
        } catch {
          reject(Error());
        }
      },
    );
    child.stdin.on('error', () => reject(Error()));
    child.stdin.end(ciphertext);
  });
}
function sameVerifier(a, b) {
  return (
    typeof a === 'string' &&
    typeof b === 'string' &&
    /^[a-f0-9]{64}$/.test(a) &&
    /^[a-f0-9]{64}$/.test(b) &&
    crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'))
  );
}
async function readSnapshot(client) {
  const identity = await client.query(
    `SELECT current_database()='vaultx_pay_staging' AND session_user=$1
    AND current_setting('transaction_read_only')='on'
    AND current_setting('server_version_num')::int>=170000 AND current_setting('server_version_num')::int<180000
    AND pg_catalog.shobj_description(oid,'pg_database')='vaultx-pay:staging' AS safe
    FROM pg_catalog.pg_database WHERE datname=current_database()`,
    [client.expectedUser],
  );
  if (identity.rowCount !== 1 || identity.rows[0]?.safe !== true) throw Error();
  const operators = await client.query(
    'SELECT id, name=$2 AS expected_name, status FROM public.operators WHERE code=$1',
    ['staging-e2e', 'VaultX Pay Staging Test Operator'],
  );
  if (operators.rowCount > 1) throw Error();
  const operator = operators.rows[0];
  const keys = operator
    ? await client.query(
        'SELECT id, operator_id, revoked_at IS NULL AS active, key_hash FROM public.operator_api_keys WHERE operator_id=$1',
        [operator.id],
      )
    : { rows: [] };
  const active = await client.query(
    "SELECT count(*)::int AS count FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND usename=session_user AND application_name='vaultx-staging-provisioning' AND pid<>pg_backend_pid()",
  );
  return { operator, keys: keys.rows, possibleIssuanceSessions: active.rows[0].count };
}
function summary(snapshot, local, unsealed) {
  const op = snapshot.operator;
  const result = {
    result:
      snapshot.possibleIssuanceSessions > 0
        ? 'STOP_POSSIBLE_OPERATION_STILL_RUNNING'
        : 'READ_ONLY_RECONCILIATION_NO_RETRY',
    possibleIssuanceSessions: snapshot.possibleIssuanceSessions,
    operator: op
      ? {
          exists: true,
          id: publicId(op.id),
          expectedName: op.expected_name === true,
          status: ['active', 'suspended'].includes(op.status) ? op.status : 'unexpected',
        }
      : { exists: false },
    keys: snapshot.keys.map((k) => ({ keyId: publicId(k.id), active: k.active === true })),
    files: {
      delivery: metadata(local.delivery, 'delivery'),
      attempt: metadata(local.attempt, 'attempt'),
      receipt: metadata(local.receipt, 'receipt'),
    },
    recovery: {
      dpapiDecryptsLocally: !!unsealed,
      envelopeMatchesDatabase: false,
      decryptedIdsMatchEnvelope: false,
      verifierMatchesDatabase: false,
      usableActiveKey: false,
    },
  };
  const envelope = local.delivery.value;
  result.files.receipt.matchesDatabase = !!(
    op &&
    publicId(op.id) &&
    publicId(local.receipt.value?.operatorId) === publicId(op.id) &&
    snapshot.keys.some(
      (k) => publicId(k.id) && publicId(k.id) === publicId(local.receipt.value?.keyId),
    )
  );
  const matching = snapshot.keys.find(
    (k) => publicId(k.id) && publicId(k.id) === publicId(envelope?.keyId),
  );
  result.recovery.envelopeMatchesDatabase = !!(
    op &&
    publicId(op.id) &&
    publicId(op.id) === publicId(envelope?.operatorId) &&
    matching
  );
  if (unsealed) {
    result.recovery.validKeyShape = unsealed.validKeyShape === true;
    result.recovery.validEnvironment = unsealed.validEnvironment === true;
    result.recovery.decryptedIdsMatchEnvelope = !!(
      publicId(unsealed.operatorId) &&
      publicId(unsealed.keyId) &&
      publicId(unsealed.operatorId) === publicId(envelope?.operatorId) &&
      publicId(unsealed.keyId) === publicId(envelope?.keyId)
    );
    result.recovery.verifierMatchesDatabase = !!(
      matching && sameVerifier(unsealed.verifier, matching.key_hash)
    );
    result.recovery.usableActiveKey =
      unsealed.validKeyShape === true &&
      unsealed.validEnvironment === true &&
      snapshot.possibleIssuanceSessions === 0 &&
      result.recovery.envelopeMatchesDatabase &&
      result.recovery.decryptedIdsMatchEnvelope &&
      result.recovery.verifierMatchesDatabase &&
      matching.active === true &&
      op.status === 'active' &&
      op.expected_name === true;
  }
  const active = snapshot.keys.some((row) => row.active === true);
  result.interpretation =
    snapshot.possibleIssuanceSessions > 0
      ? 'OPERATION_MAY_STILL_BE_RUNNING'
      : result.recovery.usableActiveKey
        ? result.files.receipt.matchesDatabase && result.files.receipt.expectedState
          ? 'COMMITTED_RECOVERABLE_RECEIPT_PRESENT'
          : 'COMMITTED_RECOVERABLE_NO_VERIFIED_RECEIPT'
        : op && active
          ? 'ACTIVE_KEY_OBSERVED_RECOVERY_NOT_VERIFIED'
          : !op
            ? local.delivery.public.exists === true
              ? 'DELIVERY_WITHOUT_COMMITTED_OPERATOR_OBSERVED'
              : 'NO_COMMITTED_OPERATOR_OBSERVED'
            : 'OPERATOR_WITHOUT_ACTIVE_KEY_OBSERVED';
  return result;
}
function compareEvidence(before, after) {
  const entries = Object.keys(before);
  if (
    entries.some(
      (k) =>
        before[k].public.exists === null ||
        after[k].public.exists === null ||
        before[k].public.readable === false ||
        after[k].public.readable === false,
    )
  )
    return null;
  return entries.every(
    (k) => before[k].hash === after[k].hash && before[k].public.exists === after[k].public.exists,
  );
}
function verifyIntegrity() {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'SHA256SUMS.json'), 'utf8'));
  for (const name of [
    'reconcile.js',
    'console-input.js',
    'status-check.js',
    'Start-Reconciliation.cmd',
    'README.txt',
    'node_modules/pg/package.json',
  ])
    if (!Object.hasOwn(manifest, name)) throw Error();
  function walk(folder) {
    for (const entry of fs.readdirSync(folder)) {
      const file = path.join(folder, entry),
        stat = fs.lstatSync(file);
      if (stat.isSymbolicLink()) throw Error();
      if (stat.isDirectory()) walk(file);
      else {
        const name = path.relative(__dirname, file).split(path.sep).join('/');
        if (name === 'SHA256SUMS.json') continue;
        if (
          !Object.hasOwn(manifest, name) ||
          crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') !== manifest[name]
        )
          throw Error();
        seen.add(name);
      }
    }
  }
  const seen = new Set();
  walk(__dirname);
  if (seen.size !== Object.keys(manifest).length) throw Error();
}
async function main() {
  verifyIntegrity();
  if (process.argv.length !== 2) throw Error();
  if (
    process.platform !== 'win32' ||
    process.versions.node.split('.')[0] !== '24' ||
    [
      'NODE_OPTIONS',
      'NODE_DEBUG',
      'NODE_DEBUG_NATIVE',
      'NODE_TLS_REJECT_UNAUTHORIZED',
      'NODE_PG_FORCE_NATIVE',
    ].some((k) => process.env[k])
  )
    throw Error();
  const { readHiddenLine } = require('./console-input.js');
  if (
    (await readHiddenLine(
      'After separate approval only: type RECONCILE READONLY (no writes): ',
    )) !== 'RECONCILE READONLY'
  )
    throw Error();
  const root = fs.realpathSync(process.env.LOCALAPPDATA),
    directory = path.join(root, 'VaultXPay', 'Secrets');
  // Missing evidence directories are reported as absent; never create them.
  let current = root;
  for (const component of ['VaultXPay', 'Secrets']) {
    current = path.join(current, component);
    try {
      const stat = fs.lstatSync(current);
      if (
        !stat.isDirectory() ||
        stat.isSymbolicLink() ||
        fs.realpathSync(current).toLowerCase() !== current.toLowerCase()
      )
        throw Error();
    } catch (error) {
      if (error.code === 'ENOENT') break;
      throw error;
    }
  }
  const destination = path.join(directory, 'initial.vaultx-key.json');
  const names = {
    delivery: destination,
    attempt: destination + '.issuance-attempt.json',
    receipt: destination + '.issuance-result.json',
  };
  const local = Object.fromEntries(Object.entries(names).map(([k, v]) => [k, inspect(v)]));
  let unsealed = null;
  if (local.delivery.value?.format === 'vaultx-dpapi-v1')
    try {
      unsealed = await unsealVerifier(local.delivery.value.ciphertext);
    } catch {
      /* Report false, never error details. */
    }
  const input = {
    approveReadOnly: true,
    expectedHost: await readHiddenLine('Verified full external hostname (hidden): '),
    expectedLogin: await readHiddenLine('Verified session login (hidden): '),
    databaseUrl: await readHiddenLine('Private external URL (hidden): '),
  };
  const { readOnlyConfig } = require('./status-check.js');
  const config = await readOnlyConfig(input);
  input.databaseUrl = '';
  config.application_name = 'vaultx-readonly-reconciliation';
  const { Pool } = require('pg');
  const pool = new Pool(config);
  let failed = false;
  pool.on('error', () => {
    failed = true;
  });
  let client;
  try {
    client = await pool.connect();
    client.on('error', () => {
      failed = true;
    });
    const { verifyStagingTarget } = await import(
      pathToFileURL(path.join(__dirname, 'pinned-app/dist/admin/staging-operator.js')).href
    );
    await verifyStagingTarget(client, String(config.user));
    await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    client.expectedUser = String(config.user);
    const snapshot = await readSnapshot(client);
    await client.query('ROLLBACK');
    const output = summary(snapshot, local, unsealed);
    const after = Object.fromEntries(
      Object.entries(names).map(([key, file]) => [key, inspect(file)]),
    );
    output.localFilesStable = compareEvidence(local, after);
    if (output.localFilesStable !== true) {
      output.result =
        output.localFilesStable === null
          ? 'STOP_LOCAL_EVIDENCE_UNREADABLE'
          : 'STOP_LOCAL_EVIDENCE_CHANGED';
      output.interpretation = 'EVIDENCE_CHANGED_DURING_CHECK';
      output.recovery.usableActiveKey = false;
    }
    if (failed) throw Error();
    if (unsealed) unsealed.verifier = '';
    unsealed = null;
    process.stdout.write(JSON.stringify(output, null, 2) + '\n');
  } finally {
    if (client) {
      await client.query('ROLLBACK').catch(() => {});
      client.release();
    }
    await pool.end();
  }
}
if (require.main === module)
  main().catch(() => {
    process.stderr.write(
      'STOP: reconciliation incomplete. Details suppressed. Preserve files; no retry or repair.\n',
    );
    process.exitCode = 2;
  });
module.exports = {
  inspect,
  metadata,
  summary,
  sameVerifier,
  readSnapshot,
  unsealVerifier,
  verifyIntegrity,
  compareEvidence,
};
