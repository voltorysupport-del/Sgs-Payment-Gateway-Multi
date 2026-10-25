/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, process, Buffer */
const fs = require('node:fs'),
  path = require('node:path'),
  os = require('node:os'),
  crypto = require('node:crypto'),
  vm = require('node:vm'),
  assert = require('node:assert/strict');
const { execFileSync, execFile } = require('node:child_process');
const root = path.resolve(process.argv[2] || '');
assert.ok(process.argv[2]);
const tool = require(path.join(root, 'reconcile.js'));
const { readOnlyConfig } = require(path.join(root, 'status-check.js'));
let count = 0;
const op = '00000000-0000-4000-8000-000000000001',
  key = '00000000-0000-4000-8000-000000000002',
  other = '00000000-0000-4000-8000-000000000003';
const sensitive = 'SYNTHETIC-SENSITIVE-NOT-A-CREDENTIAL',
  verifier = crypto.createHash('sha256').update(sensitive).digest('hex');
function fixture() {
  return {
    snapshot: {
      operator: { id: op, expected_name: true, status: 'active' },
      keys: [{ id: key, operator_id: op, active: true, key_hash: verifier }],
      possibleIssuanceSessions: 0,
    },
    local: {
      delivery: {
        public: { exists: true, readable: true },
        value: { format: 'vaultx-dpapi-v1', operatorId: op, keyId: key, ciphertext: sensitive },
      },
      attempt: {
        public: { exists: true, readable: true },
        value: {
          result: 'ATTEMPT_STARTED_DO_NOT_RETRY',
          operatorCode: 'staging-e2e',
          database: 'vaultx_pay_staging',
          applicationCommit: '245752b6722a1a1d0f21d3a21a86564f29da25a2',
          startedAt: '2026-10-25T00:00:00.000Z',
          ignored: sensitive,
        },
      },
      receipt: {
        public: { exists: true, readable: true },
        value: {
          result: 'ISSUED_AND_METADATA_VERIFIED',
          operatorCode: 'staging-e2e',
          operatorId: op,
          keyId: key,
        },
      },
    },
    unsealed: { operatorId: op, keyId: key, verifier, validKeyShape: true, validEnvironment: true },
  };
}
function check(name, modify, verify) {
  const f = fixture();
  modify(f);
  const output = tool.summary(f.snapshot, f.local, f.unsealed);
  verify(output);
  const serialized = JSON.stringify(output);
  assert.ok(!serialized.includes(sensitive) && !serialized.includes(verifier));
  count++;
  process.stdout.write(`Evidence ${name}: PASS (public-only output).\n`);
}
function encryptSynthetic(payload) {
  return new Promise((resolve, reject) => {
    const script =
      "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security; [Console]::InputEncoding=[Text.UTF8Encoding]::new($false); $bytes=[Text.Encoding]::UTF8.GetBytes([Console]::In.ReadToEnd()); [Console]::Out.Write([Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)));";
    const child = execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { timeout: 15000, maxBuffer: 16384, windowsHide: true },
      (error, stdout) => (error ? reject(Error()) : resolve(stdout)),
    );
    child.stdin.on('error', () => reject(Error()));
    child.stdin.end(JSON.stringify(payload));
  });
}
(async () => {
  tool.verifyIntegrity();
  count++;
  check(
    'succeeded',
    () => {},
    (r) => assert.ok(r.recovery.usableActiveKey && r.files.receipt.matchesDatabase),
  );
  check(
    'failed-before-execution',
    (f) => {
      f.snapshot.operator = undefined;
      f.snapshot.keys = [];
      f.local = {
        delivery: { public: { exists: false } },
        attempt: { public: { exists: false } },
        receipt: { public: { exists: false } },
      };
      f.unsealed = null;
    },
    (r) => assert.ok(!r.operator.exists && !r.recovery.usableActiveKey && !r.files.attempt.exists),
  );
  check(
    'failed-after-COMMIT',
    (f) => {
      f.local.receipt = { public: { exists: false } };
    },
    (r) => assert.ok(r.recovery.usableActiveKey && !r.files.receipt.exists),
  );
  check(
    'delivered-before-rollback',
    (f) => {
      f.snapshot.operator = undefined;
      f.snapshot.keys = [];
      f.local.receipt = { public: { exists: false } };
    },
    (r) => assert.ok(r.recovery.dpapiDecryptsLocally && !r.recovery.usableActiveKey),
  );
  check(
    'incomplete-delivery',
    (f) => {
      f.local.delivery = { public: { exists: true, readable: true, validJson: false } };
      f.unsealed = null;
    },
    (r) => assert.ok(!r.recovery.usableActiveKey && r.files.delivery.validJson === false),
  );
  check(
    'missing-delivery',
    (f) => {
      f.local.delivery = { public: { exists: false } };
      f.unsealed = null;
    },
    (r) => assert.ok(!r.recovery.usableActiveKey && r.operator.exists),
  );
  check(
    'wrong-public-ID',
    (f) => {
      f.local.delivery.value.keyId = other;
    },
    (r) => assert.ok(!r.recovery.envelopeMatchesDatabase),
  );
  check(
    'wrong-decrypted-ID',
    (f) => {
      f.unsealed.keyId = other;
    },
    (r) => assert.ok(!r.recovery.usableActiveKey),
  );
  check(
    'wrong-verifier',
    (f) => {
      f.unsealed.verifier = '0'.repeat(64);
    },
    (r) => assert.ok(!r.recovery.verifierMatchesDatabase),
  );
  check(
    'revoked',
    (f) => {
      f.snapshot.keys[0].active = false;
    },
    (r) => assert.ok(r.recovery.verifierMatchesDatabase && !r.recovery.usableActiveKey),
  );
  check(
    'suspended',
    (f) => {
      f.snapshot.operator.status = 'suspended';
    },
    (r) => assert.ok(!r.recovery.usableActiveKey),
  );
  check(
    'wrong-operator-name',
    (f) => {
      f.snapshot.operator.expected_name = false;
    },
    (r) => assert.ok(!r.recovery.usableActiveKey),
  );
  check(
    'ongoing-operation',
    (f) => {
      f.snapshot.possibleIssuanceSessions = 1;
    },
    (r) =>
      assert.ok(
        r.result === 'STOP_POSSIBLE_OPERATION_STILL_RUNNING' && !r.recovery.usableActiveKey,
      ),
  );
  check(
    'invalid-payload',
    (f) => {
      f.unsealed.validKeyShape = false;
    },
    (r) => assert.ok(!r.recovery.usableActiveKey),
  );
  const config = await readOnlyConfig({
    approveReadOnly: true,
    expectedHost: 'external.example.invalid',
    expectedLogin: 'synthetic',
    databaseUrl:
      'postgres://synthetic:NOT-A-CREDENTIAL@external.example.invalid/vaultx_pay_staging?sslmode=verify-full',
  });
  assert.ok(config.ssl.rejectUnauthorized && config.ssl.servername === 'external.example.invalid');
  assert.match(config.options, /default_transaction_read_only=on/);
  count++;
  const queries = [];
  const client = {
    expectedUser: 'synthetic',
    async query(sql) {
      queries.push(sql);
      assert.match(sql.trim(), /^SELECT\b/);
      assert.doesNotMatch(sql, /\b(INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|COMMENT|pg_advisory)\b/i);
      if (sql.includes('current_database()=')) return { rowCount: 1, rows: [{ safe: true }] };
      if (sql.includes('FROM public.operators'))
        return { rowCount: 1, rows: [fixture().snapshot.operator] };
      if (sql.includes('FROM public.operator_api_keys')) return { rows: fixture().snapshot.keys };
      if (sql.includes('pg_stat_activity')) return { rows: [{ count: 0 }] };
      throw Error();
    },
  };
  assert.equal((await tool.readSnapshot(client)).keys.length, 1);
  assert.equal(queries.length, 4);
  count++;
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultx-reconcile-fixtures-'));
  try {
    const valid = path.join(temp, 'delivery.json');
    fs.writeFileSync(valid, JSON.stringify(fixture().local.delivery.value));
    const before = fs.readFileSync(valid);
    tool.inspect(valid);
    assert.ok(fs.readFileSync(valid).equals(before));
    count++;
    const partial = path.join(temp, 'partial.json');
    fs.writeFileSync(partial, '{');
    assert.equal(tool.inspect(partial).public.validJson, false);
    count++;
    assert.equal(tool.inspect(path.join(temp, 'absent')).public.exists, false);
    count++;
    const large = path.join(temp, 'large');
    fs.writeFileSync(large, 'x'.repeat(65537));
    assert.equal(tool.inspect(large).public.readable, false);
    count++;
    const altered = path.join(temp, 'altered');
    fs.cpSync(root, altered, { recursive: true });
    fs.appendFileSync(path.join(altered, 'README.txt'), '\n');
    assert.throws(() => require(path.join(altered, 'reconcile.js')).verifyIntegrity());
    count++;
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
  // Reproduce the ORIGINAL issuance launcher's diagnostic mapping; do not edit it.
  const original = execFileSync(
    'git',
    [
      'show',
      '01742b488c6307ef497e65539ff67640ef5b1c48:tools/staging-operator-issuance/launcher.js',
    ],
    { encoding: 'utf8' },
  );
  const handler = original.match(/child.once\('close', \(exitCode\) => \{([\s\S]*?)\n\s*\}\);/);
  assert.ok(handler);
  let mapped;
  vm.runInNewContext(`(function(exitCode){${handler[1]}})(2)`, {
    timer: null,
    clearTimeout() {},
    controller: { abort() {} },
    result: { result: 'STOP_BEFORE_ISSUANCE', attempted: false },
    resolve: (value) => {
      mapped = value;
    },
  });
  assert.equal(mapped.result, 'STOP_OUTCOME_UNVERIFIED_DO_NOT_RETRY');
  assert.ok(!Object.hasOwn(mapped, 'attempted'));
  count++;
  process.stdout.write(
    'Original diagnostic flaw REPRODUCED: pre-issuance STOP with attempted=false becomes generic unverified outcome; no original files changed.\n',
  );
  if (process.platform === 'win32') {
    const synthetic = {
      operatorId: op,
      keyId: key,
      environment: 'staging',
      apiKey: 'SYNTHETIC-NOT-A-VALID-API-KEY-\u20ac-\u03bb',
    };
    const sealed = await encryptSynthetic(synthetic),
      decoded = await tool.unsealVerifier(sealed);
    assert.ok(
      decoded.operatorId === op &&
        decoded.keyId === key &&
        decoded.validKeyShape === false &&
        decoded.validEnvironment === true,
    );
    assert.ok(
      decoded.verifier === crypto.createHash('sha256').update(synthetic.apiKey).digest('hex'),
    );
    assert.ok(!JSON.stringify(decoded).includes(synthetic.apiKey));
    count++;
    const bytes = Buffer.from(sealed, 'base64');
    bytes[bytes.length - 1] ^= 0xff;
    await assert.rejects(tool.unsealVerifier(bytes.toString('base64')));
    count++;
    await assert.rejects(tool.unsealVerifier('not a valid blob'));
    count++;
    process.stdout.write(
      'Native Windows DPAPI verifier-only UTF-8 recovery and tamper rejection: PASS; synthetic invalid credential only.\n',
    );
  } else process.stdout.write('SKIPPED: native DPAPI requires Windows, not claimed passed.\n');
  process.stdout.write(
    `${count} reconciliation checks passed. No Render/network/database connection, no original user files accessed.\n`,
  );
})().catch(() => {
  process.stderr.write('Reconciliation validation FAILED; sensitive details suppressed.\n');
  process.exitCode = 1;
});
