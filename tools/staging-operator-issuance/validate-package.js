/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, process, structuredClone */
const fs = require('node:fs'),
  path = require('node:path'),
  os = require('node:os'),
  assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process'),
  { pathToFileURL } = require('node:url');
const directory = path.resolve(process.argv[2] || '');
assert.ok(process.argv[2]);
const { verifyPackage } = require(path.join(directory, 'launcher.js'));
const { readOnlyConfig, readOnlyStatus } = require(path.join(directory, 'status-check.js'));
const { checkDeliveryPath } = require(path.join(directory, 'delivery-path.js'));
let checks = 0;
const input = {
  approveReadOnly: true,
  expectedHost: 'external.example.invalid',
  expectedLogin: 'synthetic_login',
  databaseUrl:
    'postgres://synthetic_login:NOT-A-CREDENTIAL@external.example.invalid/vaultx_pay_staging?sslmode=verify-full',
};
async function statusTest(mode) {
  const queries = [];
  let released = false;
  const client = {
    on() {},
    release() {
      released = true;
    },
    async query(sql, args) {
      queries.push(sql);
      assert.match(
        sql.trim(),
        /^(BEGIN READ ONLY|BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY|SELECT|ROLLBACK)\b/,
      );
      assert.doesNotMatch(
        sql,
        /\b(?:INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|COMMENT|FOR\s+UPDATE|pg_advisory)\b/i,
      );
      if (sql.startsWith('BEGIN') || sql === 'ROLLBACK') return {};
      if (sql.includes('current_database()'))
        return { rowCount: 1, rows: [{ safe: mode !== 'bad-identity' }] };
      if (sql.startsWith('SELECT id, name')) {
        assert.equal(args[0], 'staging-e2e');
        if (mode === 'absent') return { rowCount: 0, rows: [] };
        return {
          rowCount: mode === 'duplicate' ? 2 : 1,
          rows: [
            {
              id: '00000000-0000-4000-8000-000000000001',
              expected_identity: mode !== 'wrong-name',
              status: mode === 'suspended' ? 'suspended' : 'active',
            },
          ],
        };
      }
      if (sql.startsWith('SELECT id, revoked_at')) {
        if (mode === 'query-failure') throw new Error('Synthetic-sensitive-error');
        return { rows: [{ id: '00000000-0000-4000-8000-000000000002', active: true }] };
      }
      throw Error('Unexpected query');
    },
  };
  const { verifyStagingTarget } = await import(
    pathToFileURL(path.join(directory, 'pinned-app/dist/admin/staging-operator.js')).href
  );
  const pool = {
    async connect() {
      return client;
    },
  };
  if (['bad-identity', 'query-failure', 'duplicate'].includes(mode))
    await assert.rejects(readOnlyStatus(pool, verifyStagingTarget, input.expectedLogin));
  else {
    const result = await readOnlyStatus(pool, verifyStagingTarget, input.expectedLogin);
    assert.equal(result.provisioned, false);
    assert.equal(
      result.result,
      mode === 'absent'
        ? 'READY_FOR_SEPARATE_PROVISIONING_APPROVAL'
        : mode === 'existing'
          ? 'STOP_OPERATOR_ALREADY_EXISTS'
          : 'STOP_EXISTING_OPERATOR_REQUIRES_REVIEW',
    );
    assert.ok(!JSON.stringify(result).includes('NOT-A-CREDENTIAL'));
  }
  assert.ok(released && queries.includes('ROLLBACK'));
  checks++;
  process.stdout.write(
    `Read-only status ${mode}: expected result, no write/lock SQL, rollback and pinned identity checks passed.\n`,
  );
}
async function issuanceControllerTests() {
  const { executeOnce, CONFIRM, files } = require(path.join(directory, 'issuer.js'));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultx-single-use-tests-'));
  const ids = {
    operatorId: '00000000-0000-4000-8000-000000000001',
    keyId: '00000000-0000-4000-8000-000000000002',
  };
  const fixture = {
    action: 'issued',
    operatorCode: 'staging-e2e',
    ...ids,
    keys: [{ keyId: ids.keyId, revokedAt: null }],
  };
  function dependencies(destination, mode) {
    const calls = { precheck: 0, confirm: 0, invoke: 0, verify: 0, attempt: 0 };
    return {
      calls,
      settings: {
        destination,
        precheck: async () => {
          calls.precheck++;
          if (
            mode === 'existing' ||
            (mode === 'changed-after-confirmation' && calls.precheck === 2)
          )
            throw Error();
        },
        confirm: async () => {
          calls.confirm++;
          return mode === 'cancel' ? '' : mode === 'wrong-phrase' ? 'ISSUE SOMETHING' : CONFIRM;
        },
        onAttempt: () => {
          calls.attempt++;
          assert.ok(fs.existsSync(files(destination).attempt));
        },
        invoke: async (args) => {
          calls.invoke++;
          assert.deepEqual(args, [
            'ensure',
            '--operator-code',
            'staging-e2e',
            '--key-file',
            destination,
          ]);
          assert.equal(calls.confirm, 1);
          assert.equal(calls.precheck, 2);
          assert.equal(calls.attempt, 1);
          if (mode === 'cli-failure') throw Error();
          if (mode === 'unchanged') return { ...fixture, action: 'unchanged' };
          fs.writeFileSync(
            destination,
            JSON.stringify({
              format: 'vaultx-dpapi-v1',
              ...ids,
              ciphertext: 'U1lOVEhFVElDLU5PVC1BLUtFWQ==',
            }),
            { flag: 'wx' },
          );
          if (mode === 'wrong-metadata') return { ...fixture, keyId: 'invalid' };
          if (mode === 'wrong-envelope')
            fs.writeFileSync(
              destination,
              JSON.stringify({ format: 'plaintext', ...ids, apiKey: 'SYNTHETIC-NOT-A-KEY' }),
            );
          return structuredClone(fixture);
        },
        verify: async () => {
          calls.verify++;
          if (mode === 'postcheck-failure') throw Error();
          if (mode === 'file-changed-after-check') {
            const changed = JSON.parse(fs.readFileSync(destination, 'utf8'));
            changed.ciphertext = 'Q0hBTkdFRA==';
            fs.writeFileSync(destination, JSON.stringify(changed));
          }
          if (mode === 'receipt-race')
            fs.writeFileSync(files(destination).receipt, 'SYNTHETIC-EXISTING-RECEIPT', {
              flag: 'wx',
            });
        },
      },
    };
  }
  try {
    for (const mode of [
      'success',
      'cancel',
      'wrong-phrase',
      'existing',
      'existing-file',
      'changed-after-confirmation',
      'cli-failure',
      'unchanged',
      'wrong-metadata',
      'wrong-envelope',
      'postcheck-failure',
      'receipt-race',
      'file-changed-after-check',
    ]) {
      const folder = path.join(root, mode);
      fs.mkdirSync(folder);
      const destination = path.join(folder, 'initial.vaultx-key.json');
      if (mode === 'existing-file') fs.writeFileSync(destination, 'SYNTHETIC-EXISTING-FILE');
      const { calls, settings } = dependencies(destination, mode),
        result = await executeOnce(settings);
      const invoked = [
        'success',
        'cli-failure',
        'unchanged',
        'wrong-metadata',
        'wrong-envelope',
        'postcheck-failure',
        'receipt-race',
        'file-changed-after-check',
      ].includes(mode);
      assert.equal(calls.invoke, invoked ? 1 : 0);
      assert.equal(
        result.result,
        mode === 'success'
          ? 'ISSUED_AND_METADATA_VERIFIED'
          : ['cancel', 'wrong-phrase'].includes(mode)
            ? 'CANCELLED_BEFORE_ISSUANCE'
            : invoked
              ? 'STOP_OUTCOME_UNVERIFIED_DO_NOT_RETRY'
              : 'STOP_BEFORE_ISSUANCE',
      );
      assert.ok(!JSON.stringify(result).includes('SYNTHETIC'));
      if (invoked) {
        const prior = calls.invoke;
        await executeOnce(settings);
        assert.equal(calls.invoke, prior);
        assert.ok(fs.existsSync(files(destination).attempt));
      }
      if (mode === 'existing-file')
        assert.ok(fs.readFileSync(destination, 'utf8') === 'SYNTHETIC-EXISTING-FILE');
      if (mode === 'success') {
        const receipt = JSON.parse(fs.readFileSync(files(destination).receipt, 'utf8'));
        assert.equal(receipt.keyId, ids.keyId);
        assert.equal(calls.verify, 1);
      }
      checks++;
      process.stdout.write(
        `Single-use ${mode}: confirmation/call-count/preservation expectations passed.\n`,
      );
    }
    const folder = path.join(root, 'concurrent');
    fs.mkdirSync(folder);
    const destination = path.join(folder, 'initial.vaultx-key.json');
    const first = dependencies(destination, 'success'),
      second = dependencies(destination, 'success');
    const outcomes = await Promise.all([executeOnce(first.settings), executeOnce(second.settings)]);
    assert.equal(first.calls.invoke + second.calls.invoke, 1);
    assert.equal(outcomes.filter((r) => r.result === 'ISSUED_AND_METADATA_VERIFIED').length, 1);
    checks++;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
  process.stdout.write(
    '14 single-use controller scenarios passed using fake CLI/metadata only; no real CLI issuance invoked.\n',
  );
}
(async () => {
  verifyPackage(directory);
  checks++;
  const provenance = JSON.parse(fs.readFileSync(path.join(directory, 'PROVENANCE.json'), 'utf8'));
  assert.equal(provenance.applicationCommit, '245752b6722a1a1d0f21d3a21a86564f29da25a2');
  checks++;
  await issuanceControllerTests();
  const pinnedCli = await import(
    pathToFileURL(path.join(directory, 'pinned-app/dist/admin/staging-cli.js')).href
  );
  assert.equal(typeof pinnedCli.runStagingCli, 'function');
  checks++;
  const workerSource = fs.readFileSync(path.join(directory, 'worker.js'), 'utf8');
  assert.equal((workerSource.match(/await runStagingCli\(/g) || []).length, 1);
  checks++;
  const config = await readOnlyConfig(input);
  assert.ok(
    config.ssl.rejectUnauthorized === true &&
      config.ssl.servername === input.expectedHost &&
      config.ssl.minVersion === 'TLSv1.2',
  );
  assert.match(config.options, /default_transaction_read_only=on/);
  checks++;
  for (const patch of [
    { approveReadOnly: false },
    { expectedHost: 'wrong.example.invalid' },
    { expectedLogin: 'wrong' },
    { databaseUrl: input.databaseUrl.replace('vaultx_pay_staging', 'production') },
    { databaseUrl: input.databaseUrl.replace('verify-full', 'require') },
    {
      expectedHost: '127.0.0.1',
      databaseUrl: 'postgres://synthetic_login:NOT-A-CREDENTIAL@127.0.0.1/vaultx_pay_staging',
    },
  ]) {
    await assert.rejects(readOnlyConfig({ ...input, ...patch }));
    checks++;
  }
  for (const scenario of [
    'absent',
    'existing',
    'wrong-name',
    'suspended',
    'bad-identity',
    'duplicate',
    'query-failure',
  ])
    await statusTest(scenario);
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultx-prepare-negative-'));
  try {
    const profile = path.join(temporary, 'profile');
    fs.mkdirSync(profile);
    const destination = checkDeliveryPath(profile);
    assert.ok(!fs.existsSync(destination));
    checks++;
    fs.writeFileSync(destination, 'SYNTHETIC-FILE-MUST-BE-PRESERVED');
    assert.throws(() => checkDeliveryPath(profile));
    assert.ok(fs.readFileSync(destination, 'utf8') === 'SYNTHETIC-FILE-MUST-BE-PRESERVED');
    checks++;
    const profile2 = path.join(temporary, 'profile2'),
      outside = path.join(temporary, 'outside');
    fs.mkdirSync(profile2);
    fs.mkdirSync(outside);
    fs.symlinkSync(
      outside,
      path.join(profile2, 'VaultXPay'),
      process.platform === 'win32' ? 'junction' : 'dir',
    );
    assert.throws(() => checkDeliveryPath(profile2));
    assert.ok(!fs.existsSync(path.join(outside, 'Secrets')));
    checks++;
    const altered = path.join(temporary, 'altered');
    fs.cpSync(directory, altered, { recursive: true });
    fs.appendFileSync(path.join(altered, 'status-check.js'), '\n');
    assert.throws(() => verifyPackage(altered));
    checks++;
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
  const clean = {
    ...process.env,
    NODE_OPTIONS: '',
    NODE_DEBUG: '',
    NODE_DEBUG_NATIVE: '',
    NODE_TLS_REJECT_UNAUTHORIZED: '',
    NODE_PG_FORCE_NATIVE: '',
    PSModulePath: '',
    DATABASE_URL: '',
    TEST_DATABASE_URL: '',
    TEST_DATABASE_TOKEN: '',
  };
  if (process.platform === 'win32') {
    const native = spawnSync(
      process.execPath,
      [path.join(directory, 'launcher.js'), '--validate-only'],
      { env: clean, encoding: 'utf8', timeout: 120000 },
    );
    assert.equal(native.status, 0);
    assert.match(native.stdout, /3 credential-free native DPAPI/);
    checks++;
    const restricted = spawnSync(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        "Set-ExecutionPolicy -Scope Process Restricted -Force; if ((Get-ExecutionPolicy) -ne 'Restricted') { exit 3 }; & $env:VAULTX_TEST_NODE $env:VAULTX_TEST_ENTRY --validate-only; exit $LASTEXITCODE",
      ],
      {
        env: {
          ...clean,
          VAULTX_TEST_NODE: process.execPath,
          VAULTX_TEST_ENTRY: path.join(directory, 'launcher.js'),
        },
        encoding: 'utf8',
        timeout: 120000,
      },
    );
    assert.equal(restricted.status, 0);
    assert.match(restricted.stdout, /3 credential-free native DPAPI/);
    checks++;
    process.stdout.write(
      'Native Windows and Restricted-policy DPAPI/launcher checks passed with synthetic invalid credentials only.\n',
    );
  } else
    process.stdout.write(
      'SKIPPED: native Windows DPAPI and Restricted-policy execution require Windows; not claimed passed.\n',
    );
  process.stdout.write(
    `${checks} issuance-package validation checks passed. No network/database connection; real CLI issuance never invoked.\n`,
  );
})().catch(() => {
  process.stderr.write('STOP: preparation-package validation failed; details withheld.\n');
  process.exitCode = 1;
});
