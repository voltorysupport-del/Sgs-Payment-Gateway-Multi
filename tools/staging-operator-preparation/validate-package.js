/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, process */
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
(async () => {
  verifyPackage(directory);
  checks++;
  const provenance = JSON.parse(fs.readFileSync(path.join(directory, 'PROVENANCE.json'), 'utf8'));
  assert.equal(provenance.applicationCommit, '245752b6722a1a1d0f21d3a21a86564f29da25a2');
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
    `${checks} preparation-package validation checks passed. No network/database connection; no operator/key generation.\n`,
  );
})().catch(() => {
  process.stderr.write('STOP: preparation-package validation failed; details withheld.\n');
  process.exitCode = 1;
});
