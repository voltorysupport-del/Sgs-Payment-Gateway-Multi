/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tools require no TypeScript loader. */
/* global require, process, Buffer, URL, setTimeout, clearTimeout */
const vm = require('node:vm'),
  fs = require('node:fs'),
  assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { tmpdir } = require('node:os');
const packageDirectory = path.resolve(process.argv[2] || '');
assert.ok(process.argv[2]);
const checker = path.join(packageDirectory, 'preflight.js');
const code = fs.readFileSync(checker, 'utf8');
let passed = 0;
const input = {
  approveReadOnly: true,
  expectedHost: 'external.example.invalid',
  expectedLogin: 'synthetic',
  databaseUrl:
    'postgres://synthetic:NOT-A-CREDENTIAL@external.example.invalid/vaultx_pay_staging?sslmode=verify-full',
};
async function test(scenario) {
  let output = '',
    errors = '',
    closed = false,
    queries = [],
    config;
  const fakeProcess = {
    stdin: (async function* () {
      yield Buffer.from(JSON.stringify(input));
    })(),
    stdout: { write: (s) => (output += s) },
    stderr: { write: (s) => (errors += s) },
    exitCode: 0,
  };
  const fakeClient = {
    on() {},
    release() {},
    async query(sql, args) {
      queries.push(sql);
      assert.match(
        sql.trim(),
        /^(SELECT|BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY|ROLLBACK)\b/,
      );
      assert.doesNotMatch(
        sql,
        /\b(?:INSERT\s+INTO|UPDATE\s+public\.|DELETE\s+FROM|COMMENT\s+ON|ALTER\s+|CREATE\s+|DROP\s+)\b/i,
      );
      if (sql.startsWith('BEGIN') || sql === 'ROLLBACK') return {};
      if (sql.includes('current_database() = $1'))
        return {
          rowCount: 1,
          rows: [
            {
              database: true,
              login: scenario !== 'wrong-login',
              read_only: true,
              postgresql_17: true,
              marker: scenario !== 'missing-marker',
            },
          ],
        };
      if (sql.includes('c.relkind')) {
        if (scenario === 'missing-table' && args[0] === 'operators')
          return { rowCount: 0, rows: [] };
        const columns = {
          operators: ['id', 'name', 'code', 'status', 'created_at'],
          operator_api_keys: ['id', 'operator_id', 'name', 'key_hash', 'created_at', 'revoked_at'],
          payments: [
            'id',
            'operator_id',
            'provider',
            'provider_reference',
            'amount_minor',
            'currency',
            'status',
            'idempotency_key',
            'created_at',
            'updated_at',
          ],
          schema_migrations: ['name', 'applied_at'],
        };
        return {
          rowCount: 1,
          rows: [
            {
              relkind: 'r',
              relrowsecurity: scenario === 'rls',
              relforcerowsecurity: false,
              can_select: true,
              can_insert: scenario !== 'no-write-permission',
              can_update: scenario !== 'no-write-permission',
              columns: columns[args[0]],
            },
          ],
        };
      }
      if (sql.includes('has_schema_privilege')) return { rows: [{ safe: true }] };
      if (sql.startsWith('SELECT name FROM public.schema_migrations'))
        return {
          rows:
            scenario === 'missing-migration'
              ? []
              : [{ name: '001_initial_schema.sql' }, { name: '002_operator_api_keys.sql' }],
        };
      throw Error('Unexpected SQL');
    },
  };
  class Pool {
    constructor(c) {
      config = c;
    }
    on() {}
    async connect() {
      return fakeClient;
    }
    async end() {
      closed = true;
    }
  }
  vm.runInNewContext(code, {
    require: (name) => (name === 'pg' ? { Pool } : require(name)),
    process: fakeProcess,
    Buffer,
    URL,
    console: {},
    setTimeout,
    clearTimeout,
  });
  for (let i = 0; i < 100 && !closed; i++) await new Promise((r) => setTimeout(r, 1));
  assert.equal(closed, true);
  assert.equal(config.ssl.rejectUnauthorized, true);
  assert.equal(config.ssl.minVersion, 'TLSv1.2');
  assert.equal(config.ssl.servername, input.expectedHost);
  assert.match(config.options, /default_transaction_read_only=on/);
  assert.equal(fakeProcess.exitCode, scenario === 'ready' ? 0 : 2);
  assert.ok(queries.includes('ROLLBACK'));
  assert.ok(!output.includes('NOT-A-CREDENTIAL') && !errors.includes('NOT-A-CREDENTIAL'));
  passed++;
  process.stdout.write(
    scenario +
      ': expected ' +
      (scenario === 'ready' ? 'PASS' : 'STOP') +
      '; query allowlist/TLS/privacy assertions passed\n',
  );
}
function launcher(directory, executable = 'powershell.exe', extraEnv = {}) {
  const result = spawnSync(
    executable,
    ['-NoLogo', '-NoProfile', '-File', path.join(directory, 'Run-Preflight.ps1'), '-ValidateOnly'],
    {
      env: {
        ...process.env,
        NODE_OPTIONS: '',
        NODE_DEBUG: '',
        NODE_DEBUG_NATIVE: '',
        NODE_TLS_REJECT_UNAUTHORIZED: '',
        DATABASE_URL: '',
        TEST_DATABASE_URL: '',
        TEST_DATABASE_TOKEN: '',
        ...extraEnv,
      },
      encoding: 'utf8',
      timeout: 60000,
      windowsHide: true,
    },
  );
  return result;
}
(async () => {
  for (const s of [
    'ready',
    'wrong-login',
    'missing-marker',
    'missing-table',
    'missing-migration',
    'no-write-permission',
    'rls',
  ])
    await test(s);
  const offline = spawnSync(process.execPath, [checker], {
    input: JSON.stringify({ mode: 'self-test', sentinel: '\u20ac\u03bb' }),
    encoding: 'utf8',
    timeout: 10000,
  });
  assert.equal(offline.status, 0);
  assert.match(offline.stdout, /READY:/);
  passed++;
  const invalid = spawnSync(process.execPath, [checker], {
    input: JSON.stringify({ ...input, expectedLogin: 'wrong' }),
    encoding: 'utf8',
    timeout: 10000,
  });
  assert.equal(invalid.status, 2);
  assert.ok(!invalid.stderr.includes('NOT-A-CREDENTIAL'));
  passed++;
  if (process.platform === 'win32') {
    for (const executable of ['powershell.exe', 'pwsh.exe']) {
      const result = launcher(packageDirectory, executable);
      if (result.status !== 0) {
        const safe = (result.stdout + result.stderr)
          .split('\n')
          .filter((line) => /^(STOP:|READY:)/.test(line))
          .join('\n');
        process.stderr.write(`${executable} failed with status ${result.status}: ${safe}\n`);
      }
      assert.equal(result.status, 0, `${executable} launcher failed (details suppressed).`);
      assert.match(result.stdout, /READY:/);
      assert.ok(!result.stdout.includes('NOT-A-CREDENTIAL'));
      passed++;
      process.stdout.write(
        `${executable}: native launcher, private UTF-8 pipe and space/ampersand path passed.\n`,
      );
    }
    for (const env of [
      { NODE_OPTIONS: '--trace-warnings' },
      { NODE_TLS_REJECT_UNAUTHORIZED: '0' },
    ]) {
      const result = launcher(packageDirectory, 'powershell.exe', env);
      assert.equal(result.status, 2);
      assert.doesNotMatch(result.stdout, /READY:/);
      passed++;
    }
    const temporary = fs.mkdtempSync(path.join(tmpdir(), 'vaultx-package-negative-'));
    try {
      const altered = path.join(temporary, 'altered');
      fs.cpSync(packageDirectory, altered, { recursive: true });
      fs.appendFileSync(path.join(altered, 'preflight.js'), '\n');
      assert.equal(launcher(altered).status, 2);
      passed++;
      fs.copyFileSync(checker, path.join(altered, 'preflight.js'));
      fs.unlinkSync(path.join(altered, 'README.txt'));
      assert.equal(launcher(altered).status, 2);
      passed++;
    } finally {
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  }
  process.stdout.write(
    `${passed} package validation checks passed. No database/network connection was opened.\n`,
  );
})().catch(() => {
  process.stderr.write('Package validation FAILED (details withheld).\n');
  process.exitCode = 1;
});
