/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tools require no TypeScript loader. */
/* global require, process, URL */
// Standalone review artifact; never imports the app, migration runner, or provisioning CLI.
const assert = require('node:assert/strict');
// Schema and safety requirements reviewed against merged commit 245752b.

const migrations = ['001_initial_schema.sql', '002_operator_api_keys.sql'];
const tables = {
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
function validate(input) {
  if (input.approveReadOnly !== true) throw Error();
  const url = new URL(input.databaseUrl || '');
  if (
    !['postgres:', 'postgresql:'].includes(url.protocol) ||
    url.pathname !== '/vaultx_pay_staging' ||
    url.hostname !== input.expectedHost ||
    decodeURIComponent(url.username) !== input.expectedLogin ||
    !url.password ||
    !url.username ||
    url.hash ||
    [...url.searchParams].some(([k, v]) => k !== 'sslmode' || v !== 'verify-full') ||
    /^dpg-[a-z0-9-]+$/i.test(url.hostname) ||
    !url.hostname.includes('.') ||
    /^[0-9.:]+$/.test(url.hostname) ||
    url.hostname === 'localhost' ||
    url.hostname.endsWith('.localhost') ||
    (url.port &&
      (!Number.isInteger(Number(url.port)) || Number(url.port) < 1 || Number(url.port) > 65535))
  )
    throw Error();
  return url;
}
function offlineTest() {
  // Configuration only: this function never loads pg or opens a socket.
  const fixture = {
    approveReadOnly: true,
    expectedHost: 'external.example.invalid',
    expectedLogin: 'synthetic',
    databaseUrl:
      'postgres://synthetic:NOT-A-CREDENTIAL@external.example.invalid/vaultx_pay_staging?sslmode=verify-full',
  };
  assert.equal(validate(fixture).hostname, fixture.expectedHost);
  for (const patch of [
    { approveReadOnly: false },
    { expectedHost: 'other.example.invalid' },
    { expectedLogin: 'different' },
    { databaseUrl: fixture.databaseUrl.replace('vaultx_pay_staging', 'production') },
    { databaseUrl: fixture.databaseUrl.replace('verify-full', 'require') },
    {
      expectedHost: '127.0.0.1',
      databaseUrl: 'postgres://synthetic:NOT-A-CREDENTIAL@127.0.0.1/vaultx_pay_staging',
    },
    {
      expectedHost: 'dpg-internal',
      databaseUrl: 'postgres://synthetic:NOT-A-CREDENTIAL@dpg-internal/vaultx_pay_staging',
    },
  ]) {
    assert.throws(() => validate({ ...fixture, ...patch }));
  }
  process.stdout.write('READY: offline configuration checks passed; no database connection.\n');
}
async function main() {
  // Use a bounded private input pipe, never argv, environment, a URL file or console echo.
  let raw = '';
  for await (const chunk of process.stdin) {
    raw += chunk.toString('utf8');
    if (raw.length > 32768) throw Error();
  }
  const input = JSON.parse(raw);
  raw = '';
  if (input.mode === 'self-test') {
    assert.equal(input.sentinel, '\u20ac\u03bb');
    offlineTest();
    return;
  }
  const url = validate(input);
  const { Pool } = require('pg');
  const config = {
    host: url.hostname,
    port: Number(url.port || 5432),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database: 'vaultx_pay_staging',
    ssl: { rejectUnauthorized: true, minVersion: 'TLSv1.2', servername: url.hostname },
    max: 1,
    connectionTimeoutMillis: 5000,
    options:
      '-c default_transaction_read_only=on -c search_path=pg_catalog -c statement_timeout=10000 -c lock_timeout=3000',
    application_name: 'vaultx-readonly-staging-preflight',
  };
  const pool = new Pool(config);
  let asynchronousFailure = false;
  pool.on('error', () => {
    asynchronousFailure = true;
  });
  let client;
  try {
    client = await pool.connect();
    client.on('error', () => {
      asynchronousFailure = true;
    });
    await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const identity = await client.query(
      `SELECT current_database() = $1 AS database,
      session_user = $2 AS login,
      current_setting('transaction_read_only') = 'on' AS read_only,
      current_setting('server_version_num')::int >= 170000 AND current_setting('server_version_num')::int < 180000 AS postgresql_17,
      pg_catalog.shobj_description(oid, 'pg_database') = $3 AS marker
      FROM pg_catalog.pg_database WHERE datname = current_database()`,
      ['vaultx_pay_staging', config.user, 'vaultx-pay:staging'],
    );
    const checks = { ...identity.rows[0] };
    if (identity.rowCount !== 1 || !checks.database || !checks.login || !checks.read_only)
      throw Error();
    checks.tls = true;
    const permissions = {};
    checks.tables_and_columns = true;
    for (const [table, columns] of Object.entries(tables)) {
      const found = await client.query(
        `SELECT c.relkind, c.relrowsecurity, c.relforcerowsecurity,
        pg_catalog.has_table_privilege(c.oid,'SELECT') AS can_select,
        pg_catalog.has_table_privilege(c.oid,'INSERT') AS can_insert,
        pg_catalog.has_table_privilege(c.oid,'UPDATE') AS can_update,
        (SELECT array_agg(a.attname::text) FROM pg_catalog.pg_attribute a
          WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) AS columns
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relname=$1`,
        [table],
      );
      const row = found.rows[0];
      const shape =
        found.rowCount === 1 &&
        row.relkind === 'r' &&
        columns.every((c) => row.columns.includes(c));
      checks.tables_and_columns &&= shape;
      permissions[table] = {
        select: row?.can_select === true,
        insert: row?.can_insert === true,
        update: row?.can_update === true,
        rls: row?.relrowsecurity === true || row?.relforcerowsecurity === true,
      };
    }
    const usage = await client.query(
      "SELECT pg_catalog.has_schema_privilege('public','USAGE') AS safe",
    );
    checks.schema_usage = usage.rows[0]?.safe === true;
    checks.migrations = false;
    if (checks.tables_and_columns && permissions.schema_migrations.select) {
      const applied = await client.query(
        'SELECT name FROM public.schema_migrations WHERE name = ANY($1::text[])',
        [migrations],
      );
      checks.migrations = migrations.every((m) => applied.rows.some((r) => r.name === m));
    }
    checks.provisioning_permissions =
      checks.schema_usage &&
      ['operators', 'operator_api_keys'].every(
        (t) =>
          permissions[t].select &&
          permissions[t].insert &&
          permissions[t].update &&
          !permissions[t].rls,
      );
    // Permissions are inspected via catalogs: no trial INSERT/UPDATE, even rolled back.
    await client.query('ROLLBACK');
    const pass = !asynchronousFailure && Object.values(checks).every((v) => v === true);
    process.stdout.write(
      JSON.stringify(
        {
          result: pass ? 'PASS' : 'STOP',
          checks,
          permissions,
          limitations: [
            'No writes attempted; constraints, triggers and concurrent changes are not proven by privilege checks.',
            'No payment/provider or API-key operations performed.',
          ],
        },
        null,
        2,
      ) + '\n',
    );
    process.exitCode = pass ? 0 : 2;
  } finally {
    if (client) {
      await client.query('ROLLBACK').catch(() => {});
      client.release();
    }
    await pool.end();
  }
}
main().catch(() => {
  process.stderr.write(
    'STOP: configuration, verified TLS, authentication, or read-only query failed. Details suppressed; no secrets logged.\n',
  );
  process.exitCode = 2;
});
