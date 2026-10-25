/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, module, process, __dirname, URL */
const path = require('node:path');
const { pathToFileURL } = require('node:url');
async function pinnedModules() {
  const config = await import(
    pathToFileURL(path.join(__dirname, 'pinned-app/dist/admin/staging-config.js')).href
  );
  const identity = await import(
    pathToFileURL(path.join(__dirname, 'pinned-app/dist/admin/staging-operator.js')).href
  );
  return { ...config, verifyStagingTarget: identity.verifyStagingTarget };
}
async function readOnlyConfig(input) {
  if (input.approveReadOnly !== true) throw Error();
  const url = new URL(input.databaseUrl || '');
  // This package has no local/plaintext mode, even though the pinned library permits loopback.
  if (
    !url.hostname.includes('.') ||
    /^[0-9.:]+$/.test(url.hostname) ||
    url.hostname.endsWith('.localhost')
  )
    throw Error();
  const { stagingPoolConfig } = await pinnedModules();
  const config = stagingPoolConfig({
    DATABASE_URL: input.databaseUrl,
    STAGING_DATABASE_HOST: input.expectedHost,
    STAGING_DATABASE_USER: input.expectedLogin,
    NODE_ENV: 'production',
    VAULTX_ENVIRONMENT: 'staging',
    ALLOW_STAGING_OPERATOR_PROVISIONING: 'true',
    LIVE_MODE_ENABLED: 'false',
    ALLOWED_PROVIDERS: 'simulator',
    SIMULATOR_CONTROLS_ENABLED: 'false',
  });
  // Required config flag stays in this local object, never process.env or a provisioning invocation.
  config.options += ' -c default_transaction_read_only=on';
  config.application_name = 'vaultx-readonly-operator-preparation';
  return config;
}
async function readOnlyStatus(pool, verifyStagingTarget, expectedUser) {
  const client = await pool.connect();
  let failed = false,
    result;
  client.on('error', () => {
    failed = true;
  });
  try {
    await verifyStagingTarget(client, expectedUser);
    await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const identity = await client.query(
      `SELECT current_database()='vaultx_pay_staging' AND session_user=$1
      AND current_setting('transaction_read_only')='on'
      AND current_setting('server_version_num')::int >= 170000 AND current_setting('server_version_num')::int < 180000
      AND pg_catalog.shobj_description(oid,'pg_database')='vaultx-pay:staging' AS safe
      FROM pg_catalog.pg_database WHERE datname=current_database()`,
      [expectedUser],
    );
    if (identity.rowCount !== 1 || identity.rows[0]?.safe !== true) throw Error();
    const operators = await client.query(
      'SELECT id, name = $2 AS expected_identity, status FROM public.operators WHERE code = $1',
      ['staging-e2e', 'VaultX Pay Staging Test Operator'],
    );
    if (operators.rowCount === 0)
      result = {
        result: 'READY_FOR_SEPARATE_PROVISIONING_APPROVAL',
        operator: 'absent',
        provisioned: false,
      };
    else {
      if (operators.rowCount !== 1) throw Error();
      const operator = operators.rows[0];
      if (operator.expected_identity !== true || operator.status !== 'active')
        result = { result: 'STOP_EXISTING_OPERATOR_REQUIRES_REVIEW', provisioned: false };
      else {
        const keys = await client.query(
          'SELECT id, revoked_at IS NULL AS active FROM public.operator_api_keys WHERE operator_id = $1 ORDER BY created_at, id',
          [operator.id],
        );
        result = {
          result: 'STOP_OPERATOR_ALREADY_EXISTS',
          operatorId: operator.id,
          keys: keys.rows.map((row) => ({ keyId: row.id, active: row.active })),
          provisioned: false,
        };
      }
    }
  } catch {
    failed = true;
  } finally {
    await client.query('ROLLBACK').catch(() => {
      failed = true;
    });
    client.release();
  }
  if (failed || !result) throw new Error('Read-only status failed.');
  return result;
}
async function main() {
  process.stdin.setEncoding('utf8');
  let raw = '';
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (raw.length > 32768) throw Error();
  }
  const input = JSON.parse(raw);
  raw = '';
  const config = await readOnlyConfig(input);
  input.databaseUrl = '';
  const { Pool } = require('pg'),
    { verifyStagingTarget } = await pinnedModules();
  const pool = new Pool(config);
  let failed = false;
  pool.on('error', () => {
    failed = true;
  });
  try {
    const result = await readOnlyStatus(pool, verifyStagingTarget, String(config.user));
    if (failed) throw Error();
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    process.exitCode = result.result === 'READY_FOR_SEPARATE_PROVISIONING_APPROVAL' ? 0 : 2;
  } finally {
    await pool.end();
  }
}
if (require.main === module)
  main().catch(() => {
    process.stderr.write(
      'STOP: verified identity, TLS, authentication or read-only status failed. Details suppressed.\n',
    );
    process.exitCode = 2;
  });
module.exports = { readOnlyConfig, readOnlyStatus };
