/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, process, __dirname, setTimeout, clearTimeout */
const path = require('node:path'),
  { pathToFileURL } = require('node:url');
const { executeOnce, CONFIRM } = require('./issuer.js');
const { readOnlyConfig, readOnlyStatus } = require('./status-check.js');
const { checkDeliveryPath } = require('./delivery-path.js');
function send(message) {
  if (process.connected) process.send(message);
}
function stop() {
  send({ type: 'result', value: { result: 'STOP_OUTCOME_UNVERIFIED_DO_NOT_RETRY' } });
  process.exit(2);
}
process.on('uncaughtException', stop);
process.on('unhandledRejection', stop);
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
  const destination = checkDeliveryPath();
  const { verifyStagingTarget } = await import(
    pathToFileURL(path.join(__dirname, 'pinned-app/dist/admin/staging-operator.js')).href
  );
  const { runStagingCli } = await import(
    pathToFileURL(path.join(__dirname, 'pinned-app/dist/admin/staging-cli.js')).href
  );
  const { Pool } = require('pg');
  const pool = new Pool(config);
  let failed = false;
  pool.on('error', () => {
    failed = true;
  });
  async function precheck() {
    if (checkDeliveryPath() !== destination || failed) throw Error();
    const status = await readOnlyStatus(pool, verifyStagingTarget, String(config.user));
    if (status.result !== 'READY_FOR_SEPARATE_PROVISIONING_APPROVAL' || failed) throw Error();
    // Explicit key check scoped to the intended operator; foreign-key schema also prevents orphan keys.
    const keys = await pool.query(
      'SELECT count(*)::int AS count FROM public.operator_api_keys k JOIN public.operators o ON o.id=k.operator_id WHERE o.code=$1',
      ['staging-e2e'],
    );
    if (keys.rows[0]?.count !== 0) throw Error();
  }
  try {
    const result = await executeOnce({
      destination,
      precheck,
      confirm: () =>
        new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('Confirmation expired.')), 180000);
          process.once('message', (message) => {
            clearTimeout(timer);
            if (message?.type === 'confirm' && message.value === CONFIRM) resolve(CONFIRM);
            else resolve('');
          });
          process.once('disconnect', () => {
            clearTimeout(timer);
            reject(new Error('Parent disconnected.'));
          });
          send({ type: 'ready' });
        }),
      onAttempt: () => send({ type: 'attempt-recorded' }),
      invoke: async (args) => {
        if (!process.connected) throw Error();
        // A private config object, never credentials in OS environment/argv/logs.
        const env = {
          DATABASE_URL: input.databaseUrl,
          STAGING_DATABASE_HOST: input.expectedHost,
          STAGING_DATABASE_USER: input.expectedLogin,
          NODE_ENV: 'production',
          VAULTX_ENVIRONMENT: 'staging',
          ALLOW_STAGING_OPERATOR_PROVISIONING: 'true',
          LIVE_MODE_ENABLED: 'false',
          ALLOWED_PROVIDERS: 'simulator',
          SIMULATOR_CONTROLS_ENABLED: 'false',
        };
        input.databaseUrl = '';
        let output = '';
        // Invoke the unchanged reviewed CLI function once. Suppress all original output until validated.
        const status = await runStagingCli(
          args,
          env,
          (text) => {
            if (output.length + text.length > 16384) throw Error();
            output += text;
          },
          () => {},
        );
        env.DATABASE_URL = '';
        if (status !== 0 || failed) throw Error();
        return JSON.parse(output);
      },
      verify: async (metadata) => {
        const client = await pool.connect();
        let okay = false;
        try {
          await verifyStagingTarget(client, String(config.user));
          await client.query('BEGIN READ ONLY');
          const operator = await client.query(
            'SELECT id FROM public.operators WHERE id=$1 AND code=$2 AND name=$3 AND status=$4',
            [metadata.operatorId, 'staging-e2e', 'VaultX Pay Staging Test Operator', 'active'],
          );
          const keys = await client.query(
            'SELECT id, revoked_at IS NULL AS active FROM public.operator_api_keys WHERE operator_id=$1',
            [metadata.operatorId],
          );
          okay =
            operator.rowCount === 1 &&
            keys.rowCount === 1 &&
            keys.rows[0].id === metadata.keyId &&
            keys.rows[0].active === true &&
            !failed;
          await client.query('ROLLBACK');
        } finally {
          await client.query('ROLLBACK').catch(() => {});
          client.release();
        }
        if (!okay) throw Error();
      },
    });
    input.databaseUrl = '';
    send({ type: 'result', value: result });
    process.exitCode = result.result === 'ISSUED_AND_METADATA_VERIFIED' ? 0 : 2;
  } finally {
    await pool.end();
    if (process.connected) process.disconnect();
  }
}
main().catch(stop);
