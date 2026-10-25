/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, process, __dirname, setTimeout, clearTimeout */
const path = require('node:path'),
  { pathToFileURL } = require('node:url');
const { recoverOnce, PHRASE, captureOriginal } = require('./recovery-controller.js');
const { cliReason, publicOutcome } = require('./diagnostics.js');
const { validateMetadata, verifyEnvelope } = require('./issuer.js');
const { readOnlyConfig, readOnlyStatus } = require('./status-check.js');
const { checkDeliveryPath } = require('./delivery-path.js');
let runtimePhase = 'WORKER_START',
  cliInvoked = false;
function send(message) {
  if (process.connected) process.send(message);
}
function stop() {
  send({ type: 'result', value: publicOutcome({ phase: runtimePhase, attempted: cliInvoked }) });
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
  runtimePhase = 'CONFIG_VALIDATED';
  const destination = checkDeliveryPath();
  const approvedOriginalHash = captureOriginal(destination);
  runtimePhase = 'ORIGINAL_EVIDENCE_VALIDATED';
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
    const sessions = await pool.query(
      "SELECT count(*)::int AS count FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND usename=session_user AND application_name='vaultx-staging-provisioning' AND pid<>pg_backend_pid()",
    );
    if (sessions.rows[0]?.count !== 0) throw Error();
    return {
      identityVerified: true,
      tlsVerified: true,
      operatorAbsent: true,
      keysAbsent: true,
      possibleIssuanceSessions: 0,
    };
  }
  try {
    const result = await recoverOnce({
      destination,
      approvedOriginalHash,
      readOnlyCheck: precheck,
      confirm: () =>
        new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('Confirmation expired.')), 180000);
          process.once('message', (message) => {
            clearTimeout(timer);
            if (message?.type === 'confirm' && message.value === PHRASE) resolve(PHRASE);
            else resolve('');
          });
          process.once('disconnect', () => {
            clearTimeout(timer);
            reject(new Error('Parent disconnected.'));
          });
          runtimePhase = 'READ_ONLY_CHECKED';
          send({
            type: 'ready',
            originalHash: approvedOriginalHash,
            originalTimestamp: '2026-10-25T15:08:36.036Z',
          });
        }),
      beforeCli: () => {
        if (!process.connected || failed) throw Error();
      },
      invokePinnedCli: async (args) => {
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
        let output = '',
          diagnostic = '';
        // Invoke the unchanged reviewed CLI function once. Suppress all original output until validated.
        cliInvoked = true;
        runtimePhase = 'CLI_CALL_STARTED';
        const status = await runStagingCli(
          args,
          env,
          (text) => {
            if (output.length + text.length > 16384) throw Error();
            output += text;
          },
          (text) => {
            if (diagnostic.length + text.length <= 4096) diagnostic += text;
          },
        );
        runtimePhase = status === 0 ? 'CLI_RETURNED_SUCCESS' : 'CLI_RETURNED_FAILURE';
        env.DATABASE_URL = '';
        let metadata;
        try {
          if (status === 0) metadata = JSON.parse(output);
        } catch {
          /* Record CLI success then fail metadata verification. */
        }
        return { status, reason: cliReason(diagnostic), metadata };
      },
      verifyIssued: async (value) => {
        const metadata = validateMetadata(value);
        const digest = verifyEnvelope(destination, metadata);
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
        if (!okay || digest !== verifyEnvelope(destination, metadata)) throw Error();
        return true;
      },
    });
    input.databaseUrl = '';
    send({ type: 'result', value: result });
    process.exitCode = result.result === 'RECOVERY_VERIFIED' ? 0 : 2;
  } finally {
    await pool.end();
    if (process.connected) process.disconnect();
  }
}
main().catch(stop);
