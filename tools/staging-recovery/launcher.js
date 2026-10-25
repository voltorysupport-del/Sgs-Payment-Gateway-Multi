/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS package. */
/* global require, module, process, __dirname, Buffer, setTimeout, clearTimeout, AbortController */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { fork } = require('node:child_process');
function verifyPackage(directory) {
  const root = fs.realpathSync(directory);
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'SHA256SUMS.json'), 'utf8'));
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw Error();
  const required = [
    'launcher.js',
    'console-input.js',
    'Start-Recovery-01.cmd',
    'diagnostics.js',
    'recovery-controller.js',
    'issuer.js',
    'worker.js',
    'pinned-app/dist/admin/staging-cli.js',
    'status-check.js',
    'delivery-path.js',
    'dpapi-test.js',
    'pinned-app/dist/admin/staging-config.js',
    'pinned-app/dist/admin/staging-operator.js',
    'pinned-app/dist/admin/key-delivery.js',
    'README.txt',
    'package.json',
    'PROVENANCE.json',
    'node_modules/pg/package.json',
  ];
  if (!required.every((name) => Object.hasOwn(manifest, name))) throw Error();
  const actual = [];
  function walk(folder) {
    for (const entry of fs.readdirSync(folder)) {
      const file = path.join(folder, entry);
      const stat = fs.lstatSync(file);
      if (stat.isSymbolicLink()) throw Error();
      if (stat.isDirectory()) walk(file);
      else {
        actual.push(path.relative(root, file).split(path.sep).join('/'));
        if (actual.length > 5000) throw Error();
      }
    }
  }
  walk(root);
  if (actual.length !== Object.keys(manifest).length + 1) throw Error();
  for (const name of actual) {
    if (name === 'SHA256SUMS.json') continue;
    if (!Object.hasOwn(manifest, name) || !/^[a-f0-9]{64}$/.test(manifest[name])) throw Error();
    const digest = crypto
      .createHash('sha256')
      .update(fs.readFileSync(path.join(root, name)))
      .digest('hex');
    if (digest !== manifest[name]) throw Error();
  }
}
async function runIssuance(payload) {
  const { readHiddenLine } = require('./console-input.js');
  const { PHRASE: CONFIRM } = require('./recovery-controller.js');
  const { publicOutcome } = require('./diagnostics.js');
  const bytes = Buffer.from(JSON.stringify(payload), 'utf8');
  payload.databaseUrl = '';
  const controller = new AbortController();
  try {
    return await new Promise((resolve) => {
      let result,
        asked = false,
        confirmationSent = false;
      const child = fork(path.join(__dirname, 'worker.js'), [], {
        cwd: __dirname,
        execArgv: [],
        windowsHide: true,
        stdio: ['pipe', 'ignore', 'ignore', 'ipc'],
        env: { ...process.env, DATABASE_URL: '', TEST_DATABASE_URL: '', TEST_DATABASE_TOKEN: '' },
      });
      const timer = setTimeout(() => {
        controller.abort();
        child.kill();
      }, 300000);
      child.on('message', (message) => {
        if (message?.type === 'ready' && !asked) {
          asked = true;
          if (
            !/^[a-f0-9]{64}$/.test(message.originalHash) ||
            message.originalTimestamp !== '2026-10-25T15:08:36.036Z'
          ) {
            child.kill();
            return;
          }
          process.stdout.write(
            'Original attempt fingerprint: ' +
              message.originalHash +
              '\nOriginal timestamp: ' +
              message.originalTimestamp +
              '\n',
          );
          process.stdout.write(
            'FINAL RECOVERY-01 CHECKPOINT\nDatabase: vaultx_pay_staging\nOperator: VaultX Pay Staging Test Operator (staging-e2e)\nDelivery: %LOCALAPPDATA%\\VaultXPay\\Secrets\\initial.vaultx-key.json\nSimulator only; no real payments. No issuance has occurred.\n',
          );
          readHiddenLine(
            `Type ${CONFIRM} to authorize ONE CLI invocation, or Enter to cancel: `,
            process.stdin,
            process.stdout,
            controller.signal,
          )
            .then((value) => {
              if (child.connected) {
                confirmationSent = value === CONFIRM;
                child.send({ type: 'confirm', value: value === CONFIRM ? CONFIRM : '' }, () => {});
              }
            })
            .catch(() => {
              if (child.connected) child.send({ type: 'cancel' }, () => {});
            });
        } else if (message?.type === 'result') result = message.value;
      });
      child.once('error', () => {
        clearTimeout(timer);
        controller.abort();
        resolve(
          publicOutcome({ phase: 'WORKER_START', attempted: confirmationSent ? null : false }),
        );
      });
      child.once('close', (exitCode) => {
        clearTimeout(timer);
        controller.abort();
        const safe = publicOutcome(
          result || {
            phase: asked ? 'READ_ONLY_CHECKED' : 'WORKER_START',
            attempted: confirmationSent ? null : false,
          },
        );
        if (exitCode !== 0 && safe.result === 'RECOVERY_VERIFIED')
          safe.result = 'STOP_RECOVERY_OUTCOME_UNVERIFIED';
        if (
          safe.result === 'RECOVERY_VERIFIED' &&
          /^[a-f0-9-]{36}$/i.test(result.operatorId || '') &&
          /^[a-f0-9-]{36}$/i.test(result.keyId || '')
        ) {
          safe.operatorId = result.operatorId;
          safe.keyId = result.keyId;
          safe.operatorCode = 'staging-e2e';
        }
        resolve(safe);
      });
      child.stdin.on('error', () => child.kill());
      child.stdin.end(bytes, () => bytes.fill(0));
    });
  } finally {
    controller.abort();
    bytes.fill(0);
  }
}
async function main() {
  if (
    process.versions.node.split('.')[0] !== '24' ||
    [
      'NODE_OPTIONS',
      'NODE_DEBUG',
      'NODE_DEBUG_NATIVE',
      'NODE_TLS_REJECT_UNAUTHORIZED',
      'NODE_PG_FORCE_NATIVE',
    ].some((name) => process.env[name])
  )
    throw Error();
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== '--validate-only')) throw Error();
  verifyPackage(__dirname);
  if (process.platform !== 'win32') throw Error();
  const { runDpapiTests } = require('./dpapi-test.js');
  // Native DPAPI capability is tested BEFORE any real credentials are requested.
  if (args[0] === '--validate-only') {
    await runDpapiTests();
    return 0;
  }
  const { checkDeliveryPath } = require('./delivery-path.js');
  const { captureOriginal } = require('./recovery-controller.js');
  captureOriginal(checkDeliveryPath());
  // Preparation and DPAPI capability were already approved/passed. No repeated
  // preparation suite in a real run; --validate-only is credential-free CI mode.
  const { readHiddenLine } = require('./console-input.js');
  process.stdout.write(
    'Evidence-linked recovery-01. Original attempt is required and preserved. Run only after separate authorization. All replies are hidden.\n',
  );
  const consent = await readHiddenLine(
    'Type READONLY to authorize the immediate pre-issuance status check: ',
  );
  if (consent !== 'READONLY') throw Error();
  const expectedHost = await readHiddenLine('Previously verified FULL EXTERNAL staging hostname: ');
  const expectedLogin = await readHiddenLine(
    'Previously verified authenticated PostgreSQL login: ',
  );
  let databaseUrl = await readHiddenLine('Private external staging URL (hidden): ');
  const payload = {
    approveReadOnly: true,
    expectedHost: expectedHost.trim(),
    expectedLogin: expectedLogin.trim(),
    databaseUrl,
  };
  databaseUrl = '';
  const result = await runIssuance(payload);
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  if (result.result !== 'RECOVERY_VERIFIED')
    process.stdout.write(
      'STOP. Preserve any encrypted delivery and attempt files. Never retry, rotate, revoke or delete files automatically.\n',
    );
  return result.result === 'RECOVERY_VERIFIED' ? 0 : 2;
}
if (require.main === module)
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch(() => {
      process.stderr.write(
        'STOP: existing delivery/attempt record or launcher failure. No details printed. Do not retry an ambiguous attempt.\n',
      );
      process.exitCode = 2;
    });
module.exports = { verifyPackage };
