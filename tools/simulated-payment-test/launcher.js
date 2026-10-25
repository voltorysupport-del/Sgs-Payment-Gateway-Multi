/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, process, __dirname, module */
const fs = require('node:fs'),
  path = require('node:path'),
  crypto = require('node:crypto');
function verify() {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'SHA256SUMS.json'), 'utf8')),
    seen = new Set();
  for (const name of [
    'launcher.js',
    'flow.js',
    'key-reader.js',
    'console-input.js',
    'Start-Simulated-Payment.cmd',
    'README.txt',
    'package.json',
    'PROVENANCE.json',
  ])
    if (!Object.hasOwn(manifest, name)) throw Error();
  function walk(folder) {
    for (const name of fs.readdirSync(folder)) {
      const file = path.join(folder, name),
        stat = fs.lstatSync(file);
      if (stat.isSymbolicLink()) throw Error();
      if (stat.isDirectory()) walk(file);
      else {
        const relative = path.relative(__dirname, file).split(path.sep).join('/');
        if (relative === 'SHA256SUMS.json') continue;
        if (
          !Object.hasOwn(manifest, relative) ||
          crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') !==
            manifest[relative]
        )
          throw Error();
        seen.add(relative);
      }
    }
  }
  walk(__dirname);
  if (seen.size !== Object.keys(manifest).length) throw Error();
}
async function main() {
  if (
    process.platform !== 'win32' ||
    process.versions.node.split('.')[0] !== '24' ||
    process.argv.length !== 2 ||
    [
      'NODE_OPTIONS',
      'NODE_DEBUG',
      'NODE_DEBUG_NATIVE',
      'NODE_TLS_REJECT_UNAUTHORIZED',
      'NODE_PG_FORCE_NATIVE',
    ].some((k) => process.env[k])
  )
    throw Error();
  verify();
  const { readHiddenLine } = require('./console-input.js'),
    { origin, transport, run, CONFIRM } = require('./flow.js');
  process.stdout.write(
    'One SIMULATED EUR 1.00 payment, then simulated success. Existing operator/key only. No real payments.\n',
  );
  const base = origin(
    await readHiddenLine('Verified STAGING web-service HTTPS URL (not a database URL): '),
  );
  process.stdout.write('Target: ' + base + '\n');
  if (
    (await readHiddenLine(
      'Confirm this is the approved simulator-only deployment with LIVE_MODE_ENABLED=false. Type READONLY for auth checks: ',
    )) !== 'READONLY'
  )
    throw Error();
  const { readExistingKey } = require('./key-reader.js');
  const credential = await readExistingKey();
  let fd;
  try {
    const outcome = await run({
      request: transport(base, credential.apiKey),
      confirm: () =>
        readHiddenLine('Type ' + CONFIRM + ' to authorize the one simulated payment: '),
      begin: async (header) => {
        const local = fs.realpathSync(process.env.LOCALAPPDATA);
        const directory = path.join(local, 'VaultXPay', 'SimulatedTests');
        let current = local;
        for (const item of ['VaultXPay', 'SimulatedTests']) {
          current = path.join(current, item);
          try {
            const s = fs.lstatSync(current);
            if (!s.isDirectory() || s.isSymbolicLink()) throw Error();
          } catch (e) {
            if (e.code !== 'ENOENT') throw e;
            fs.mkdirSync(current, { mode: 0o700 });
          }
          if (fs.realpathSync(current).toLowerCase() !== current.toLowerCase()) throw Error();
        }
        fd = fs.openSync(
          path.join(directory, 'first-simulated-payment.attempt.jsonl'),
          'wx',
          0o600,
        );
        fs.writeSync(
          fd,
          JSON.stringify({
            phase: 'AUTHORIZED',
            origin: base,
            operatorId: credential.operatorId,
            keyId: credential.keyId,
            ...header,
          }) + '\n',
        );
        fs.fsyncSync(fd);
      },
      record: async (value) => {
        fs.writeSync(fd, JSON.stringify(value) + '\n');
        fs.fsyncSync(fd);
      },
    });
    process.stdout.write(JSON.stringify(outcome, null, 2) + '\n');
  } finally {
    credential.apiKey = '';
    if (fd !== undefined) fs.closeSync(fd);
  }
}
if (require.main === module)
  main().catch((error) => {
    process.stderr.write(
      JSON.stringify({
        result: 'STOP_NO_AUTOMATIC_RETRY',
        phase: typeof error.phase === 'string' ? error.phase : 'LAUNCHER',
        reason: typeof error.reason === 'string' ? error.reason : 'PREREQUISITE_OR_KEY_READ',
        ...(error.httpStatus ? { httpStatus: error.httpStatus } : {}),
        ...(error.paymentId ? { paymentId: error.paymentId } : {}),
        writesAttempted: error.writesAttempted === true,
      }) + '\n',
    );
    process.exitCode = 2;
  });
module.exports = { verify };
