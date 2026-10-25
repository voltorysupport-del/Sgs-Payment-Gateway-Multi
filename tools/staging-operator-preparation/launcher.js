/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS package. */
/* global require, module, process, __dirname, Buffer, setTimeout, clearTimeout */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
function verifyPackage(directory) {
  const root = fs.realpathSync(directory);
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'SHA256SUMS.json'), 'utf8'));
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw Error();
  const required = [
    'launcher.js',
    'console-input.js',
    'Start-Preparation.cmd',
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
async function runStatus(payload) {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8');
  if (Object.hasOwn(payload, 'databaseUrl')) payload.databaseUrl = '';
  try {
    return await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [path.join(__dirname, 'status-check.js')], {
        cwd: __dirname,
        shell: false,
        windowsHide: true,
        stdio: ['pipe', 'inherit', 'inherit'],
        env: { ...process.env, DATABASE_URL: '', TEST_DATABASE_URL: '', TEST_DATABASE_TOKEN: '' },
      });
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error('Checker timeout.'));
      }, 180000);
      child.once('error', () => {
        clearTimeout(timer);
        reject(new Error('Checker failed.'));
      });
      child.once('close', (code) => {
        clearTimeout(timer);
        resolve(code === 0 ? 0 : 2);
      });
      child.stdin.once('error', () => {
        child.kill();
        clearTimeout(timer);
        reject(new Error('Private input failed.'));
      });
      child.stdin.end(encoded, () => {
        encoded.fill(0);
      });
    });
  } finally {
    encoded.fill(0);
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
  checkDeliveryPath();
  process.stdout.write(
    'PASS: intended delivery file absent. Only its private parent directories may be created.\n',
  );
  await runDpapiTests();
  const { readHiddenLine } = require('./console-input.js');
  process.stdout.write(
    'Preparation ONLY: no operator/key issuance, rotation or revocation exists in this launcher.\n',
  );
  const consent = await readHiddenLine(
    'Type READONLY for the staging status check, or Enter to stop: ',
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
  checkDeliveryPath();
  const code = await runStatus(payload);
  checkDeliveryPath();
  process.stdout.write(
    'STOP: preparation complete. No operator or key was provisioned. Separate issuance approval is required.\n',
  );
  return code;
}
if (require.main === module) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch(() => {
      process.stderr.write(
        'STOP: preparation failed or delivery file exists. No sensitive error details printed. No issuance attempted.\n',
      );
      process.exitCode = 2;
    });
}
module.exports = { verifyPackage };
