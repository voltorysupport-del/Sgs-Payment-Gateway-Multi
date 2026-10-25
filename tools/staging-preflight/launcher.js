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
    'Start-Preflight.cmd',
    'preflight.js',
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
async function runChecker(payload) {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8');
  if (Object.hasOwn(payload, 'databaseUrl')) payload.databaseUrl = '';
  try {
    return await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [path.join(__dirname, 'preflight.js')], {
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
  if (args[0] === '--validate-only')
    return runChecker({ mode: 'self-test', sentinel: '\u20ac\u03bb' });
  if (process.platform !== 'win32') throw Error();
  const { readHiddenLine } = require('./console-input.js');
  process.stdout.write(
    'Read-only staging preflight. All responses are hidden; no operator or key is created.\n',
  );
  const consent = await readHiddenLine(
    'Type READONLY to authorize the read-only connection, or Enter to stop: ',
  );
  if (consent !== 'READONLY') throw Error();
  const expectedHost = await readHiddenLine(
    'Independently verified full EXTERNAL staging hostname: ',
  );
  const expectedLogin = await readHiddenLine(
    'Independently verified authenticated PostgreSQL login: ',
  );
  let databaseUrl = await readHiddenLine(
    'Private EXTERNAL staging URL (hidden; never send it to chat): ',
  );
  const payload = {
    approveReadOnly: true,
    expectedHost: expectedHost.trim(),
    expectedLogin: expectedLogin.trim(),
    databaseUrl,
  };
  databaseUrl = '';
  return runChecker(payload);
}
if (require.main === module) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch(() => {
      process.stderr.write(
        'STOP: console, integrity, runtime options, consent or launcher failure. Details suppressed.\n',
      );
      process.exitCode = 2;
    });
}
module.exports = { verifyPackage };
