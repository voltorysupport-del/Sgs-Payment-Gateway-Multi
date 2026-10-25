/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tools require no TypeScript loader. */
/* global require, process, __dirname */
// Copy only the reviewed tool and locked pure-JS pg dependency tree. No install hooks.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../..');
const destination = path.resolve(process.argv[2] || '');
assert.ok(process.argv[2] && !fs.existsSync(destination), 'Choose a new package directory.');
const relative = path.relative(root, destination);
assert.ok(
  relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative),
  'Package must be outside the repository.',
);
fs.mkdirSync(destination, { recursive: true });
for (const name of [
  'preflight.js',
  'Run-Preflight.ps1',
  'Start-Preflight.cmd',
  'README.txt',
  'package.json',
]) {
  fs.copyFileSync(path.join(__dirname, name), path.join(destination, name));
}
const copied = new Map();
function copy(name) {
  if (copied.has(name)) return;
  const source = path.join(root, 'node_modules', name);
  const data = JSON.parse(fs.readFileSync(path.join(source, 'package.json'), 'utf8'));
  if (name === 'pg') assert.equal(data.version, '8.23.1');
  // Do not follow symlinked packages or bundle unrelated application dependencies.
  assert.ok(!fs.lstatSync(source).isSymbolicLink());
  copied.set(name, data.version);
  fs.cpSync(source, path.join(destination, 'node_modules', name), { recursive: true });
  for (const dependency of Object.keys(data.dependencies || {})) copy(dependency);
}
copy('pg');
fs.writeFileSync(
  path.join(destination, 'PROVENANCE.json'),
  JSON.stringify(
    {
      schemaBase: '245752b6722a1a1d0f21d3a21a86564f29da25a2',
      sourceCommit: process.env.GITHUB_SHA || 'local-unpublished-validation',
      dependencies: Object.fromEntries(copied),
    },
    null,
    2,
  ) + '\n',
);
const hashes = {};
function walk(directory) {
  for (const name of fs.readdirSync(directory).sort()) {
    const file = path.join(directory, name);
    const stat = fs.lstatSync(file);
    assert.ok(!stat.isSymbolicLink(), 'No symlinks permitted in package.');
    if (stat.isDirectory()) walk(file);
    else
      hashes[path.relative(destination, file).split(path.sep).join('/')] = crypto
        .createHash('sha256')
        .update(fs.readFileSync(file))
        .digest('hex');
  }
}
walk(destination);
fs.writeFileSync(path.join(destination, 'SHA256SUMS.json'), JSON.stringify(hashes, null, 2) + '\n');
process.stdout.write(
  `Packaged ${Object.keys(hashes).length} verified files; ${copied.size} locked runtime dependencies.\n`,
);
