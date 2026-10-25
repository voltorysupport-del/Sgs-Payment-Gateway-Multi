/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require,process,__dirname */
const fs = require('node:fs'),
  path = require('node:path'),
  crypto = require('node:crypto');
const out = path.resolve(process.argv[2] || '');
if (!process.argv[2] || fs.existsSync(out)) throw Error();
const repo = path.resolve(__dirname, '../..'),
  relative = path.relative(repo, out);
if (!relative.startsWith('..' + path.sep) && !path.isAbsolute(relative)) throw Error();
fs.mkdirSync(out, { recursive: true });
for (const name of [
  'launcher.js',
  'flow.js',
  'key-reader.js',
  'console-input.js',
  'Start-Simulated-Payment.cmd',
  'README.txt',
  'package.json',
])
  fs.copyFileSync(path.join(__dirname, name), path.join(out, name));
fs.writeFileSync(
  path.join(out, 'PROVENANCE.json'),
  JSON.stringify(
    {
      apiContractCommit: '245752b6722a1a1d0f21d3a21a86564f29da25a2',
      sourceCommit: process.env.GITHUB_SHA || 'unpublished-local-draft',
      dependencies: 'Node built-ins only',
      requiresNode: '24',
    },
    null,
    2,
  ) + '\n',
);
const hashes = {};
for (const name of fs.readdirSync(out).sort())
  hashes[name] = crypto
    .createHash('sha256')
    .update(fs.readFileSync(path.join(out, name)))
    .digest('hex');
fs.writeFileSync(path.join(out, 'SHA256SUMS.json'), JSON.stringify(hashes, null, 2) + '\n');
process.stdout.write(
  'Built Node-only simulated-payment client; no application/server/database/provisioning code packaged.\n',
);
