/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, process, __dirname */
const fs = require('node:fs'),
  path = require('node:path'),
  os = require('node:os'),
  crypto = require('node:crypto'),
  assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const COMMIT = '245752b6722a1a1d0f21d3a21a86564f29da25a2';
const root = path.resolve(__dirname, '../..'),
  destination = path.resolve(process.argv[2] || '');
function git(args) {
  return execFileSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}
assert.ok(process.argv[2] && !fs.existsSync(destination));
const relative = path.relative(root, destination);
assert.ok(relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative));
const pinnedLock = JSON.parse(git(['show', COMMIT + ':package-lock.json']));
assert.deepEqual(
  JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8')),
  pinnedLock,
);
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultx-pinned-build-'));
try {
  const source = path.join(temporary, 'source');
  fs.mkdirSync(source);
  const files = git(['ls-tree', '-r', '--name-only', COMMIT, 'src']).trim().split(/\r?\n/);
  for (const file of [...files, 'package.json', 'tsconfig.json', 'tsconfig.build.json']) {
    assert.ok(!path.isAbsolute(file) && !file.split('/').includes('..'));
    const target = path.join(source, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, git(['show', COMMIT + ':' + file]));
  }
  // Temporary dependency link only; never bundled. Windows junctions need no
  // developer-mode symlink permission. Original compiler settings remain unchanged.
  fs.symlinkSync(
    path.join(root, 'node_modules'),
    path.join(source, 'node_modules'),
    process.platform === 'win32' ? 'junction' : 'dir',
  );
  assert.equal(
    JSON.parse(fs.readFileSync(path.join(root, 'node_modules/typescript/package.json'), 'utf8'))
      .version,
    pinnedLock.packages['node_modules/typescript'].version,
  );
  execFileSync(
    process.execPath,
    [
      path.join(root, 'node_modules/typescript/bin/tsc'),
      '-p',
      path.join(source, 'tsconfig.build.json'),
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  fs.mkdirSync(destination, { recursive: true });
  for (const file of [
    'reconcile.js',
    'console-input.js',
    'status-check.js',
    'Start-Reconciliation.cmd',
    'README.txt',
    'DIAGNOSTIC-FINDINGS.md',
    'package.json',
  ]) {
    fs.copyFileSync(path.join(__dirname, file), path.join(destination, file));
  }
  const modules = [
    'admin/staging-config.js',
    'admin/staging-operator.js',
    'db/operator-keys.js',
    'config/index.js',
    'config/safety.js',
  ];
  for (const file of modules) {
    const target = path.join(destination, 'pinned-app/dist', file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(source, 'dist', file), target);
  }
  fs.writeFileSync(
    path.join(destination, 'pinned-app/package.json'),
    JSON.stringify({ private: true, type: 'module' }),
  );
  const dependencies = {};
  function copy(name) {
    if (Object.hasOwn(dependencies, name)) return;
    const folder = path.join(root, 'node_modules', name),
      data = JSON.parse(fs.readFileSync(path.join(folder, 'package.json'), 'utf8'));
    assert.equal(data.version, pinnedLock.packages['node_modules/' + name].version);
    assert.ok(!fs.lstatSync(folder).isSymbolicLink());
    dependencies[name] = data.version;
    fs.cpSync(folder, path.join(destination, 'node_modules', name), {
      recursive: true,
      filter: (file) => !path.basename(file).startsWith('.'),
    });
    for (const dependency of Object.keys(data.dependencies || {})) copy(dependency);
  }
  copy('pg');
  copy('zod');
  fs.writeFileSync(
    path.join(destination, 'PROVENANCE.json'),
    JSON.stringify(
      {
        applicationCommit: COMMIT,
        sourceCommit: process.env.GITHUB_SHA || 'unpublished-local-reconciliation',
        includedPinnedModules: modules,
        dependencies,
      },
      null,
      2,
    ) + '\n',
  );
  const hashes = {};
  function walk(folder) {
    for (const entry of fs.readdirSync(folder).sort()) {
      const file = path.join(folder, entry),
        stat = fs.lstatSync(file);
      assert.ok(!stat.isSymbolicLink());
      if (stat.isDirectory()) walk(file);
      else
        hashes[path.relative(destination, file).split(path.sep).join('/')] = crypto
          .createHash('sha256')
          .update(fs.readFileSync(file))
          .digest('hex');
    }
  }
  walk(destination);
  fs.writeFileSync(
    path.join(destination, 'SHA256SUMS.json'),
    JSON.stringify(hashes, null, 2) + '\n',
  );
  process.stdout.write(
    'Built read-only reconciliation package; no CLI entry, issuer, worker, server or payment entry packaged.\n',
  );
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
