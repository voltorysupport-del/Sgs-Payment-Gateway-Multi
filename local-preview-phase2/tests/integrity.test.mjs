/* global URL */
import process from 'node:process';
import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdtemp, rm, writeFile, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
test('manifest accepts intact package and rejects tampering, additions and missing files without disclosure', async (t) => {
  const temporary = await mkdtemp(path.join(tmpdir(), 'vaultx-demo-integrity-'));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const root = path.join(temporary, 'copy');
  await cp(fileURLToPath(new URL('../', import.meta.url)), root, { recursive: true });
  const run = () =>
    spawnSync(process.execPath, ['scripts/verify.mjs'], {
      cwd: root,
      encoding: 'utf8',
      shell: false,
    });
  assert.equal(run().status, 0);
  await writeFile(path.join(root, 'unexpected.txt'), 'synthetic-sensitive-canary');
  const extra = run();
  assert.equal(extra.status, 1);
  assert.equal((extra.stdout + extra.stderr).includes('synthetic-sensitive-canary'), false);
  await unlink(path.join(root, 'unexpected.txt'));
  assert.equal(run().status, 0);
  await writeFile(path.join(root, 'public/app.js'), 'synthetic-sensitive-canary');
  const changed = run();
  assert.equal(changed.status, 1);
  assert.equal((changed.stdout + changed.stderr).includes('synthetic-sensitive-canary'), false);
  await unlink(path.join(root, 'public/app.js'));
  assert.equal(run().status, 1);
});
