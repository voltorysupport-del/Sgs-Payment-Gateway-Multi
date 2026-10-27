/* global URL */
import process from 'node:process';
// Hash manifest is an integrity check, not a publisher signature. Obtain ZIP only from the reviewed Actions run.
import { createHash } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
export async function verify() {
  if (Number(process.versions.node.split('.')[0]) !== 24)
    throw new Error('Node.js 24 LTS required.');
  const manifest = JSON.parse(await readFile(path.join(root, 'SHA256SUMS.json'), 'utf8'));
  const expected = Object.keys(manifest.files ?? {});
  if (manifest.algorithm !== 'SHA-256' || expected.length < 8 || expected.length > 100)
    throw new Error('Invalid integrity manifest.');
  async function walk(folder) {
    const output = [];
    for (const name of await readdir(folder)) {
      const full = path.join(folder, name),
        stat = await lstat(full);
      if (stat.isSymbolicLink() || (!stat.isFile() && !stat.isDirectory()))
        throw new Error('Unexpected package entry.');
      if (stat.isDirectory()) output.push(...(await walk(full)));
      else output.push(path.relative(root, full).split(path.sep).join('/'));
    }
    return output;
  }
  const actual = (await walk(root)).filter((p) => p !== 'SHA256SUMS.json').sort();
  if (JSON.stringify(expected.sort()) !== JSON.stringify(actual))
    throw new Error('Package contents do not match integrity manifest.');
  for (const name of expected) {
    if (
      !/^[A-Za-z0-9_./-]+$/.test(name) ||
      name.split('/').includes('..') ||
      path.isAbsolute(name) ||
      !/^[a-f0-9]{64}$/.test(manifest.files[name])
    )
      throw new Error('Invalid integrity entry.');
    const hash = createHash('sha256')
      .update(await readFile(path.join(root, name)))
      .digest('hex');
    if (hash !== manifest.files[name]) throw new Error('Package integrity mismatch.');
  }
  return actual.length;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  verify()
    .then((count) =>
      process.stdout.write(`PASS: ${count} package files match SHA-256 integrity manifest.`),
    )
    .catch(() => {
      process.stderr.write(
        'STOP: Node.js 24 LTS and an unchanged complete extracted package are required. Download the verified package again; do not change files or bypass this check.',
      );
      process.exitCode = 1;
    });
