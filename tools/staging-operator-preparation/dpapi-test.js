/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, module, process, __dirname, Buffer */
const assert = require('node:assert/strict'),
  fs = require('node:fs/promises'),
  path = require('node:path'),
  os = require('node:os');
const { pathToFileURL } = require('node:url'),
  { execFile } = require('node:child_process');
function decrypt(ciphertext) {
  return new Promise((resolve, reject) => {
    const script = `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security;
    [Console]::InputEncoding=[Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);
    $bytes=[Convert]::FromBase64String([Console]::In.ReadToEnd());
    $plain=[Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);
    [Console]::Out.Write([Text.Encoding]::UTF8.GetString($plain));`;
    const child = execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { timeout: 15000, maxBuffer: 65536, windowsHide: true },
      (error, stdout) => {
        if (error) reject(new Error('DPAPI test failed.'));
        else resolve(stdout);
      },
    );
    child.stdin.on('error', () => reject(new Error('DPAPI test input failed.')));
    child.stdin.end(ciphertext);
  });
}
async function runDpapiTests() {
  if (process.platform !== 'win32') throw new Error('Windows required.');
  const { encryptForWindows, deliverKeyFile } = await import(
    pathToFileURL(path.join(__dirname, 'pinned-app/dist/admin/key-delivery.js')).href
  );
  const synthetic = 'SYNTHETIC-NOT-A-CREDENTIAL-\u20ac-\u03bb';
  const ciphertext = await encryptForWindows(synthetic);
  assert.ok(!ciphertext.includes(synthetic));
  assert.ok((await decrypt(ciphertext)) === synthetic);
  const directory = await fs.realpath(
    await fs.mkdtemp(path.join(os.tmpdir(), 'vaultx-dpapi-preparation-')),
  );
  try {
    const destination = path.join(directory, 'synthetic.vaultx-key.json');
    // Deliberately invalid credential, not a generated or usable operator API key.
    const fixture = {
      operatorId: '00000000-0000-4000-8000-000000000001',
      keyId: '00000000-0000-4000-8000-000000000002',
      apiKey: 'SYNTHETIC-NOT-A-VALID-API-KEY',
    };
    await deliverKeyFile(destination, fixture);
    const sealed = await fs.readFile(destination, 'utf8'),
      envelope = JSON.parse(sealed);
    assert.equal(envelope.format, 'vaultx-dpapi-v1');
    assert.ok(!sealed.includes(fixture.apiKey));
    const plain = JSON.parse(await decrypt(envelope.ciphertext));
    assert.ok(plain.apiKey === fixture.apiKey);
    assert.equal(plain.environment, 'staging');
    await assert.rejects(deliverKeyFile(destination, fixture));
    assert.ok((await fs.readFile(destination, 'utf8')) === sealed);
    const bytes = Buffer.from(ciphertext, 'base64');
    bytes[bytes.length - 1] ^= 0xff;
    await assert.rejects(decrypt(bytes.toString('base64')));
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
  process.stdout.write(
    'PASS: 3 credential-free native DPAPI checks using pinned delivery code; no real key generated.\n',
  );
}
module.exports = { runDpapiTests };
