/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require,module,process */
const fs = require('node:fs'),
  path = require('node:path');
const { execFile } = require('node:child_process');
async function decrypt(ciphertext) {
  return new Promise((resolve, reject) => {
    if (
      typeof ciphertext !== 'string' ||
      ciphertext.length > 65536 ||
      !/^[A-Za-z0-9+/]+=*$/.test(ciphertext)
    ) {
      reject(Error());
      return;
    }
    const script =
      "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security; [Console]::InputEncoding=[Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $bytes=[Convert]::FromBase64String([Console]::In.ReadToEnd()); $plain=[Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Text.Encoding]::UTF8.GetString($plain));";
    const child = execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { timeout: 15000, maxBuffer: 65536, windowsHide: true },
      (error, stdout) => {
        if (error) {
          reject(Error());
          return;
        }
        try {
          resolve(JSON.parse(stdout));
        } catch {
          reject(Error());
        }
      },
    );
    child.stdin.on('error', () => reject(Error()));
    child.stdin.end(ciphertext);
  });
}
async function readExistingKey() {
  const root = fs.realpathSync(process.env.LOCALAPPDATA),
    parent = path.join(root, 'VaultXPay', 'Secrets');
  if (fs.realpathSync(parent).toLowerCase() !== parent.toLowerCase()) throw Error();
  const file = path.join(parent, 'initial.vaultx-key.json'),
    stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536) throw Error();
  const envelope = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (envelope.format !== 'vaultx-dpapi-v1') throw Error();
  const plain = await decrypt(envelope.ciphertext);
  if (
    plain.environment !== 'staging' ||
    plain.operatorId !== envelope.operatorId ||
    plain.keyId !== envelope.keyId ||
    typeof plain.apiKey !== 'string' ||
    !/^vxp_[a-f0-9]{64}$/.test(plain.apiKey)
  )
    throw Error();
  return plain;
}
module.exports = { decrypt, readExistingKey };
