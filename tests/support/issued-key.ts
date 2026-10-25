import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import type { IssuedOperatorKey } from '../../src/db/operator-keys.js';

// Test-only: DPAPI plaintext is captured in memory, never inherited console output.
export function decryptForTest(ciphertext: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const script = `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security;
      [Console]::InputEncoding=[Text.UTF8Encoding]::new($false);
      [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);
      $bytes=[Convert]::FromBase64String([Console]::In.ReadToEnd());
      $plain=[Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);
      [Console]::Out.Write([Text.Encoding]::UTF8.GetString($plain));`;
    const child = execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { timeout: 15_000, maxBuffer: 64 * 1024, windowsHide: true },
      (error, stdout) => {
        if (error) reject(new Error('Native DPAPI decryption failed.'));
        else resolve(stdout);
      },
    );
    child.stdin?.on('error', () => reject(new Error('Native DPAPI input failed.')));
    child.stdin?.end(ciphertext);
  });
}

export async function readIssuedKey(destination: string): Promise<IssuedOperatorKey> {
  let text = await readFile(destination, 'utf8');
  if (process.platform === 'win32') {
    const envelope = JSON.parse(text) as { format?: string; ciphertext?: string };
    if (envelope.format !== 'vaultx-dpapi-v1' || typeof envelope.ciphertext !== 'string')
      throw new Error('Expected a DPAPI-protected test key file.');
    text = await decryptForTest(envelope.ciphertext);
  }
  const key = JSON.parse(text) as IssuedOperatorKey;
  if (typeof key.apiKey !== 'string' || !key.apiKey || !key.operatorId || !key.keyId)
    throw new Error('Invalid issued test key file.');
  return key;
}
