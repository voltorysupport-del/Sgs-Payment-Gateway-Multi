import { execFile } from 'node:child_process';
import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { deliverKeyFile, encryptForWindows } from '../../src/admin/key-delivery.js';

// No database, valid API key, provider, or repository secret is involved.
function decrypt(ciphertext: string): Promise<string> {
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

describe.skipIf(process.platform !== 'win32')(
  'real Windows DPAPI (no credentials or database)',
  () => {
    it('round-trips UTF-8 input under the current Windows user without plaintext output', async () => {
      const plaintext = 'SYNTHETIC-NOT-A-CREDENTIAL-\u20ac-\u03bb';
      const ciphertext = await encryptForWindows(plaintext);
      expect(ciphertext.includes(plaintext)).toBe(false);
      expect((await decrypt(ciphertext)) === plaintext).toBe(true);
    });

    it('delivers an encrypted file once and decrypts using the documented CurrentUser workflow', async () => {
      const directory = await realpath(await mkdtemp(path.join(tmpdir(), 'vaultx-dpapi-')));
      const destination = path.join(directory, 'synthetic.vaultx-key.json');
      const key = {
        operatorId: randomUUID(),
        keyId: randomUUID(),
        apiKey: 'SYNTHETIC-NOT-A-VALID-API-KEY',
      };
      try {
        await deliverKeyFile(destination, key);
        const text = await readFile(destination, 'utf8');
        const file = JSON.parse(text) as { format: string; ciphertext: string };
        expect(file.format).toBe('vaultx-dpapi-v1');
        expect(text.includes(key.apiKey)).toBe(false);
        const unsealed = JSON.parse(await decrypt(file.ciphertext)) as {
          apiKey: string;
          environment: string;
        };
        expect(unsealed.apiKey === key.apiKey).toBe(true);
        expect(unsealed.environment).toBe('staging');
        await expect(deliverKeyFile(destination, key)).rejects.toThrow(
          'Staging provisioning refused (delivery).',
        );
        expect((await readFile(destination, 'utf8')) === text).toBe(true);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    });

    it('rejects a tampered DPAPI blob', async () => {
      const ciphertext = await encryptForWindows('SYNTHETIC-NOT-A-CREDENTIAL');
      const bytes = Buffer.from(ciphertext, 'base64');
      bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 0xff;
      await expect(decrypt(bytes.toString('base64'))).rejects.toThrow(
        'Native DPAPI decryption failed.',
      );
    });
  },
);
