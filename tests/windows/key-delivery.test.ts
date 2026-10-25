import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decryptForTest, readIssuedKey } from '../support/issued-key.js';
import { deliverKeyFile, encryptForWindows } from '../../src/admin/key-delivery.js';

describe.skipIf(process.platform !== 'win32')(
  'real Windows DPAPI (no credentials or database)',
  { timeout: 30_000 }, // Multiple native PowerShell startups can exceed Vitest's 5s default.
  () => {
    it('round-trips UTF-8 input under the current Windows user without plaintext output', async () => {
      const plaintext = 'SYNTHETIC-NOT-A-CREDENTIAL-\u20ac-\u03bb';
      const ciphertext = await encryptForWindows(plaintext);
      expect(ciphertext.includes(plaintext)).toBe(false);
      expect((await decryptForTest(ciphertext)) === plaintext).toBe(true);
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
        const unsealed = JSON.parse(await decryptForTest(file.ciphertext)) as {
          apiKey: string;
          environment: string;
        };
        expect(unsealed.apiKey === key.apiKey).toBe(true);
        expect(unsealed.environment).toBe('staging');
        expect((await readIssuedKey(destination)).apiKey === key.apiKey).toBe(true);
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
      await expect(decryptForTest(bytes.toString('base64'))).rejects.toThrow(
        'Native DPAPI decryption failed.',
      );
    });
  },
);
