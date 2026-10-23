import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { IssuedOperatorKey } from '../db/operator-keys.js';
import { ProvisioningError } from './staging-config.js';

const projectDirectory = fileURLToPath(new URL('../../', import.meta.url));

export async function encryptForWindows(plaintext: string): Promise<string> {
  // Secret input travels only over stdin; neither argv nor stdout contains it.
  return new Promise((resolve, reject) => {
    const script = `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security;
      [Console]::InputEncoding=[Text.UTF8Encoding]::new($false);
      $bytes=[Text.Encoding]::UTF8.GetBytes([Console]::In.ReadToEnd());
      $sealed=[Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);
      [Console]::Out.Write([Convert]::ToBase64String($sealed));`;
    const child = execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { timeout: 15_000, maxBuffer: 64 * 1024, windowsHide: true },
      (error, stdout) => {
        if (error || !/^[A-Za-z0-9+/]+=*$/.test(stdout)) reject(new ProvisioningError('delivery'));
        else resolve(stdout);
      },
    );
    child.stdin?.on('error', () => reject(new ProvisioningError('delivery')));
    child.stdin?.end(plaintext);
  });
}

/** Explicit one-time delivery, never a log stream. Existing paths are never overwritten. */
export async function deliverKeyFile(destination: string, key: IssuedOperatorKey): Promise<void> {
  try {
    if (!path.isAbsolute(destination)) throw new Error();
    const parent = path.dirname(destination);
    const canonicalParent = await realpath(parent);
    const repository = await realpath(projectDirectory);
    const relative = path.relative(repository, canonicalParent);
    if (
      !relative ||
      (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative))
    )
      throw new Error();
    // Reject directory symlinks and require a private parent on POSIX.
    const comparable = (value: string) =>
      process.platform === 'win32' ? value.toLowerCase() : value;
    if (comparable(path.resolve(parent)) !== comparable(canonicalParent)) throw new Error();
    const stat = await lstat(parent);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error();
    if (
      process.platform !== 'win32' &&
      ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.())
    )
      throw new Error();

    const plaintext = JSON.stringify({ ...key, environment: 'staging' });
    const content =
      process.platform === 'win32'
        ? JSON.stringify({
            format: 'vaultx-dpapi-v1',
            operatorId: key.operatorId,
            keyId: key.keyId,
            ciphertext: await encryptForWindows(plaintext),
          })
        : plaintext;
    const file = await open(
      destination,
      constants.O_CREAT |
        constants.O_EXCL |
        constants.O_WRONLY |
        (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW),
      0o600,
    );
    try {
      await file.writeFile(content + '\n', 'utf8');
      await file.sync();
    } finally {
      await file.close();
    }
  } catch {
    throw new ProvisioningError('delivery');
  }
}
