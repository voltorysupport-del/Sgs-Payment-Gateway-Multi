import { describe, expect, it, vi } from 'vitest';
import { encryptForWindows } from '../../src/admin/key-delivery.js';

const mocks = vi.hoisted(() => ({ args: [] as string[], stdin: '', fail: false }));
vi.mock('node:child_process', () => ({
  execFile: (
    _file: string,
    args: string[],
    _options: unknown,
    callback: (error: Error | null, stdout: string) => void,
  ) => {
    mocks.args = args;
    return {
      stdin: {
        on: () => undefined,
        end: (input: string) => {
          mocks.stdin = input;
          callback(mocks.fail ? new Error('synthetic-sensitive-error') : null, 'ZW5jcnlwdGVk');
        },
      },
    };
  },
}));

describe('Windows administrator-only DPAPI delivery', () => {
  it('passes secret input through stdin and returns only ciphertext', async () => {
    mocks.fail = false;
    expect(await encryptForWindows('synthetic-secret')).toBe('ZW5jcnlwdGVk');
    expect(mocks.stdin === 'synthetic-secret').toBe(true);
    expect(mocks.args.join(' ').includes('synthetic-secret')).toBe(false);
    expect(mocks.args.join(' ').includes('CurrentUser')).toBe(true);
  });
  it('suppresses process error details', async () => {
    mocks.fail = true;
    await expect(encryptForWindows('synthetic-secret')).rejects.toThrow(
      'Staging provisioning refused (delivery).',
    );
  });
});
