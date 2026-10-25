import type { Request } from 'express';
import { afterEach, expect, it, vi } from 'vitest';
import { readRestriction, signReadRestriction } from '../../src/payments/internal-read.js';
const operator = '00000000-0000-4000-8000-000000000001';
const other = '00000000-0000-4000-8000-000000000002';
const key = 'SYNTHETIC-NOT-A-REAL-KEY';
function req(
  headers: Record<string, string | string[]>,
  path = '/payments',
  method = 'GET',
): Request {
  return { headers, originalUrl: path, method } as Request;
}
afterEach(() => {
  vi.useRealTimers();
});
it('binds exact method/path/key/operator/permission and expires without granting Bearer identity', () => {
  vi.useFakeTimers();
  const headers = signReadRestriction('/payments', key, operator);
  expect(readRestriction(req(headers), key)).toEqual({
    operatorId: operator,
    permission: 'read_only',
  });
  expect(readRestriction(req({}), key)).toBeUndefined();
  for (const request of [
    req(headers, '/payments?limit=1'),
    req(headers, '/payments', 'POST'),
    req({ ...headers, 'x-vaultx-read-operator': other }),
    req({ ...headers, 'x-vaultx-read-permission': 'read_write' }),
    req({ ...headers, 'x-vaultx-read-proof': '0'.repeat(64) }),
    req({ ...headers, 'x-vaultx-read-expires': ['1', '2'] }),
    req({ ...headers, 'x-vaultx-read-unknown': 'value' }),
  ])
    expect(() => readRestriction(request, key)).toThrow();
  expect(() => readRestriction(req(headers), '')).toThrow();
  expect(() => readRestriction(req(headers), 'OTHER-SYNTHETIC-KEY')).toThrow();
  vi.advanceTimersByTime(10001);
  expect(() => readRestriction(req(headers), key)).toThrow();
});
