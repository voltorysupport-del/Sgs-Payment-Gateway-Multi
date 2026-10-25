import { expect, it } from 'vitest';
import { hashDashboardPassword, verifyDashboardPassword } from '../../src/dashboard/passwords.js';
import { testConfig } from '../helpers.js';
it('uses salted Argon2id, validates length and rejects wrong or invalid verifiers', async () => {
  const password = 'SYNTHETIC long password €';
  const a = await hashDashboardPassword(password),
    b = await hashDashboardPassword(password);
  expect(a.startsWith('$argon2id$')).toBe(true);
  expect(a === b).toBe(false);
  expect(await verifyDashboardPassword(a, password)).toBe(true);
  expect(await verifyDashboardPassword(a, 'wrong')).toBe(false);
  expect(await verifyDashboardPassword('invalid', password)).toBe(false);
  expect(() => hashDashboardPassword('short')).toThrow();
  expect(() => hashDashboardPassword('x'.repeat(129))).toThrow();
});
it('requires explicit feature enablement and an exact HTTPS origin', () => {
  expect(testConfig().dashboardEnabled).toBe(false);
  for (const value of [
    'http://example.invalid',
    'https://example.invalid/path',
    'https://user:password@example.invalid',
    'https://example.invalid/',
  ]) {
    expect(() =>
      testConfig({ DASHBOARD_ENABLED: 'true', DASHBOARD_PUBLIC_ORIGIN: value }),
    ).toThrow();
  }
  expect(() => testConfig({ DASHBOARD_ENABLED: 'true' })).toThrow();
});
it('rejects broad or ambiguous proxy trust and accepts explicit network boundaries', () => {
  for (const value of ['true', '1', '0.0.0.0/0', '::/0', 'loopback', 'bad'])
    expect(() => testConfig({ DASHBOARD_TRUSTED_PROXIES: value })).toThrow();
  expect(
    testConfig({ DASHBOARD_TRUSTED_PROXIES: '127.0.0.1/32,::1/128' }).dashboardTrustedProxies,
  ).toHaveLength(2);
});
