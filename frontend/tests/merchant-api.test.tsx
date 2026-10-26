import { afterEach, expect, it, vi } from 'vitest';
import { merchantApi, MerchantApiError, type MerchantIdentity } from '../src/merchant/api';
const user = '11111111-1111-4111-8111-111111111111';
const tenant = '22222222-2222-4222-8222-222222222222';
const membership = '33333333-3333-4333-8333-333333333333';
const identity: MerchantIdentity = {
  user: { id: user, username: 'synthetic_admin' },
  operator: { id: tenant },
  membership: { id: membership, version: 1 },
  permissions: [
    'client.users.manage_subaccounts',
    'client.payments.read',
    'client.permissions.delegate',
  ],
};
const response = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  Object.defineProperty(navigator, 'locks', { configurable: true, value: undefined });
});
it('uses only fixed same-origin URLs with no-store, redirect refusal and bounded timeout', async () => {
  const fetcher = vi.fn().mockResolvedValue(response(identity));
  vi.stubGlobal('fetch', fetcher);
  await expect(merchantApi.me()).resolves.toEqual(identity);
  expect(fetcher).toHaveBeenCalledWith(
    '/merchant-api/me',
    expect.objectContaining({
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      signal: expect.any(AbortSignal) as unknown,
    }),
  );
});
it('rejects malformed, foreign-page and unbounded input metadata', async () => {
  const fetcher = vi
    .fn()
    .mockResolvedValue(
      response({ members: [], pagination: { limit: 20, offset: 20, hasMore: false } }),
    );
  vi.stubGlobal('fetch', fetcher);
  await expect(merchantApi.members(0)).rejects.toMatchObject({ status: 502 });
  await expect(merchantApi.members(-20)).rejects.toMatchObject({ status: 400 });
  await expect(merchantApi.members(10020)).rejects.toMatchObject({ status: 400 });
  expect(fetcher).toHaveBeenCalledTimes(1);
});
it('fails closed when Web Locks cannot serialize client CSRF/session mutations', async () => {
  const fetcher = vi.fn();
  vi.stubGlobal('fetch', fetcher);
  await expect(
    merchantApi.invite(identity, {
      username: 'synthetic_user',
      permissions: ['client.payments.read'],
      terminalIds: [],
    }),
  ).rejects.toMatchObject({ status: 503 });
  expect(fetcher).not.toHaveBeenCalled();
});
it('rechecks subject, tenant, membership and version before obtaining CSRF or posting', async () => {
  Object.defineProperty(navigator, 'locks', {
    configurable: true,
    value: {
      request: async (_name: string, _options: unknown, work: () => Promise<unknown>) => work(),
    },
  });
  const fetcher = vi
    .fn()
    .mockResolvedValue(
      response({ ...identity, membership: { ...identity.membership, version: 2 } }),
    );
  vi.stubGlobal('fetch', fetcher);
  await expect(
    merchantApi.invite(identity, {
      username: 'synthetic_user',
      permissions: ['client.payments.read'],
      terminalIds: [],
    }),
  ).rejects.toMatchObject({ status: 401 });
  expect(fetcher).toHaveBeenCalledTimes(1);
});
it('records pending intent with a private CSRF header, never an activation token', async () => {
  const lock = vi.fn(async (_name: string, _options: unknown, work: () => Promise<unknown>) =>
    work(),
  );
  Object.defineProperty(navigator, 'locks', { configurable: true, value: { request: lock } });
  const csrf = 'a'.repeat(64);
  const fetcher = vi
    .fn()
    .mockResolvedValueOnce(response(identity))
    .mockResolvedValueOnce(response({ csrfToken: csrf }))
    .mockResolvedValueOnce(
      response(
        {
          invitationId: '44444444-4444-4444-8444-444444444444',
          expiresAt: '2026-10-27T00:00:00.000Z',
          status: 'pending',
          activationEnabled: false,
        },
        201,
      ),
    );
  vi.stubGlobal('fetch', fetcher);
  await merchantApi.invite(identity, {
    username: 'synthetic_user',
    permissions: ['client.payments.read'],
    terminalIds: [],
  });
  expect(lock).toHaveBeenCalledWith(
    'vaultx-dashboard-auth',
    { mode: 'exclusive' },
    expect.any(Function),
  );
  expect(fetcher).toHaveBeenLastCalledWith(
    '/merchant-api/invitations',
    expect.objectContaining({
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({
        username: 'synthetic_user',
        permissions: ['client.payments.read'],
        terminalIds: [],
      }),
    }),
  );
});
it('sanitizes upstream failure detail', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(response({ error: 'private internal detail' }, 503)),
  );
  const failure = await merchantApi.me().catch((error: unknown) => error);
  expect(failure).toBeInstanceOf(MerchantApiError);
  expect(String(failure)).not.toContain('private internal');
});
