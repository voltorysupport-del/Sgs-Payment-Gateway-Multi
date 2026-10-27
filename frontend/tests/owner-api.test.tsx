import { afterEach, expect, it, vi } from 'vitest';
import { ownerApi, ownerIdentitySchema, OwnerApiError } from '../src/owner/api';
const target = '22222222-2222-4222-8222-222222222222';
const operator = { id: target, code: 'synthetic', name: 'Synthetic', status: 'active', version: 2 };
const response = (data: unknown, status = 200) =>
  ({ ok: status < 400, status, json: () => Promise.resolve(data) }) as Response;
afterEach(() => vi.unstubAllGlobals());
it('rejects viewer roles and unknown/wildcard platform permissions', () => {
  expect(
    ownerIdentitySchema.safeParse({ user: { id: target, username: 'viewer' }, role: 'viewer' })
      .success,
  ).toBe(false);
  expect(
    ownerIdentitySchema.safeParse({ owner: { id: target, username: 'owner' }, permissions: ['*'] })
      .success,
  ).toBe(false);
});
it('uses fixed same-origin paths, cookie credentials and no-store with no Authorization header', async () => {
  const fetch = vi
    .fn()
    .mockResolvedValue(
      response({ operators: [operator], pagination: { limit: 20, offset: 0, hasMore: false } }),
    );
  vi.stubGlobal('fetch', fetch);
  await ownerApi.operators(0);
  expect(fetch).toHaveBeenCalledWith(
    '/owner-api/clients?limit=20&offset=0',
    expect.objectContaining({ credentials: 'same-origin', cache: 'no-store', redirect: 'error' }),
  );
  expect((fetch.mock.calls[0]?.[1] as RequestInit).headers).toBeUndefined();
});
it('obtains fresh owner CSRF and sends versioned JSON PATCH for status', async () => {
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(response({ csrfToken: 'a'.repeat(64) }))
    .mockResolvedValueOnce(response({ operator }));
  vi.stubGlobal('fetch', fetch);
  await ownerApi.setStatus(target, { status: 'suspended', expectedVersion: 1 });
  expect(fetch.mock.calls[0]?.[0]).toBe('/owner-api/auth/csrf');
  expect(fetch.mock.calls[1]?.[0]).toBe('/owner-api/clients/' + target);
  expect(fetch.mock.calls[1]?.[1]).toMatchObject({
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'a'.repeat(64) },
    body: JSON.stringify({ status: 'suspended', expectedVersion: 1 }),
  });
});
it('rejects mismatched selected operator identity and pagination metadata', async () => {
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(
      response({ operator: { ...operator, id: '33333333-3333-4333-8333-333333333333' } }),
    )
    .mockResolvedValueOnce(
      response({ operators: [operator], pagination: { limit: 20, offset: 20, hasMore: false } }),
    );
  vi.stubGlobal('fetch', fetch);
  await expect(ownerApi.operator(target)).rejects.toMatchObject({ status: 502 });
  await expect(ownerApi.operators(0)).rejects.toMatchObject({ status: 502 });
});
it('rejects foreign membership envelope and unknown permissions', async () => {
  const fetch = vi.fn().mockResolvedValue(
    response({
      operatorId: '33333333-3333-4333-8333-333333333333',
      members: [],
      pagination: { limit: 20, offset: 0, hasMore: false },
    }),
  );
  vi.stubGlobal('fetch', fetch);
  await expect(ownerApi.memberships(target, 0)).rejects.toMatchObject({ status: 502 });
});
it('does not place private server error content in errors', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(response({ error: 'PRIVATE DATABASE DETAILS' }, 503)),
  );
  await expect(ownerApi.operators(0)).rejects.toEqual(new OwnerApiError(503));
});

it('creates credential-free merchants and validates pending-only invitation responses', async () => {
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(response({ csrfToken: 'a'.repeat(64) }))
    .mockResolvedValueOnce(response({ operator }))
    .mockResolvedValueOnce(response({ csrfToken: 'b'.repeat(64) }))
    .mockResolvedValueOnce(
      response({
        invitationId: target,
        expiresAt: '2026-12-01T00:00:00.000Z',
        status: 'pending',
        activationEnabled: false,
      }),
    );
  vi.stubGlobal('fetch', fetch);
  await ownerApi.createMerchant({ code: 'synthetic', name: 'Synthetic' });
  expect(fetch.mock.calls[1]?.[0]).toBe('/owner-api/clients');
  expect(fetch.mock.calls[1]?.[1]).toMatchObject({
    method: 'POST',
    body: JSON.stringify({ code: 'synthetic', name: 'Synthetic' }),
  });
  await ownerApi.inviteAdministrator(target, {
    username: 'synthetic.admin',
    permissions: ['client.payments.read'],
    terminalIds: [],
  });
  expect(fetch.mock.calls[3]?.[0]).toBe(
    '/owner-api/clients/' + target + '/administrator-invitations',
  );
  const bad = vi
    .fn()
    .mockResolvedValueOnce(response({ csrfToken: 'a'.repeat(64) }))
    .mockResolvedValueOnce(
      response({
        invitationId: target,
        expiresAt: '2026-12-01T00:00:00.000Z',
        status: 'pending',
        activationEnabled: true,
      }),
    );
  vi.stubGlobal('fetch', bad);
  await expect(
    ownerApi.inviteAdministrator(target, {
      username: 'synthetic.admin',
      permissions: [],
      terminalIds: [],
    }),
  ).rejects.toMatchObject({ status: 502 });
});
