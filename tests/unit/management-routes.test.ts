import { createHash } from 'node:crypto';
import express from 'express';
import type { Pool } from 'pg';
import request from 'supertest';
import { beforeEach, expect, it, vi } from 'vitest';
import { createManagementRouter } from '../../src/management/routes.js';
import { executeManagement } from '../../src/management/domain.js';
import { testConfig } from '../helpers.js';

vi.mock('../../src/management/domain.js', () => ({ executeManagement: vi.fn() }));
const execute = vi.mocked(executeManagement);
const origin = 'https://owner.example.invalid';
const raw = 'a'.repeat(64),
  csrf = 'b'.repeat(64);
const ownerCookie = '__Host-vaultx_owner_session=' + raw;
const target = '00000000-0000-4000-8000-000000000001';
function app(enabled = true) {
  const result = express();
  // Disposable test transport emulates an explicitly trusted loopback TLS proxy.
  result.set('trust proxy', 'loopback');
  result.use(
    '/owner-api',
    createManagementRouter(
      {} as Pool,
      testConfig({
        OWNER_ENABLED: String(enabled),
        OWNER_ORIGIN: origin,
        DASHBOARD_PUBLIC_ORIGIN: 'https://client.example.invalid',
      }),
    ),
  );
  return result;
}
function get(path: string) {
  return request(app())
    .get('/owner-api' + path)
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', ownerCookie);
}
function patch(body: Record<string, unknown>) {
  return request(app())
    .patch('/owner-api/clients/' + target)
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', ownerCookie)
    .set('Origin', origin)
    .set('X-CSRF-Token', csrf)
    .send(body);
}
beforeEach(() => {
  execute.mockReset();
  execute.mockResolvedValue({
    ok: true,
    value: { owner: { id: target, username: 'synthetic-owner' }, permissions: [] },
  });
});
it('is default-off and performs no domain operation when disabled', async () => {
  await request(app(false)).get('/owner-api/clients').expect(404);
  expect(execute).not.toHaveBeenCalled();
});
it('accepts only the separate owner cookie and hashes it before domain dispatch', async () => {
  const response = await get('/auth/me').expect(200);
  expect(response.headers['cache-control']).toBe('no-store');
  expect(execute).toHaveBeenCalledWith(
    expect.anything(),
    createHash('sha256').update(raw).digest('hex'),
    { action: 'identity' },
    undefined,
  );
  expect(JSON.stringify(response.body)).not.toContain(raw);
});
for (const cookie of [
  '',
  '__Host-vaultx_session=' + raw,
  ownerCookie + '; ' + ownerCookie,
  '__Host-vaultx_owner_session=not-a-token',
]) {
  it(
    'rejects absent, client-realm, duplicate and malformed owner cookies without domain work: ' +
      cookie.slice(0, 30),
    async () => {
      await request(app())
        .get('/owner-api/clients')
        .set('Host', 'owner.example.invalid')
        .set('X-Forwarded-Proto', 'https')
        .set('Cookie', cookie)
        .expect(401);
      expect(execute).not.toHaveBeenCalled();
    },
  );
}
for (const fields of [
  { Host: 'client.example.invalid' },
  { Origin: 'https://client.example.invalid' },
  { 'Sec-Fetch-Site': 'cross-site' },
  { 'Sec-Fetch-Site': 'same-site' },
  { Authorization: 'Bearer synthetic-machine-key' },
  { 'X-Forwarded-Proto': 'http' },
]) {
  it(
    'rejects foreign realm, insecure transport, or mixed machine authority ' +
      JSON.stringify(fields),
    async () => {
      const req = get('/clients');
      for (const [name, value] of Object.entries(fields)) req.set(name, value);
      await req.expect(403);
      expect(execute).not.toHaveBeenCalled();
    },
  );
}
it('does not use X-Forwarded-Host as owner authority', async () => {
  await get('/clients')
    .set('Host', 'client.example.invalid')
    .set('X-Forwarded-Host', 'owner.example.invalid')
    .expect(403);
  expect(execute).not.toHaveBeenCalled();
});
for (const method of ['head', 'options', 'put', 'delete'] as const) {
  it('rejects unsupported ' + method.toUpperCase() + ' before a business action', async () => {
    await request(app())
      [method]('/owner-api/clients')
      .set('Host', 'owner.example.invalid')
      .set('X-Forwarded-Proto', 'https')
      .set('Cookie', ownerCookie)
      .expect(405);
    expect(execute).not.toHaveBeenCalled();
  });
}
for (const path of [
  '/clients?limit=51',
  '/clients?offset=-1',
  '/clients?operatorId=' + target,
  '/clients?limit=2&limit=3',
  '/clients/not-a-uuid',
  '/clients/' + target + '?role=owner',
  '/audit?limit=0',
]) {
  it('strictly bounds queries and target IDs ' + path, async () => {
    await get(path).expect(400);
    expect(execute).not.toHaveBeenCalled();
  });
}
for (const body of [
  { name: 'New name' },
  { expectedVersion: 1, role: 'owner' },
  { expectedVersion: 1, operatorId: target },
  { expectedVersion: 1, name: 'x'.repeat(121) },
  { expectedVersion: 0, name: 'name' },
  { expectedVersion: 1 },
]) {
  it(
    'rejects authority injection and invalid mutation shape ' + JSON.stringify(body).slice(0, 70),
    async () => {
      await patch(body).expect(400);
      expect(execute).not.toHaveBeenCalled();
    },
  );
}
it('requires exact write Origin, JSON and a bounded CSRF token', async () => {
  await patch({ expectedVersion: 1, name: 'Synthetic name' }).unset('Origin').expect(403);
  await patch({ expectedVersion: 1, name: 'Synthetic name' })
    .set('Origin', 'https://client.example.invalid')
    .expect(403);
  await patch({ expectedVersion: 1, name: 'Synthetic name' })
    .set('X-CSRF-Token', 'bad')
    .expect(403);
  expect(execute).not.toHaveBeenCalled();
});
it('passes only validated target, patch, precondition and hashed CSRF to the domain', async () => {
  await patch({ expectedVersion: 4, name: '  Synthetic operator  ', status: 'suspended' }).expect(
    200,
  );
  expect(execute).toHaveBeenLastCalledWith(
    expect.anything(),
    expect.any(String),
    {
      action: 'operators.update',
      targetId: target,
      expectedVersion: 4,
      patch: { name: 'Synthetic operator', status: 'suspended' },
      csrfHash: createHash('sha256').update(csrf).digest('hex'),
    },
    undefined,
  );
});
it('returns only server-generated CSRF material after authenticated domain rotation', async () => {
  const response = await get('/auth/csrf').expect(200);
  expect(response.body.csrfToken).toMatch(/^[a-f0-9]{64}$/);
  expect(execute).toHaveBeenLastCalledWith(
    expect.anything(),
    expect.any(String),
    {
      action: 'csrf.rotate',
      newCsrfHash: createHash('sha256')
        .update(response.body.csrfToken as string)
        .digest('hex'),
    },
    undefined,
  );
});
it('logout invalidates only the owner session and clears a secure host-only cookie', async () => {
  const response = await request(app())
    .post('/owner-api/auth/logout')
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', ownerCookie)
    .set('Origin', origin)
    .set('X-CSRF-Token', csrf)
    .send({})
    .expect(204);
  expect(execute).toHaveBeenLastCalledWith(
    expect.anything(),
    expect.any(String),
    {
      action: 'logout',
      csrfHash: createHash('sha256').update(csrf).digest('hex'),
    },
    undefined,
  );
  const cookie = (response.headers['set-cookie'] as unknown as string[])[0]!;
  expect(cookie).toMatch(/__Host-vaultx_owner_session=/);
  expect(cookie).toContain('Secure');
  expect(cookie).toContain('HttpOnly');
  expect(cookie).toContain('SameSite=Strict');
  expect(cookie).not.toMatch(/Domain=/i);
});
for (const [error, status] of [
  ['unauthorized', 401],
  ['forbidden', 403],
  ['not_found', 404],
  ['conflict', 409],
  ['unavailable', 503],
] as const) {
  it('sanitizes domain denial ' + error, async () => {
    execute.mockResolvedValueOnce({ ok: false, error });
    const response = await get('/clients').expect(status);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(JSON.stringify(response.body)).not.toMatch(/SELECT|token_hash|password|database_url/i);
  });
}
it('sanitizes thrown database details and malformed JSON', async () => {
  execute.mockRejectedValueOnce(new Error('SELECT password_hash FROM private_secrets'));
  const response = await get('/clients').expect(503);
  expect(JSON.stringify(response.body)).not.toMatch(/SELECT|password_hash|private_secrets/);
  await request(app())
    .patch('/owner-api/clients/' + target)
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', ownerCookie)
    .set('Origin', origin)
    .set('X-CSRF-Token', csrf)
    .set('Content-Type', 'application/json')
    .send('{')
    .expect(400);
});

it('refuses owner routes in production even if a forged Config bypasses parsing', async () => {
  const server = express();
  const config = testConfig({
    OWNER_ENABLED: 'true',
    OWNER_ORIGIN: origin,
    DASHBOARD_PUBLIC_ORIGIN: 'https://client.example.invalid',
  });
  server.use(
    '/owner-api',
    createManagementRouter({} as Pool, { ...config, nodeEnv: 'production' }),
  );
  await request(server).get('/owner-api/clients').expect(404);
  expect(execute).not.toHaveBeenCalled();
});

it('creates merchant organizations without a key or browser-supplied owner identity', async () => {
  await request(app())
    .post('/owner-api/clients')
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', ownerCookie)
    .set('Origin', origin)
    .set('X-CSRF-Token', csrf)
    .send({ code: 'synthetic-merchant', name: 'Synthetic Merchant' })
    .expect(201);
  expect(execute).toHaveBeenLastCalledWith(
    expect.anything(),
    expect.any(String),
    {
      action: 'operators.create',
      code: 'synthetic-merchant',
      name: 'Synthetic Merchant',
      csrfHash: createHash('sha256').update(csrf).digest('hex'),
    },
    undefined,
  );
  execute.mockClear();
  await request(app())
    .post('/owner-api/clients')
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', ownerCookie)
    .set('Origin', origin)
    .set('X-CSRF-Token', csrf)
    .send({ code: 'synthetic-merchant', name: 'Synthetic Merchant', ownerId: target })
    .expect(400);
  expect(execute).not.toHaveBeenCalled();
});
it('dispatches explicit administrator invitation intent without enrollment tokens or browser role elevation', async () => {
  await request(app())
    .post('/owner-api/clients/' + target + '/administrator-invitations')
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', ownerCookie)
    .set('Origin', origin)
    .set('X-CSRF-Token', csrf)
    .send({
      username: 'synthetic-admin',
      permissions: ['client.users.manage_subaccounts'],
      terminalIds: [],
    })
    .expect(201);
  expect(execute).toHaveBeenLastCalledWith(
    expect.anything(),
    expect.any(String),
    {
      action: 'invitations.create_admin',
      targetId: target,
      username: 'synthetic-admin',
      permissions: ['client.users.manage_subaccounts'],
      terminalIds: [],
      csrfHash: createHash('sha256').update(csrf).digest('hex'),
    },
    undefined,
  );
});
