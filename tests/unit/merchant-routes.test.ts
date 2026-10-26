import { createHash } from 'node:crypto';
import express from 'express';
import type { Pool } from 'pg';
import request from 'supertest';
import { beforeEach, expect, it, vi } from 'vitest';
import { createMerchantRouter } from '../../src/management/merchant-routes.js';
import { executeMerchantCommand } from '../../src/management/merchant-session.js';
import { testConfig } from '../helpers.js';
vi.mock('../../src/management/merchant-session.js', () => ({ executeMerchantCommand: vi.fn() }));
const execute = vi.mocked(executeMerchantCommand);
const origin = 'https://client.example.invalid',
  raw = 'a'.repeat(64),
  csrf = 'b'.repeat(64);
const member = '00000000-0000-4000-8000-000000000001';
function app(enabled = true) {
  const app = express();
  app.set('trust proxy', 'loopback');
  app.use(
    '/merchant-api',
    createMerchantRouter(
      {} as Pool,
      testConfig({
        DASHBOARD_ENABLED: 'true',
        DASHBOARD_PUBLIC_ORIGIN: origin,
        MERCHANT_MANAGEMENT_ENABLED: String(enabled),
      }),
    ),
  );
  return app;
}
function get(path = '/members') {
  return request(app())
    .get('/merchant-api' + path)
    .set('Host', 'client.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', '__Host-vaultx_session=' + raw);
}
function post(path: string, body: string | object) {
  return request(app())
    .post('/merchant-api' + path)
    .set('Host', 'client.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', '__Host-vaultx_session=' + raw)
    .set('Origin', origin)
    .set('X-CSRF-Token', csrf)
    .send(body);
}
beforeEach(() => {
  execute.mockReset();
  execute.mockResolvedValue({ ok: true, value: { members: [] } });
});
it('keeps the new client management feature default-off', async () => {
  await request(app(false)).get('/merchant-api/members').expect(404);
  expect(execute).not.toHaveBeenCalled();
});
it('uses only hashed authenticated client session material and no browser tenant authority', async () => {
  const response = await get('/members?limit=3&offset=1').expect(200);
  expect(response.headers['cache-control']).toBe('no-store');
  expect(execute).toHaveBeenLastCalledWith(
    expect.anything(),
    createHash('sha256').update(raw).digest('hex'),
    { action: 'members.list', limit: 3, offset: 1 },
    undefined,
    undefined,
  );
  expect(JSON.stringify(response.body)).not.toContain(raw);
  await get('/members?operatorId=' + member).expect(400);
});
it('rejects owner cookies, mixed bearer authority and duplicate cookies', async () => {
  await get()
    .set('Cookie', '__Host-vaultx_owner_session=' + raw)
    .expect(401);
  await get()
    .set('Cookie', '__Host-vaultx_session=' + raw + '; __Host-vaultx_session=' + raw)
    .expect(401);
  await get().set('Authorization', 'Bearer synthetic').expect(403);
  expect(execute).not.toHaveBeenCalled();
});
for (const headers of [
  { Host: 'owner.example.invalid' },
  { Origin: 'https://foreign.invalid' },
  { 'X-Forwarded-Proto': 'http' },
  { 'Sec-Fetch-Site': 'same-site' },
  { 'Sec-Fetch-Site': 'cross-site' },
]) {
  it('refuses foreign/insecure client transport ' + JSON.stringify(headers), async () => {
    const req = get();
    for (const [key, value] of Object.entries(headers)) req.set(key, value);
    await req.expect(403);
    expect(execute).not.toHaveBeenCalled();
  });
}
for (const method of ['head', 'options', 'patch', 'put', 'delete'] as const) {
  it('rejects unsupported ' + method, async () => {
    await request(app())
      [method]('/merchant-api/members')
      .set('Host', 'client.example.invalid')
      .set('X-Forwarded-Proto', 'https')
      .set('Cookie', '__Host-vaultx_session=' + raw)
      .expect(405);
    expect(execute).not.toHaveBeenCalled();
  });
}
it('rejects write requests without same-origin JSON CSRF before dispatch', async () => {
  const body = {
    username: 'synthetic-user',
    permissions: ['client.payments.read'],
    terminalIds: [],
  };
  await post('/invitations', body).unset('Origin').expect(403);
  await post('/invitations', body).set('X-CSRF-Token', 'bad').expect(403);
  await post('/invitations', { ...body, operatorId: member }).expect(400);
  await post('/invitations', { ...body, permissions: ['platform.clients.manage'] }).expect(400);
  await post('/invitations', {
    ...body,
    permissions: ['client.payments.read', 'client.payments.read'],
  }).expect(400);
  expect(execute).not.toHaveBeenCalled();
});
it('dispatches strict submerchant invitations with no authoritative tenant/role input', async () => {
  await post('/invitations', {
    username: 'synthetic-user',
    permissions: ['client.payments.read'],
    terminalIds: [member],
  }).expect(201);
  expect(execute).toHaveBeenLastCalledWith(
    expect.anything(),
    expect.any(String),
    {
      action: 'invitations.create',
      username: 'synthetic-user',
      permissions: ['client.payments.read'],
      terminalIds: [member],
    },
    createHash('sha256').update(csrf).digest('hex'),
    undefined,
  );
});
it('requires immutable member IDs and bounded optimistic versions for reducers', async () => {
  await post('/members/' + member + '/disable', { expectedVersion: 3 }).expect(200);
  expect(execute).toHaveBeenLastCalledWith(
    expect.anything(),
    expect.any(String),
    { action: 'members.disable', membershipId: member, expectedVersion: 3 },
    expect.any(String),
    undefined,
  );
  execute.mockClear();
  await post('/members/not-an-id/disable', { expectedVersion: 3 }).expect(400);
  await post('/members/' + member + '/disable', { expectedVersion: 0 }).expect(400);
  await post('/members/' + member + '/grants/platform.audit.read/withdraw', {
    expectedVersion: 3,
  }).expect(400);
  expect(execute).not.toHaveBeenCalled();
});
it('sanitizes thrown private database details and JSON parser failures', async () => {
  execute.mockRejectedValueOnce(new Error('SELECT password_hash FROM secrets connection_url'));
  const result = await get().expect(503);
  expect(JSON.stringify(result.body)).not.toMatch(/password_hash|SELECT|connection_url|secrets/);
  await post('/invitations', '{').set('Content-Type', 'application/json').expect(400);
});
it('disallows malformed and excessive pagination', async () => {
  for (const path of [
    '/members?limit=51',
    '/members?limit=2&limit=3',
    '/terminals?offset=-1',
    '/audit?offset=10001',
  ])
    await get(path).expect(400);
  expect(execute).not.toHaveBeenCalled();
});
