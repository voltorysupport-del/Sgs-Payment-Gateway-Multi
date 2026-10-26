import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import request from 'supertest';
import { beforeAll, beforeEach, afterEach, afterAll, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { runMigrations } from '../../src/db/migrate.js';
import { createOperatorWithApiKey } from '../../src/db/operator-keys.js';
import { openTestDatabase } from '../test-database.js';
import { captureLogger, testConfig } from '../helpers.js';
import { createOwnerFixture, cleanupOwnerFixture } from '../management-fixtures.js';
import {
  seedViewerFixture,
  cleanupViewerFixture,
  insertViewerSession,
} from '../viewer-policy-fixtures.js';

let pool: Pool;
let owner: Awaited<ReturnType<typeof createOwnerFixture>>;
let operator: string, otherOperator: string, user: string, otherUser: string;
let membership: string, otherMembership: string, viewerCookie: string, machineKey: string;
const otherOwners: string[] = [];
const origin = 'https://owner.example.invalid';
const captured = captureLogger();
function app() {
  return createApp({
    pool,
    logger: captured.logger,
    config: testConfig({
      OWNER_ENABLED: 'true',
      OWNER_ORIGIN: origin,
      DASHBOARD_ENABLED: 'true',
      DASHBOARD_PUBLIC_ORIGIN: 'https://client.example.invalid',
      DASHBOARD_TRUSTED_PROXIES: '127.0.0.1,::1',
    }),
  });
}
function get(path: string, cookie = '__Host-vaultx_owner_session=' + owner.token) {
  return request(app())
    .get('/owner-api' + path)
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', cookie);
}
function change(
  body: Record<string, unknown>,
  cookie = '__Host-vaultx_owner_session=' + owner.token,
  csrf = owner.csrf,
) {
  return request(app())
    .patch('/owner-api/clients/' + operator)
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', cookie)
    .set('Origin', origin)
    .set('X-CSRF-Token', csrf)
    .send(body);
}
beforeAll(async () => {
  pool = await openTestDatabase();
  await runMigrations(pool);
});
beforeEach(async () => {
  otherOwners.length = 0;
  owner = await createOwnerFixture(pool);
  const first = await createOperatorWithApiKey(
    pool,
    'HTTP management synthetic',
    'http_' + randomUUID(),
  );
  const second = await createOperatorWithApiKey(
    pool,
    'Other HTTP synthetic',
    'http_other_' + randomUUID(),
  );
  operator = first.operatorId;
  otherOperator = second.operatorId;
  machineKey = first.apiKey;
  const members = [];
  for (const op of [operator, otherOperator]) {
    const id = randomUUID(),
      mid = randomUUID();
    await pool.query('INSERT INTO dashboard_users(id,username,password_hash) VALUES($1,$2,$3)', [
      id,
      'http_' + id,
      'synthetic-unused-verifier',
    ]);
    await pool.query('INSERT INTO dashboard_memberships(id,user_id,operator_id) VALUES($1,$2,$3)', [
      mid,
      id,
      op,
    ]);
    await seedViewerFixture(pool, id);
    members.push({ id, mid });
  }
  user = members[0]!.id;
  membership = members[0]!.mid;
  otherUser = members[1]!.id;
  otherMembership = members[1]!.mid;
  const raw = randomBytes(32).toString('hex');
  await insertViewerSession(
    pool,
    user,
    createHash('sha256').update(raw).digest('hex'),
    randomBytes(32).toString('hex'),
  );
  viewerCookie = '__Host-vaultx_session=' + raw;
});
afterEach(async () => {
  for (const id of [owner.id, ...otherOwners]) await cleanupOwnerFixture(pool, id);
  for (const id of [user, otherUser]) await cleanupViewerFixture(pool, id);
  for (const id of [operator, otherOperator]) {
    await pool.query('DELETE FROM operator_api_keys WHERE operator_id=$1', [id]);
    await pool.query('DELETE FROM operators WHERE id=$1', [id]);
  }
});
afterAll(async () => {
  await pool?.end();
});
it('authenticates only the owner realm; viewer cookies, machine keys and owner cookies never substitute for each other', async () => {
  await get('/auth/me').expect(200);
  await get('/clients', viewerCookie).expect(401);
  await get('/clients', viewerCookie)
    .set('Authorization', 'Bearer ' + machineKey)
    .expect(403);
  await request(app())
    .get('/dashboard-api/auth/me')
    .set('Cookie', '__Host-vaultx_owner_session=' + owner.token)
    .expect(401);
  await request(app())
    .get('/payments')
    .set('Cookie', '__Host-vaultx_owner_session=' + owner.token)
    .expect(401);
  await request(app())
    .get('/payments')
    .set('Authorization', 'Bearer ' + owner.token)
    .expect(401);
});
it('returns audited operator/member projections and rejects a foreign membership under the selected tenant', async () => {
  const list = await get('/clients?limit=20&offset=0')
    .set('X-Request-ID', 'owner-http-test-01')
    .expect(200);
  expect(list.headers['x-request-id']).toBe('owner-http-test-01');
  const evidence = await pool.query<{
    request_id: string;
    outcome: string;
    owner_policy_version: number;
    mfa_verified_at: Date;
  }>(
    "SELECT request_id,outcome,owner_policy_version,mfa_verified_at FROM management_audit WHERE actor_id=$1 AND action='operators.list'",
    [owner.id],
  );
  expect(evidence.rows[0]).toMatchObject({
    request_id: 'owner-http-test-01',
    outcome: 'success',
  });
  expect(evidence.rows[0]!.owner_policy_version).toBeGreaterThan(0);
  expect(evidence.rows[0]!.mfa_verified_at).toBeInstanceOf(Date);
  expect((list.body as { operators: unknown[] }).operators.length).toBeLessThanOrEqual(20);
  await get('/clients/' + operator).expect(200);
  const members = await get('/clients/' + operator + '/members').expect(200);
  expect(members.body.operatorId).toBe(operator);
  expect((members.body as { members: { id: string }[] }).members.map((value) => value.id)).toEqual([
    membership,
  ]);
  await get('/clients/' + operator + '/members/' + otherMembership).expect(404);
  const detail = await get('/clients/' + operator + '/members/' + membership).expect(200);
  expect(detail.body.operatorId).toBe(operator);
  expect(JSON.stringify([list.body, members.body, detail.body])).not.toMatch(
    /key_hash|password_hash|token_hash|csrf_hash/,
  );
  const events = await pool.query<{ action: string }>(
    'SELECT action FROM management_audit WHERE actor_id=$1 ORDER BY action',
    [owner.id],
  );
  expect(events.rows.map((value) => value.action)).toEqual([
    'members.detail',
    'members.list',
    'operators.detail',
    'operators.list',
  ]);
});
it('checks live exact administrative permissions and refuses stale CSRF or elevation inputs', async () => {
  const reader = await createOwnerFixture(pool, ['platform.clients.read']);
  otherOwners.push(reader.id);
  const cookie = '__Host-vaultx_owner_session=' + reader.token;
  await get('/clients', cookie).expect(200);
  await get('/audit', cookie).expect(403);
  await change({ expectedVersion: 1, name: 'Denied' }, cookie, reader.csrf).expect(403);
  await change({ expectedVersion: 1, name: 'Denied' })
    .set('X-CSRF-Token', '0'.repeat(64))
    .expect(403);
  await change({ expectedVersion: 1, name: 'Denied', role: 'owner' }).expect(400);
  expect(
    (await pool.query('SELECT name,management_version FROM operators WHERE id=$1', [operator]))
      .rows[0],
  ).toEqual({ name: 'HTTP management synthetic', management_version: 1 });
});
it('commits metadata and audit together, rejects stale forms and withdraws viewer rights without touching machine keys', async () => {
  const renamed = await change({ expectedVersion: 1, name: 'Synthetic renamed client' }).expect(
    200,
  );
  expect(renamed.body.operator.version).toBe(2);
  await change({ expectedVersion: 1, status: 'suspended' }).expect(409);
  await request(app())
    .post('/owner-api/clients/' + operator + '/entitlements/client.payments.read/withdraw')
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', '__Host-vaultx_owner_session=' + owner.token)
    .set('Origin', origin)
    .set('X-CSRF-Token', owner.csrf)
    .send({ expectedVersion: 2 })
    .expect(200);
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', viewerCookie).expect(401);
  expect(
    (
      await pool.query(
        "SELECT count(*) FROM membership_permission_grants WHERE membership_id=$1 AND permission_code='client.payments.read' AND revoked_at IS NULL",
        [membership],
      )
    ).rows[0].count,
  ).toBe('0');
  await request(app())
    .get('/payments')
    .set('Authorization', 'Bearer ' + machineKey)
    .expect(200);
  const events = await pool.query<{ action: string }>(
    'SELECT action FROM management_audit WHERE actor_id=$1 ORDER BY action',
    [owner.id],
  );
  expect(events.rows.map((value) => value.action)).toEqual([
    'entitlements.withdraw',
    'operators.update',
  ]);
});
it('rotates owner CSRF and logs out without exposing or retaining owner authentication material', async () => {
  const csrf = await get('/auth/csrf').expect(200);
  const value = csrf.body.csrfToken as string;
  expect(value).toMatch(/^[a-f0-9]{64}$/);
  await change({ expectedVersion: 1, name: 'Denied' }, undefined, owner.csrf).expect(403);
  await request(app())
    .post('/owner-api/auth/logout')
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', '__Host-vaultx_owner_session=' + owner.token)
    .set('Origin', origin)
    .set('X-CSRF-Token', value)
    .send({})
    .expect(204);
  await get('/auth/me').expect(401);
  expect(
    (await pool.query('SELECT token_hash FROM owner_sessions WHERE owner_id=$1', [owner.id]))
      .rowCount,
  ).toBe(0);
  expect(captured.output()).not.toContain(owner.token);
  expect(captured.output()).not.toContain(machineKey);
});
