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
  lockPolicyRows,
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

it('uses exactly one management revision for a combined metadata/status PATCH and rejects its stale replay', async () => {
  const response = await change({
    expectedVersion: 1,
    name: 'Combined synthetic change',
    status: 'suspended',
  }).expect(200);
  expect(response.body.operator).toMatchObject({
    id: operator,
    name: 'Combined synthetic change',
    status: 'suspended',
    version: 2,
  });
  expect(
    (
      await pool.query<{ management_version: number }>(
        'SELECT management_version FROM operators WHERE id=$1',
        [operator],
      )
    ).rows[0]!.management_version,
  ).toBe(2);
  await change({
    expectedVersion: 1,
    name: 'Combined synthetic change',
    status: 'suspended',
  }).expect(409);
  const events = await pool.query<{ target_version: number; summary: { version: number } }>(
    "SELECT target_version,summary FROM management_audit WHERE operator_id=$1 AND action='operators.update'",
    [operator],
  );
  expect(events.rows).toHaveLength(1);
  expect(events.rows[0]).toMatchObject({ target_version: 2, summary: { version: 2 } });
});

it('consumes exactly one management revision for an authorized metadata no-op', async () => {
  const response = await change({ expectedVersion: 1, name: 'HTTP management synthetic' }).expect(
    200,
  );
  expect(response.body.operator).toMatchObject({
    id: operator,
    name: 'HTTP management synthetic',
    status: 'active',
    version: 2,
  });
  await change({ expectedVersion: 1, name: 'HTTP management synthetic' }).expect(409);
  const events = await pool.query<{
    target_version: number;
    summary: { version: number; nameChanged: boolean };
  }>(
    "SELECT target_version,summary FROM management_audit WHERE operator_id=$1 AND action='operators.update'",
    [operator],
  );
  expect(events.rows).toHaveLength(1);
  expect(events.rows[0]).toMatchObject({
    target_version: 2,
    summary: { version: 2 },
  });
});

it('keeps management revision and entitlement policy revision independent in withdrawal results and audit evidence', async () => {
  for (let version = 1; version <= 3; version++) {
    const response = await change({
      expectedVersion: version,
      name: 'Synthetic metadata revision ' + version,
    }).expect(200);
    expect(response.body.operator.version).toBe(version + 1);
  }
  const before = (
    await pool.query<{ authorization_version: number }>(
      'SELECT authorization_version FROM operator_access_policies WHERE operator_id=$1',
      [operator],
    )
  ).rows[0]!.authorization_version;
  const response = await request(app())
    .post('/owner-api/clients/' + operator + '/entitlements/client.payments.read/withdraw')
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', '__Host-vaultx_owner_session=' + owner.token)
    .set('Origin', origin)
    .set('X-CSRF-Token', owner.csrf)
    .send({ expectedVersion: 4 })
    .expect(200);
  expect(response.body.operator.version).toBe(5);
  expect(response.body.policyVersion).toBe(before + 1);
  const current = await pool.query<{ management_version: number; authorization_version: number }>(
    'SELECT o.management_version,p.authorization_version FROM operators o JOIN operator_access_policies p ON p.operator_id=o.id WHERE o.id=$1',
    [operator],
  );
  expect(current.rows[0]).toEqual({ management_version: 5, authorization_version: before + 1 });
  const events = await pool.query<{
    target_version: number;
    summary: { version: number; policyVersion: number };
  }>(
    "SELECT target_version,summary FROM management_audit WHERE operator_id=$1 AND action='entitlements.withdraw'",
    [operator],
  );
  expect(events.rows).toHaveLength(1);
  expect(events.rows[0]).toMatchObject({
    target_version: 5,
    summary: { version: 5, policyVersion: before + 1 },
  });
});

it('serializes two owner PATCH requests at the tenant gate and commits one revision with one audit record', async () => {
  const second = await createOwnerFixture(pool);
  otherOwners.push(second.id);
  const holder = await pool.connect();
  let pending: Promise<request.Response>[] = [];
  try {
    await holder.query('BEGIN');
    await lockPolicyRows(holder, operator);
    // Distinct owners and session rows ensure the tenant gate, not a shared
    // session lock, controls this interleaving.
    pending = [
      change({ expectedVersion: 1, name: 'Concurrent owner A' }).then((response) => response),
      change(
        { expectedVersion: 1, name: 'Concurrent owner B' },
        '__Host-vaultx_owner_session=' + second.token,
        second.csrf,
      ).then((response) => response),
    ];
    for (const operation of pending) void operation.catch(() => undefined);
    let waiting = 0;
    for (let check = 0; check < 200; check++) {
      const locks = await holder.query<{ waiting: string }>(
        `SELECT count(*) AS waiting FROM pg_catalog.pg_locks l
         CROSS JOIN (SELECT pg_catalog.hashtextextended('vaultx.viewer.policy:' || $1::uuid::text,0) AS key) gate
         WHERE l.locktype='advisory' AND NOT l.granted AND l.mode='ExclusiveLock' AND l.objsubid=1
           AND l.database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
           AND l.classid=((gate.key >> 32) & 4294967295)::oid AND l.objid=(gate.key & 4294967295)::oid`,
        [operator],
      );
      waiting = Number(locks.rows[0]!.waiting);
      if (waiting === 2) break;
    }
    expect(waiting).toBe(2);
    await holder.query('COMMIT');
    const responses = await Promise.all(pending);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 409]);
    const successful = responses.find((response) => response.status === 200)!;
    expect(successful.body.operator.version).toBe(2);
    const current = await pool.query<{ management_version: number; name: string }>(
      'SELECT management_version,name FROM operators WHERE id=$1',
      [operator],
    );
    expect(current.rows[0]).toEqual({
      management_version: 2,
      name: successful.body.operator.name as string,
    });
    const events = await pool.query<{
      actor_id: string;
      target_version: number;
      summary: { version: number };
    }>(
      "SELECT actor_id,target_version,summary FROM management_audit WHERE operator_id=$1 AND action='operators.update'",
      [operator],
    );
    expect(events.rows).toHaveLength(1);
    expect(events.rows[0]).toMatchObject({ target_version: 2, summary: { version: 2 } });
    const winningOwner =
      successful.body.operator.name === 'Concurrent owner A' ? owner.id : second.id;
    expect(events.rows[0]!.actor_id).toBe(winningOwner);
  } finally {
    await holder.query('ROLLBACK');
    holder.release();
    await Promise.allSettled(pending);
  }
});
