import * as permissionModule from '../../src/dashboard/permissions.js';
import {
  seedViewerFixture,
  cleanupViewerFixture,
  policyQuery,
  lockPolicyRows,
} from '../viewer-policy-fixtures.js';
import { createHash, randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import request from 'supertest';
import { beforeAll, beforeEach, afterEach, afterAll, expect, it, vi } from 'vitest';
import { createApp } from '../../src/app.js';
import { runMigrations } from '../../src/db/migrate.js';
import * as passwordModule from '../../src/dashboard/passwords.js';
import { cleanupDashboardAuth } from '../../src/dashboard/maintenance.js';
import { hashDashboardPassword } from '../../src/dashboard/passwords.js';
import { openTestDatabase } from '../test-database.js';
import { captureLogger, testConfig } from '../helpers.js';

let pool: Pool, user: string, operator: string, username: string;
let passwordHash: string;
const extraUsers: string[] = [],
  extraOperators: string[] = [];
const password = 'SYNTHETIC dashboard password only';
const origin = 'https://dashboard.example.invalid';
const originalPassword = passwordModule.verifyDashboardPassword;
const originalIdentity = permissionModule.lockViewerIdentity;
const logs = captureLogger();
function app(trusted = '') {
  return createApp({
    pool,
    logger: logs.logger,
    config: testConfig({
      DASHBOARD_ENABLED: 'true',
      DASHBOARD_PUBLIC_ORIGIN: origin,
      DASHBOARD_TRUSTED_PROXIES: trusted,
    }),
  });
}
function cookie(res: request.Response): string {
  const raw = res.headers['set-cookie'] as unknown as string[];
  return raw[0]!.split(';')[0]!;
}
async function pre() {
  const res = await request(app()).get('/dashboard-api/auth/csrf').expect(200);
  return { cookie: cookie(res), csrf: (res.body as { csrfToken: string }).csrfToken };
}
async function login(preauth?: Awaited<ReturnType<typeof pre>>, status?: number) {
  const p = preauth ?? (await pre());
  const req = request(app())
    .post('/dashboard-api/auth/login')
    .set('Origin', origin)
    .set('Cookie', p.cookie)
    .set('Origin', origin)
    .set('X-CSRF-Token', p.csrf)
    .send({ username, password });
  return status === undefined ? req : req.expect(status);
}
beforeAll(async () => {
  pool = await openTestDatabase();
  await runMigrations(pool);
  passwordHash = await hashDashboardPassword(password);
});
beforeEach(async () => {
  extraUsers.length = 0;
  extraOperators.length = 0;
  user = randomUUID();
  operator = randomUUID();
  username = 'user_' + user;
  await pool.query('INSERT INTO operators(id, name, code) VALUES ($1, $2, $3)', [
    operator,
    'Dashboard test',
    'op_' + operator,
  ]);
  await pool.query('INSERT INTO dashboard_users(id, username, password_hash) VALUES ($1, $2, $3)', [
    user,
    username,
    passwordHash,
  ]);
  await pool.query(
    'INSERT INTO dashboard_memberships(id, user_id, operator_id) VALUES ($1, $2, $3)',
    [randomUUID(), user, operator],
  );
  await seedViewerFixture(pool, user);
});
afterEach(async () => {
  for (const id of [user, ...extraUsers]) await cleanupViewerFixture(pool, id);
  for (const id of [operator, ...extraOperators])
    await pool.query('DELETE FROM operators WHERE id = $1', [id]);
  // This suite alone uses auth tables in an independently verified disposable DB.
  await pool.query('DELETE FROM dashboard_sessions WHERE user_id IS NULL');
  await pool.query('DELETE FROM dashboard_login_limits');
});
afterAll(async () => {
  await pool?.end();
});

it('is default-off and does not change payment authentication', async () => {
  const disabled = createApp({ pool, logger: logs.logger, config: testConfig() });
  await request(disabled).get('/dashboard-api/auth/csrf').expect(404);
  await request(app()).get('/payments').expect(401);
});
it('rotates pre-auth tokens, hashes sessions, sets secure cookies, and invalidates logout', async () => {
  const p = await pre();
  const result = await login(p, 200);
  const authCookie = cookie(result);
  expect(authCookie === p.cookie).toBe(false);
  const header = (result.headers['set-cookie'] as unknown as string[])[0]!;
  for (const flag of ['Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/'])
    expect(header).toContain(flag);
  expect(header).not.toContain('Domain=');
  expect(result.headers['cache-control']).toBe('no-store');
  const sessions = await pool.query<{ token_hash: string }>(
    'SELECT token_hash FROM dashboard_sessions WHERE user_id = $1',
    [user],
  );
  expect(sessions.rows).toHaveLength(1);
  expect(sessions.rows[0]!.token_hash === authCookie.split('=')[1]).toBe(false);
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', p.cookie).expect(401);
  const me = await request(app())
    .get('/dashboard-api/auth/me')
    .set('Cookie', authCookie)
    .expect(200);
  expect(me.body).toEqual({
    user: { id: user, username },
    operator: { id: operator },
    role: 'viewer',
  });
  await request(app()).get('/payments').set('Cookie', authCookie).expect(401);
  await request(app())
    .post('/dashboard-api/auth/logout')
    .set('Cookie', authCookie)
    .set('Origin', origin)
    .set('X-CSRF-Token', (result.body as { csrfToken: string }).csrfToken)
    .expect(204);
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', authCookie).expect(401);
  expect(logs.output()).not.toContain(password);
  expect(logs.output()).not.toContain(authCookie);
  expect(logs.output()).not.toContain((result.body as { csrfToken: string }).csrfToken);
});
it('rejects login CSRF, missing Origin, hostile Origin and cross-site token vending', async () => {
  const p = await pre();
  for (const value of ['', 'https://hostile.invalid']) {
    await request(app())
      .post('/dashboard-api/auth/login')
      .set('Origin', origin)
      .set('Cookie', p.cookie)
      .set('Origin', value)
      .set('X-CSRF-Token', p.csrf)
      .send({ username, password })
      .expect(403);
  }
  await request(app())
    .post('/dashboard-api/auth/login')
    .set('Origin', origin)
    .set('Cookie', p.cookie)
    .set('Origin', origin)
    .send({ username, password })
    .expect(403);
  await request(app())
    .get('/dashboard-api/auth/csrf')
    .set('Origin', 'https://hostile.invalid')
    .expect(403);
  await request(app())
    .get('/dashboard-api/auth/csrf')
    .set('Sec-Fetch-Site', 'cross-site')
    .expect(403);
  expect(
    (await pool.query('SELECT token_hash FROM dashboard_sessions WHERE user_id = $1', [user]))
      .rowCount,
  ).toBe(0);
});
it('requires valid session-bound CSRF on logout, rotates CSRF and rejects duplicate cookies', async () => {
  const result = await login(undefined, 200),
    c = cookie(result);
  await request(app())
    .post('/dashboard-api/auth/logout')
    .set('Cookie', c)
    .set('Origin', origin)
    .expect(403);
  await request(app())
    .post('/dashboard-api/auth/logout')
    .set('Cookie', c)
    .set('Origin', 'https://hostile.invalid')
    .set('X-CSRF-Token', (result.body as { csrfToken: string }).csrfToken)
    .expect(403);
  await request(app())
    .get('/dashboard-api/auth/me')
    .set('Cookie', c + '; ' + c)
    .expect(401);
  const rotated = await request(app()).get('/dashboard-api/auth/csrf').set('Cookie', c).expect(200);
  await request(app())
    .post('/dashboard-api/auth/logout')
    .set('Cookie', c)
    .set('Origin', origin)
    .set('X-CSRF-Token', (result.body as { csrfToken: string }).csrfToken)
    .expect(403);
  await request(app())
    .post('/dashboard-api/auth/logout')
    .set('Cookie', c)
    .set('Origin', origin)
    .set('X-CSRF-Token', (rotated.body as { csrfToken: string }).csrfToken)
    .expect(204);
});
it.each(['idle', 'absolute', 'disabled', 'suspended', 'membership', 'version'])(
  'rejects %s invalidated sessions',
  async (mode) => {
    const result = await login(undefined, 200),
      c = cookie(result);
    if (mode === 'idle')
      await pool.query(
        "UPDATE dashboard_sessions SET last_seen_at = NOW() - INTERVAL '31 minutes' WHERE user_id = $1",
        [user],
      );
    if (mode === 'absolute')
      await pool.query(
        "UPDATE dashboard_sessions SET created_at = NOW() - INTERVAL '9 hours' WHERE user_id = $1",
        [user],
      );
    if (mode === 'disabled')
      await policyQuery(
        pool,
        operator,
        "UPDATE dashboard_users SET status = 'disabled' WHERE id = $1",
        [user],
      );
    if (mode === 'suspended')
      await policyQuery(pool, operator, "UPDATE operators SET status = 'suspended' WHERE id = $1", [
        operator,
      ]);
    if (mode === 'membership')
      await policyQuery(
        pool,
        operator,
        "UPDATE dashboard_memberships SET status='disabled' WHERE user_id=$1",
        [user],
      );
    if (mode === 'version')
      await policyQuery(
        pool,
        operator,
        'UPDATE dashboard_users SET auth_version = auth_version + 1 WHERE id = $1',
        [user],
      );
    await request(app()).get('/dashboard-api/auth/me').set('Cookie', c).expect(401);
  },
);
it('returns generic failures for unknown, disabled, suspended and incorrect-password logins', async () => {
  const p = await pre();
  async function fail(name: string) {
    const r = await request(app())
      .post('/dashboard-api/auth/login')
      .set('Origin', origin)
      .set('Cookie', p.cookie)
      .set('Origin', origin)
      .set('X-CSRF-Token', p.csrf)
      .send({ username: name, password: password + 'incorrect' })
      .expect(401);
    return r.body as { error: { code: string; message: string } };
  }
  const known = await fail(username),
    unknown = await fail('unknown_test');
  expect(known.error.message).toBe(unknown.error.message);
  await policyQuery(
    pool,
    operator,
    "UPDATE dashboard_users SET status = 'disabled' WHERE id = $1",
    [user],
  );
  await login(p, 401);
  await policyQuery(pool, operator, "UPDATE dashboard_users SET status = 'active' WHERE id = $1", [
    user,
  ]);
  await policyQuery(pool, operator, "UPDATE operators SET status = 'suspended' WHERE id = $1", [
    operator,
  ]);
  await login(p, 401);
});
it('allows at most one successful concurrent login with a pre-auth token', async () => {
  const p = await pre();
  const results = await Promise.all([login(p), login(p)]);
  expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
  expect(
    (await pool.query('SELECT token_hash FROM dashboard_sessions WHERE user_id = $1', [user]))
      .rowCount,
  ).toBe(1);
});
it('expires pre-auth sessions and rejects malformed or oversized JSON safely', async () => {
  const p = await pre();
  await pool.query(
    "UPDATE dashboard_sessions SET created_at = NOW() - INTERVAL '11 minutes' WHERE user_id IS NULL",
  );
  await login(p, 403);
  await request(app())
    .post('/dashboard-api/auth/login')
    .set('Origin', origin)
    .set('Content-Type', 'application/json')
    .send('{')
    .expect(400);
  await request(app())
    .post('/dashboard-api/auth/login')
    .set('Origin', origin)
    .send({ password: 'x'.repeat(5000) })
    .expect(413);
});
it('enforces account limits across router recreation and forwarded-IP spoofing', async () => {
  const p = await pre();
  for (let i = 0; i < 5; i++) {
    await request(app('127.0.0.1/32,::1/128'))
      .post('/dashboard-api/auth/login')
      .set('Origin', origin)
      .set('Cookie', p.cookie)
      .set('Origin', origin)
      .set('X-CSRF-Token', p.csrf)
      .set('X-Forwarded-For', '192.0.2.' + i)
      .send({ username: username.toUpperCase(), password: password + 'wrong' })
      .expect(401);
  }
  await login(p, 429);
  await pool.query("UPDATE dashboard_login_limits SET expires_at = NOW() - INTERVAL '1 second'");
  await login(p, 200);
});
it('enforces IP limits before allocating unlimited account buckets, ignoring forwarded headers by default', async () => {
  for (let i = 0; i < 30; i++) {
    await request(app())
      .post('/dashboard-api/auth/login')
      .set('Origin', origin)
      .set('X-Forwarded-For', '192.0.2.' + i)
      .send({ username: 'unknown_' + i, password })
      .expect(403);
  }
  await request(app())
    .post('/dashboard-api/auth/login')
    .set('Origin', origin)
    .set('X-Forwarded-For', '198.51.100.1')
    .send({ username: 'another', password })
    .expect(429);
  expect((await pool.query('SELECT bucket_hash FROM dashboard_login_limits')).rowCount).toBe(1);
});
it('password replacement and suspension permanently invalidate previous sessions', async () => {
  const first = await login(undefined, 200),
    c = cookie(first);
  await policyQuery(pool, operator, 'UPDATE dashboard_users SET password_hash = $2 WHERE id = $1', [
    user,
    await hashDashboardPassword(password + ' replacement'),
  ]);
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', c).expect(401);
  await policyQuery(pool, operator, 'UPDATE dashboard_users SET password_hash = $2 WHERE id = $1', [
    user,
    passwordHash,
  ]);
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', c).expect(401);
  const second = cookie(await login(undefined, 200));
  await policyQuery(pool, operator, "UPDATE operators SET status = 'suspended' WHERE id = $1", [
    operator,
  ]);
  await policyQuery(pool, operator, "UPDATE operators SET status = 'active' WHERE id = $1", [
    operator,
  ]);
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', second).expect(401);
});
it('ignores forged operator selection, rejects replacement and invalidates disabled memberships', async () => {
  const logged = cookie(await login(undefined, 200));
  const identity = await request(app())
    .get('/dashboard-api/auth/me?operatorId=' + randomUUID())
    .set('Cookie', logged)
    .set('X-Operator-Id', randomUUID())
    .expect(200);
  expect((identity.body as { operator: { id: string } }).operator.id).toBe(operator);
  await expect(
    policyQuery(pool, operator, 'UPDATE dashboard_memberships SET id = $2 WHERE user_id = $1', [
      user,
      randomUUID(),
    ]),
  ).rejects.toThrow();
  await policyQuery(
    pool,
    operator,
    "UPDATE dashboard_memberships SET status='disabled' WHERE user_id=$1",
    [user],
  );
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', logged).expect(401);
});
it('accepts forwarded addresses only through explicitly trusted peers', async () => {
  const trustedApp = app('127.0.0.1/32,::1/128');
  for (let i = 0; i < 31; i++) {
    await request(trustedApp)
      .post('/dashboard-api/auth/login')
      .set('Origin', origin)
      .set('X-Forwarded-For', '192.0.2.' + i)
      .send({ username: 'unknown_' + i, password })
      .expect(403);
  }
  const untrustedApp = app('198.51.100.1/32');
  for (let i = 0; i < 30; i++)
    await request(untrustedApp)
      .post('/dashboard-api/auth/login')
      .set('Origin', origin)
      .set('X-Forwarded-For', '192.0.2.' + i)
      .send({})
      .expect(403);
  await request(untrustedApp)
    .post('/dashboard-api/auth/login')
    .set('Origin', origin)
    .set('X-Forwarded-For', '192.0.2.100')
    .send({})
    .expect(429);
});
it('shares IP limits across concurrent requests and refuses database failures', async () => {
  const results = await Promise.all(
    Array.from({ length: 35 }, () =>
      request(app()).post('/dashboard-api/auth/login').set('Origin', origin).send({}),
    ),
  );
  expect(results.filter((r) => r.status === 429)).toHaveLength(5);
  expect(results.filter((r) => r.status === 403)).toHaveLength(30);
  const failedPool = {
    query: () => Promise.reject(new Error('PRIVATE_DATABASE_DETAIL')),
  } as unknown as Pool;
  const capture = captureLogger();
  const failed = createApp({
    pool: failedPool,
    logger: capture.logger,
    config: testConfig({ DASHBOARD_ENABLED: 'true', DASHBOARD_PUBLIC_ORIGIN: origin }),
  });
  const res = await request(failed).get('/dashboard-api/auth/csrf').expect(503);
  expect(JSON.stringify(res.body)).not.toContain('PRIVATE_DATABASE_DETAIL');
  expect(capture.output()).not.toContain('PRIVATE_DATABASE_DETAIL');
});
it('canonicalizes forwarded IPv6 spelling and limits CSRF issuance', async () => {
  const trustedApp = app('127.0.0.1/32,::1/128');
  for (let i = 0; i < 30; i++) {
    await request(trustedApp)
      .post('/dashboard-api/auth/login')
      .set('Origin', origin)
      .set('X-Forwarded-For', i % 2 ? '2001:db8::1' : '2001:0db8:0:0:0:0:0:1')
      .send({})
      .expect(403);
  }
  await request(trustedApp)
    .post('/dashboard-api/auth/login')
    .set('Origin', origin)
    .set('X-Forwarded-For', '2001:db8::1')
    .send({})
    .expect(429);
  for (let i = 0; i < 60; i++) await request(app()).get('/dashboard-api/auth/csrf').expect(200);
  await request(app()).get('/dashboard-api/auth/csrf').expect(429);
});
it('refreshes idle activity without extending the absolute session lifetime', async () => {
  const c = cookie(await login(undefined, 200));
  await pool.query(
    "UPDATE dashboard_sessions SET last_seen_at = NOW() - INTERVAL '29 minutes' WHERE user_id = $1",
    [user],
  );
  const before = await pool.query<{ created_at: Date }>(
    'SELECT created_at FROM dashboard_sessions WHERE user_id = $1',
    [user],
  );
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', c).expect(200);
  const after = await pool.query<{ created_at: Date; recent: boolean }>(
    "SELECT created_at, last_seen_at > NOW() - INTERVAL '1 minute' AS recent FROM dashboard_sessions WHERE user_id = $1",
    [user],
  );
  expect(after.rows[0]!.created_at).toEqual(before.rows[0]!.created_at);
  expect(after.rows[0]!.recent).toBe(true);
});
it('bounds expensive verification concurrency after asynchronous session checks', async () => {
  const p = await pre();
  let active = 0,
    maximum = 0;
  const spy = vi.spyOn(passwordModule, 'verifyDashboardPassword').mockImplementation(async () => {
    active++;
    maximum = Math.max(maximum, active);
    await new Promise((resolve) => setTimeout(resolve, 100));
    active--;
    return true;
  });
  try {
    const sharedApp = app();
    const results = await Promise.all(
      Array.from({ length: 5 }, () =>
        request(sharedApp)
          .post('/dashboard-api/auth/login')
          .set('Origin', origin)
          .set('Cookie', p.cookie)
          .set('Origin', origin)
          .set('X-CSRF-Token', p.csrf)
          .send({ username, password }),
      ),
    );
    expect(maximum).toBe(2);
    expect(results.some((r) => r.status === 429)).toBe(true);
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
  } finally {
    spy.mockRestore();
  }
});

function barrier() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
const hashToken = (value: string) => createHash('sha256').update(value).digest('hex');

it('rejects invalid Origins without DB work and does not charge account budgets for invalid CSRF', async () => {
  const query = vi.fn(() => Promise.reject(new Error('Must not query')));
  const connect = vi.fn(() => Promise.reject(new Error('Must not connect')));
  const guarded = createApp({
    pool: { query, connect } as unknown as Pool,
    logger: logs.logger,
    config: testConfig({ DASHBOARD_ENABLED: 'true', DASHBOARD_PUBLIC_ORIGIN: origin }),
  });
  for (const value of ['', 'null', 'https://hostile.invalid']) {
    await request(guarded)
      .post('/dashboard-api/auth/login')
      .set('Origin', value)
      .send({ username, password })
      .expect(403);
  }
  expect(query).not.toHaveBeenCalled();
  expect(connect).not.toHaveBeenCalled();
  const p = await pre();
  for (let i = 0; i < 6; i++)
    await request(app())
      .post('/dashboard-api/auth/login')
      .set('Origin', origin)
      .set('Cookie', p.cookie)
      .set('X-CSRF-Token', '0'.repeat(64))
      .send({ username, password })
      .expect(403);
  expect(
    (
      await pool.query(
        'SELECT attempts FROM public.dashboard_login_limits WHERE bucket_hash = $1',
        [hashToken('login-user:' + username)],
      )
    ).rowCount,
  ).toBe(0);
  await login(p, 200);
});

it.each(['password', 'membership', 'operator'])(
  'invalidates the real session despite altered search_path and temp shadow tables: %s',
  async (mode) => {
    const c = cookie(await login(undefined, 200));
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await lockPolicyRows(client, operator);
      await client.query(
        'CREATE TEMP TABLE dashboard_sessions(user_id UUID, membership_id UUID) ON COMMIT DROP; CREATE TEMP TABLE dashboard_memberships(id UUID, operator_id UUID) ON COMMIT DROP',
      );
      await client.query('INSERT INTO pg_temp.dashboard_sessions(user_id) VALUES ($1)', [user]);
      await client.query('SET LOCAL search_path = pg_temp, pg_catalog');
      if (mode === 'password')
        await client.query('UPDATE public.dashboard_users SET password_hash = $2 WHERE id = $1', [
          user,
          await hashDashboardPassword(password + ' changed'),
        ]);
      if (mode === 'membership')
        await client.query(
          'UPDATE public.dashboard_memberships SET authorization_version=authorization_version+1 WHERE user_id=$1',
          [user],
        );
      if (mode === 'operator')
        await client.query("UPDATE public.operators SET status = 'suspended' WHERE id = $1", [
          operator,
        ]);
      expect(
        (
          await client.query(
            'SELECT token_hash FROM public.dashboard_sessions WHERE user_id = $1',
            [user],
          )
        ).rowCount,
      ).toBe(0);
      expect((await client.query('SELECT user_id FROM pg_temp.dashboard_sessions')).rowCount).toBe(
        1,
      );
      const functions = await client.query<{ prosecdef: boolean; proconfig: string[] }>(
        "SELECT prosecdef, proconfig FROM pg_catalog.pg_proc WHERE oid IN ('public.invalidate_dashboard_user_sessions()'::regprocedure, 'public.invalidate_dashboard_membership_sessions()'::regprocedure, 'public.invalidate_suspended_operator_sessions()'::regprocedure)",
      );
      expect(functions.rows).toHaveLength(3);
      expect(
        functions.rows.every(
          (row) =>
            !row.prosecdef && row.proconfig.includes('search_path=pg_catalog, public, pg_temp'),
        ),
      ).toBe(true);
      await client.query('COMMIT');
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
    await request(app()).get('/dashboard-api/auth/me').set('Cookie', c).expect(401);
  },
);

it.each(['password', 'membership', 'operator'])(
  'fails closed when %s changes during password verification',
  async (mode) => {
    const p = await pre(),
      entered = barrier(),
      release = barrier();
    const original = passwordModule.verifyDashboardPassword;
    const spy = vi
      .spyOn(passwordModule, 'verifyDashboardPassword')
      .mockImplementation(async (...args) => {
        entered.resolve();
        await release.promise;
        return original(...args);
      });
    let pending: Promise<request.Response> | undefined;
    try {
      pending = login(p);
      await entered.promise;
      if (mode === 'password')
        await policyQuery(
          pool,
          operator,
          'UPDATE public.dashboard_users SET password_hash = $2 WHERE id = $1',
          [user, await hashDashboardPassword(password + ' replacement')],
        );
      if (mode === 'membership') {
        const other = randomUUID();
        extraOperators.push(other);
        await pool.query('INSERT INTO public.operators(id, name, code) VALUES ($1, $2, $3)', [
          other,
          'Reassigned operator',
          'reassigned_' + other,
        ]);
        await expect(
          policyQuery(
            pool,
            operator,
            'UPDATE public.dashboard_memberships SET operator_id=$2 WHERE user_id=$1',
            [user, other],
          ),
        ).rejects.toThrow();
        await policyQuery(
          pool,
          operator,
          "UPDATE public.dashboard_memberships SET status='disabled' WHERE user_id=$1",
          [user],
        );
      }
      if (mode === 'operator')
        await policyQuery(
          pool,
          operator,
          "UPDATE public.operators SET status = 'suspended' WHERE id = $1",
          [operator],
        );
      release.resolve();
      expect((await pending).status).toBe(401);
      expect(
        (
          await pool.query('SELECT token_hash FROM public.dashboard_sessions WHERE user_id = $1', [
            user,
          ])
        ).rowCount,
      ).toBe(0);
    } finally {
      release.resolve();
      await pending;
      spy.mockRestore();
    }
  },
);

it('keeps two populated users and operator identities independent', async () => {
  const otherUser = randomUUID(),
    otherOperator = randomUUID(),
    otherName = 'other_' + otherUser;
  extraUsers.push(otherUser);
  extraOperators.push(otherOperator);
  await pool.query('INSERT INTO public.operators(id, name, code) VALUES ($1, $2, $3)', [
    otherOperator,
    'Second operator',
    'second_' + otherOperator,
  ]);
  await pool.query(
    'INSERT INTO public.dashboard_users(id, username, password_hash) VALUES ($1, $2, $3)',
    [otherUser, otherName, passwordHash],
  );
  await pool.query(
    'INSERT INTO public.dashboard_memberships(id, user_id, operator_id) VALUES ($1, $2, $3)',
    [randomUUID(), otherUser, otherOperator],
  );
  await seedViewerFixture(pool, otherUser);
  const first = cookie(await login(undefined, 200)),
    p = await pre();
  const second = cookie(
    await request(app())
      .post('/dashboard-api/auth/login')
      .set('Origin', origin)
      .set('Cookie', p.cookie)
      .set('X-CSRF-Token', p.csrf)
      .send({ username: otherName, password })
      .expect(200),
  );
  for (const [c, id, op] of [
    [first, user, operator],
    [second, otherUser, otherOperator],
  ]) {
    const me = await request(app())
      .get('/dashboard-api/auth/me?operatorId=' + randomUUID())
      .set('Cookie', c!)
      .expect(200);
    expect(me.body).toEqual({
      user: { id, username: id === user ? username : otherName },
      operator: { id: op },
      role: 'viewer',
    });
  }
  await policyQuery(
    pool,
    operator,
    "UPDATE public.dashboard_memberships SET status='disabled' WHERE user_id=$1",
    [user],
  );
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', first).expect(401);
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', second).expect(200);
});

it('cleans bounded expired batches, preserving current windows, active and locked sessions', async () => {
  await login(undefined, 200);
  await pre();
  const validSessions = await pool.query(
    'SELECT token_hash FROM public.dashboard_sessions ORDER BY token_hash',
  );
  const validLimits = await pool.query(
    'SELECT bucket_hash, attempts, expires_at FROM public.dashboard_login_limits ORDER BY bucket_hash',
  );
  await pool.query(
    `INSERT INTO public.dashboard_sessions(token_hash, csrf_hash, created_at)
    SELECT md5($1 || g::text) || md5(g::text || $1), repeat('a', 64), clock_timestamp() - INTERVAL '11 minutes' FROM generate_series(1, 105) g`,
    [randomUUID()],
  );
  await pool.query(
    `INSERT INTO public.dashboard_sessions(token_hash, csrf_hash, user_id, membership_id, auth_version, membership_authz_version, operator_authz_version, created_at, last_seen_at)
    SELECT md5($1 || g::text) || md5(g::text || $1), repeat('a', 64), u.id, m.id, u.auth_version, m.authorization_version, 1,
      CASE WHEN g = 1 THEN clock_timestamp() - INTERVAL '9 hours' ELSE clock_timestamp() END,
      clock_timestamp() - INTERVAL '31 minutes'
    FROM public.dashboard_users u JOIN public.dashboard_memberships m ON m.user_id = u.id CROSS JOIN generate_series(1, 2) g WHERE u.id = $2`,
    [randomUUID(), user],
  );
  await pool.query(
    `INSERT INTO public.dashboard_login_limits(bucket_hash, attempts, expires_at)
    SELECT md5($1 || g::text) || md5(g::text || $1), 1, clock_timestamp() - INTERVAL '1 minute' FROM generate_series(1, 105) g`,
    [randomUUID()],
  );
  const blocker = await pool.connect();
  try {
    await blocker.query('BEGIN');
    const locked = await blocker.query<{ token_hash: string }>(
      "SELECT token_hash FROM public.dashboard_sessions WHERE user_id IS NULL AND created_at < clock_timestamp() - INTERVAL '10 minutes' LIMIT 1 FOR UPDATE",
    );
    await cleanupDashboardAuth(pool);
    expect((await pool.query('SELECT token_hash FROM public.dashboard_sessions')).rowCount).toBe(
      validSessions.rowCount! + 7,
    );
    expect(
      (await pool.query('SELECT bucket_hash FROM public.dashboard_login_limits')).rowCount,
    ).toBe(validLimits.rowCount! + 5);
    await cleanupDashboardAuth(pool);
    expect((await pool.query('SELECT token_hash FROM public.dashboard_sessions')).rowCount).toBe(
      validSessions.rowCount! + 1,
    );
    expect(
      (
        await pool.query('SELECT token_hash FROM public.dashboard_sessions WHERE token_hash = $1', [
          locked.rows[0]!.token_hash,
        ])
      ).rowCount,
    ).toBe(1);
    await blocker.query('COMMIT');
  } finally {
    await blocker.query('ROLLBACK');
    blocker.release();
  }
  await cleanupDashboardAuth(pool);
  expect(
    (await pool.query('SELECT token_hash FROM public.dashboard_sessions ORDER BY token_hash')).rows,
  ).toEqual(validSessions.rows);
  expect(
    (
      await pool.query(
        'SELECT bucket_hash, attempts, expires_at FROM public.dashboard_login_limits ORDER BY bucket_hash',
      )
    ).rows,
  ).toEqual(validLimits.rows);
});

it('does not revive a session that expires while its activity refresh waits on a lock', async () => {
  const c = cookie(await login(undefined, 200)),
    hashed = hashToken(c.split('=')[1]!);
  await pool.query(
    "UPDATE public.dashboard_sessions SET last_seen_at = clock_timestamp() - INTERVAL '30 minutes' + INTERVAL '1 second' WHERE token_hash = $1",
    [hashed],
  );
  const before = await pool.query(
    'SELECT last_seen_at FROM public.dashboard_sessions WHERE token_hash = $1',
    [hashed],
  );
  const blocker = await pool.connect();
  let touching: Promise<request.Response> | undefined;
  try {
    await blocker.query('BEGIN');
    await blocker.query(
      'SELECT token_hash FROM public.dashboard_sessions WHERE token_hash = $1 FOR UPDATE',
      [hashed],
    );
    touching = request(app())
      .get('/dashboard-api/auth/me')
      .set('Cookie', c)
      .then((r) => r);
    let waiting = false;
    for (let i = 0; i < 100; i++) {
      const state = await pool.query(
        "SELECT pid FROM pg_catalog.pg_stat_activity WHERE pid <> pg_backend_pid() AND query LIKE '%dashboard-touch-lock%' AND wait_event_type = 'Lock'",
      );
      if (state.rowCount) {
        waiting = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(waiting).toBe(true);
    await blocker.query('SELECT pg_sleep(1.05)');
    await blocker.query('COMMIT');
    expect((await touching).status).toBe(401);
    expect(
      (
        await pool.query(
          'SELECT last_seen_at FROM public.dashboard_sessions WHERE token_hash = $1',
          [hashed],
        )
      ).rows,
    ).toEqual(before.rows);
  } finally {
    await blocker.query('ROLLBACK');
    blocker.release();
    await touching;
  }
});

it('initializes the dummy verifier before login DB work and uses it for the first unknown account', async () => {
  const initialized = barrier(),
    actual = await passwordModule.dummyPasswordHash();
  const spy = vi.spyOn(passwordModule, 'dummyPasswordHash').mockImplementation(async () => {
    await initialized.promise;
    return actual;
  });
  let pending: Promise<request.Response> | undefined;
  try {
    const shared = app();
    const csrfResponse = await request(shared).get('/dashboard-api/auth/csrf').expect(200);
    pending = request(shared)
      .post('/dashboard-api/auth/login')
      .set('Origin', origin)
      .set('Cookie', cookie(csrfResponse))
      .set('X-CSRF-Token', (csrfResponse.body as { csrfToken: string }).csrfToken)
      .send({ username: 'unknown_initialization', password })
      .then((r) => r);
    await new Promise((r) => setTimeout(r, 25));
    expect(
      (
        await pool.query(
          'SELECT bucket_hash FROM public.dashboard_login_limits WHERE bucket_hash = $1',
          [hashToken('login-user:unknown_initialization')],
        )
      ).rowCount,
    ).toBe(0);
    initialized.resolve();
    expect((await pending).status).toBe(401);
    expect(spy).toHaveBeenCalledTimes(1);
  } finally {
    initialized.resolve();
    await pending;
    spy.mockRestore();
  }
});

it.each(['withdrawal-first', 'login-first'])(
  'serializes final login versus entitlement withdrawal (%s)',
  async (order) => {
    const entered = barrier(),
      release = barrier();
    const p = await pre();
    let pending: Promise<request.Response> | undefined;
    let withdrawal: ReturnType<typeof policyQuery> | undefined;
    const spy =
      order === 'withdrawal-first'
        ? vi
            .spyOn(passwordModule, 'verifyDashboardPassword')
            .mockImplementation(async (...args) => {
              entered.resolve();
              await release.promise;
              return originalPassword(...args);
            })
        : vi.spyOn(permissionModule, 'lockViewerIdentity').mockImplementation(async (...args) => {
            const value = await originalIdentity(...args);
            entered.resolve();
            await release.promise;
            return value;
          });
    try {
      pending = login(p);
      await entered.promise;
      const change = () =>
        policyQuery(
          pool,
          operator,
          "UPDATE operator_permission_entitlements SET enabled=false WHERE operator_id=$1 AND permission_code='client.payments.read'",
          [operator],
        );
      if (order === 'withdrawal-first') {
        await change();
        release.resolve();
        const result = await pending;
        expect(result.status).toBe(200);
        await request(app())
          .get('/dashboard-api/auth/me')
          .set('Cookie', cookie(result))
          .expect(200);
        const row = (
          await pool.query<{ current: boolean }>(
            `SELECT s.membership_authz_version=m.authorization_version AND s.operator_authz_version=p.authorization_version AS current FROM dashboard_sessions s JOIN dashboard_memberships m ON m.id=s.membership_id JOIN operator_access_policies p ON p.operator_id=m.operator_id WHERE s.user_id=$1`,
            [user],
          )
        ).rows[0];
        expect(row?.current).toBe(true);
      } else {
        withdrawal = change();
        void withdrawal.catch(() => undefined);
        let waiting = false;
        for (let i = 0; i < 100; i++) {
          const q = await pool.query<{ waiting: boolean }>(
            "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())) AS waiting",
          );
          if (q.rows[0]?.waiting) {
            waiting = true;
            break;
          }
          await new Promise((r) => setTimeout(r, 10));
        }
        expect(waiting).toBe(true);
        release.resolve();
        const result = await pending;
        expect(result.status).toBe(200);
        await withdrawal;
        await request(app())
          .get('/dashboard-api/auth/me')
          .set('Cookie', cookie(result))
          .expect(401);
      }
    } finally {
      release.resolve();
      await pending;
      await withdrawal;
      spy.mockRestore();
    }
  },
);

// Stop an ordered policy writer immediately BEFORE its session locks. Actual
// session-only endpoints must finish while it holds every identity/grant lock.
// A hidden FK/reverse lock dependency would time out instead of completing.
for (const action of ['csrf', 'logout'] as const) {
  for (const mutation of ['entitlement', 'membership', 'user'] as const) {
    it(`${action} has no reverse identity/gate dependency during ${mutation} withdrawal`, async () => {
      const authenticated = await login(undefined, 200);
      const authCookie = cookie(authenticated);
      const holder = await pool.connect();
      try {
        await holder.query('BEGIN');
        await holder.query("SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='2000ms'");
        await holder.query(
          "SELECT pg_advisory_xact_lock(hashtextextended('vaultx.viewer.policy:' || $1::uuid::text,0))",
          [operator],
        );
        await holder.query(
          'SELECT operator_id FROM operator_access_policies WHERE operator_id=$1 FOR UPDATE',
          [operator],
        );
        await holder.query('SELECT id FROM dashboard_users WHERE id=$1 FOR UPDATE', [user]);
        await holder.query('SELECT id FROM dashboard_memberships WHERE user_id=$1 FOR UPDATE', [
          user,
        ]);
        await holder.query('SELECT id FROM operators WHERE id=$1 FOR UPDATE', [operator]);
        await holder.query(
          'SELECT id FROM membership_permission_grants WHERE operator_id=$1 ORDER BY membership_id,permission_code,id FOR UPDATE',
          [operator],
        );
        const req =
          action === 'csrf'
            ? request(app()).get('/dashboard-api/auth/csrf').set('Cookie', authCookie)
            : request(app())
                .post('/dashboard-api/auth/logout')
                .set('Cookie', authCookie)
                .set('Origin', origin)
                .set('X-CSRF-Token', (authenticated.body as { csrfToken: string }).csrfToken);
        await req.timeout({ deadline: 2000 }).expect(action === 'csrf' ? 200 : 204);
        // Now finish the same policy transaction, including session invalidation.
        if (mutation === 'entitlement')
          await holder.query(
            "UPDATE operator_permission_entitlements SET enabled=false WHERE operator_id=$1 AND permission_code='client.payments.read'",
            [operator],
          );
        else if (mutation === 'membership')
          await holder.query(
            "UPDATE dashboard_memberships SET status='disabled' WHERE user_id=$1",
            [user],
          );
        else await holder.query("UPDATE dashboard_users SET status='disabled' WHERE id=$1", [user]);
        await holder.query('COMMIT');
        await request(app()).get('/dashboard-api/auth/me').set('Cookie', authCookie).expect(401);
      } finally {
        await holder.query('ROLLBACK');
        holder.release();
      }
    });
  }
}

it('cleanup skips a session held by the ordered policy writer and never waits for its gate', async () => {
  const authenticated = await login(undefined, 200);
  const hash = createHash('sha256').update(cookie(authenticated).split('=')[1]!).digest('hex');
  await pool.query(
    "UPDATE dashboard_sessions SET last_seen_at=clock_timestamp()-interval '31 minutes' WHERE token_hash=$1",
    [hash],
  );
  const holder = await pool.connect();
  try {
    await holder.query('BEGIN');
    await lockPolicyRows(holder, operator); // Includes the expired session row.
    await cleanupDashboardAuth(pool); // Must SKIP LOCKED, not wait or acquire identity locks.
    expect(
      (await holder.query('SELECT token_hash FROM dashboard_sessions WHERE token_hash=$1', [hash]))
        .rowCount,
    ).toBe(1);
    await holder.query('COMMIT');
    await cleanupDashboardAuth(pool);
    expect(
      (await pool.query('SELECT token_hash FROM dashboard_sessions WHERE token_hash=$1', [hash]))
        .rowCount,
    ).toBe(0);
  } finally {
    await holder.query('ROLLBACK');
    holder.release();
  }
});
