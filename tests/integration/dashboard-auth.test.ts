import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import request from 'supertest';
import { beforeAll, beforeEach, afterEach, afterAll, expect, it, vi } from 'vitest';
import { createApp } from '../../src/app.js';
import { runMigrations } from '../../src/db/migrate.js';
import * as passwordModule from '../../src/dashboard/passwords.js';
import { hashDashboardPassword } from '../../src/dashboard/passwords.js';
import { openTestDatabase } from '../test-database.js';
import { captureLogger, testConfig } from '../helpers.js';

let pool: Pool, user: string, operator: string, username: string;
let passwordHash: string;
const password = 'SYNTHETIC dashboard password only';
const origin = 'https://dashboard.example.invalid';
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
});
afterEach(async () => {
  await pool.query('DELETE FROM dashboard_users WHERE id = $1', [user]);
  await pool.query('DELETE FROM operators WHERE id = $1', [operator]);
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
      .set('Cookie', p.cookie)
      .set('Origin', value)
      .set('X-CSRF-Token', p.csrf)
      .send({ username, password })
      .expect(403);
  }
  await request(app())
    .post('/dashboard-api/auth/login')
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
      await pool.query("UPDATE dashboard_users SET status = 'disabled' WHERE id = $1", [user]);
    if (mode === 'suspended')
      await pool.query("UPDATE operators SET status = 'suspended' WHERE id = $1", [operator]);
    if (mode === 'membership')
      await pool.query('DELETE FROM dashboard_memberships WHERE user_id = $1', [user]);
    if (mode === 'version')
      await pool.query('UPDATE dashboard_users SET auth_version = auth_version + 1 WHERE id = $1', [
        user,
      ]);
    await request(app()).get('/dashboard-api/auth/me').set('Cookie', c).expect(401);
  },
);
it('returns generic failures for unknown, disabled, suspended and incorrect-password logins', async () => {
  const p = await pre();
  async function fail(name: string) {
    const r = await request(app())
      .post('/dashboard-api/auth/login')
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
  await pool.query("UPDATE dashboard_users SET status = 'disabled' WHERE id = $1", [user]);
  await login(p, 401);
  await pool.query("UPDATE dashboard_users SET status = 'active' WHERE id = $1", [user]);
  await pool.query("UPDATE operators SET status = 'suspended' WHERE id = $1", [operator]);
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
    .set('Content-Type', 'application/json')
    .send('{')
    .expect(400);
  await request(app())
    .post('/dashboard-api/auth/login')
    .send({ password: 'x'.repeat(5000) })
    .expect(413);
});
it('enforces account limits across router recreation and forwarded-IP spoofing', async () => {
  const p = await pre();
  for (let i = 0; i < 5; i++) {
    await request(app('127.0.0.1/32,::1/128'))
      .post('/dashboard-api/auth/login')
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
      .set('X-Forwarded-For', '192.0.2.' + i)
      .send({ username: 'unknown_' + i, password })
      .expect(403);
  }
  await request(app())
    .post('/dashboard-api/auth/login')
    .set('X-Forwarded-For', '198.51.100.1')
    .send({ username: 'another', password })
    .expect(429);
  expect((await pool.query('SELECT bucket_hash FROM dashboard_login_limits')).rowCount).toBe(31);
});
it('password replacement and suspension permanently invalidate previous sessions', async () => {
  const first = await login(undefined, 200),
    c = cookie(first);
  await pool.query('UPDATE dashboard_users SET password_hash = $2 WHERE id = $1', [
    user,
    await hashDashboardPassword(password + ' replacement'),
  ]);
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', c).expect(401);
  await pool.query('UPDATE dashboard_users SET password_hash = $2 WHERE id = $1', [
    user,
    passwordHash,
  ]);
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', c).expect(401);
  const second = cookie(await login(undefined, 200));
  await pool.query("UPDATE operators SET status = 'suspended' WHERE id = $1", [operator]);
  await pool.query("UPDATE operators SET status = 'active' WHERE id = $1", [operator]);
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', second).expect(401);
});
it('ignores forged operator selection and invalidates replaced memberships', async () => {
  const logged = cookie(await login(undefined, 200));
  const identity = await request(app())
    .get('/dashboard-api/auth/me?operatorId=' + randomUUID())
    .set('Cookie', logged)
    .set('X-Operator-Id', randomUUID())
    .expect(200);
  expect((identity.body as { operator: { id: string } }).operator.id).toBe(operator);
  await pool.query('UPDATE dashboard_memberships SET id = $2 WHERE user_id = $1', [
    user,
    randomUUID(),
  ]);
  await request(app()).get('/dashboard-api/auth/me').set('Cookie', logged).expect(401);
});
it('accepts forwarded addresses only through explicitly trusted peers', async () => {
  const trustedApp = app('127.0.0.1/32,::1/128');
  for (let i = 0; i < 31; i++) {
    await request(trustedApp)
      .post('/dashboard-api/auth/login')
      .set('X-Forwarded-For', '192.0.2.' + i)
      .send({ username: 'unknown_' + i, password })
      .expect(403);
  }
  const untrustedApp = app('198.51.100.1/32');
  for (let i = 0; i < 30; i++)
    await request(untrustedApp)
      .post('/dashboard-api/auth/login')
      .set('X-Forwarded-For', '192.0.2.' + i)
      .send({})
      .expect(403);
  await request(untrustedApp)
    .post('/dashboard-api/auth/login')
    .set('X-Forwarded-For', '192.0.2.100')
    .send({})
    .expect(429);
});
it('shares IP limits across concurrent requests and refuses database failures', async () => {
  const results = await Promise.all(
    Array.from({ length: 35 }, () => request(app()).post('/dashboard-api/auth/login').send({})),
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
      .set('X-Forwarded-For', i % 2 ? '2001:db8::1' : '2001:0db8:0:0:0:0:0:1')
      .send({})
      .expect(403);
  }
  await request(trustedApp)
    .post('/dashboard-api/auth/login')
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
