import { createHash, randomBytes, randomUUID } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Pool } from 'pg';
import request from 'supertest';
import express from 'express';
import { beforeAll, afterAll, beforeEach, afterEach, expect, it, vi } from 'vitest';
import { createApp } from '../../src/app.js';
import { runMigrations } from '../../src/db/migrate.js';
import { createOperatorWithApiKey, generateOperatorApiKey } from '../../src/db/operator-keys.js';
import { withReadClient, ReadUnavailable } from '../../src/db/read-client.js';
import { signReadRestriction } from '../../src/payments/internal-read.js';
import { hashDashboardPassword } from '../../src/dashboard/passwords.js';
import { captureLogger, testConfig } from '../helpers.js';
import { openTestDatabase } from '../test-database.js';

let pool: Pool, gateway: http.Server, port: number, passwordHash: string;
let operator: string, otherOperator: string, reader: string, otherReader: string, writer: string;
let readerId: string, user: string, otherUser: string, session: string, otherSession: string;
let payment: string, otherPayment: string;
let gatewayRequests = 0;
let upstreamGate: ((req: http.IncomingMessage) => Promise<void>) | undefined;
const origin = 'https://bff.example.invalid';
const captured = captureLogger();
function app(overrides: Record<string, string> = {}, connectionPool: Pool = pool) {
  return createApp({
    pool: connectionPool,
    logger: captured.logger,
    config: testConfig({
      DASHBOARD_ENABLED: 'true',
      DASHBOARD_BFF_ENABLED: 'true',
      DASHBOARD_PUBLIC_ORIGIN: origin,
      DASHBOARD_OPERATOR_ID: operator,
      DASHBOARD_READ_ONLY_API_KEY: reader,
      PORT: String(port),
      ...overrides,
    }),
  });
}
async function identity(op: string) {
  const id = randomUUID(),
    token = randomBytes(32).toString('hex'),
    membership = randomUUID();
  await pool.query('INSERT INTO dashboard_users(id, username, password_hash) VALUES ($1, $2, $3)', [
    id,
    'bff_' + id,
    passwordHash,
  ]);
  await pool.query(
    'INSERT INTO dashboard_memberships(id, user_id, operator_id) VALUES ($1, $2, $3)',
    [membership, id, op],
  );
  await pool.query(
    'INSERT INTO dashboard_sessions(token_hash, csrf_hash, user_id, membership_id, auth_version) VALUES ($1, $2, $3, $4, 1)',
    [
      createHash('sha256').update(token).digest('hex'),
      randomBytes(32).toString('hex'),
      id,
      membership,
    ],
  );
  return { id, cookie: '__Host-vaultx_session=' + token };
}
beforeAll(async () => {
  pool = await openTestDatabase();
  await runMigrations(pool);
  passwordHash = await hashDashboardPassword('SYNTHETIC BFF fixture password');
  const gatewayApp = createApp({ pool, logger: captured.logger, config: testConfig() });
  gateway = http.createServer((req, res) => {
    gatewayRequests++;
    void (async () => {
      await upstreamGate?.(req);
      if (!res.destroyed) gatewayApp(req, res);
    })().catch(() => {
      if (!res.destroyed) {
        res.statusCode = 503;
        res.end();
      }
    });
  });
  await new Promise<void>((resolve) => {
    gateway.listen(0, '127.0.0.1', resolve);
  });
  port = (gateway.address() as AddressInfo).port;
});
beforeEach(async () => {
  const first = await createOperatorWithApiKey(
    pool,
    'BFF test',
    'bff_' + randomUUID(),
    'Read-only',
    'read_only',
  );
  const second = await createOperatorWithApiKey(
    pool,
    'Other BFF test',
    'bff_other_' + randomUUID(),
    'Read-only',
    'read_only',
  );
  operator = first.operatorId;
  reader = first.apiKey;
  readerId = first.keyId;
  otherOperator = second.operatorId;
  otherReader = second.apiKey;
  const generated = generateOperatorApiKey();
  writer = generated.apiKey;
  await pool.query(
    'INSERT INTO operator_api_keys(id, operator_id, name, key_hash) VALUES ($1, $2, $3, $4)',
    [randomUUID(), operator, 'Writer fixture', generated.keyHash],
  );
  const a = await identity(operator),
    b = await identity(otherOperator);
  user = a.id;
  session = a.cookie;
  otherUser = b.id;
  otherSession = b.cookie;
  payment = randomUUID();
  otherPayment = randomUUID();
  for (const [id, op] of [
    [payment, operator],
    [otherPayment, otherOperator],
  ]) {
    await pool.query(
      "INSERT INTO payments(id, operator_id, amount_minor, currency, idempotency_key) VALUES ($1, $2, 100, 'EUR', $3)",
      [id, op, randomUUID()],
    );
  }
});
afterEach(async () => {
  upstreamGate = undefined;
  for (const id of [user, otherUser])
    await pool.query('DELETE FROM dashboard_users WHERE id = $1', [id]);
  for (const op of [operator, otherOperator]) {
    await pool.query('DELETE FROM payments WHERE operator_id = $1', [op]);
    await pool.query('DELETE FROM operator_api_keys WHERE operator_id = $1', [op]);
    await pool.query('DELETE FROM operators WHERE id = $1', [op]);
  }
});
afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    gateway.close((error) => (error ? reject(error) : resolve())),
  );
  await pool.end();
});
it('reads history (including trailing slash), detail and minimal status through the real gateway', async () => {
  for (const path of ['/dashboard-api/payments', '/dashboard-api/payments/']) {
    const res = await request(app()).get(path).set('Cookie', session).expect(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect((res.body as { payments: { id: string }[] }).payments.map((p) => p.id)).toEqual([
      payment,
    ]);
  }
  const detail = await request(app())
    .get('/dashboard-api/payments/' + payment)
    .set('Cookie', session)
    .expect(200);
  expect((detail.body as { id: string }).id).toBe(payment);
  await request(app({ DASHBOARD_OPERATOR_ID: operator.toUpperCase() }))
    .get('/dashboard-api/payments/' + payment.toUpperCase())
    .set('Cookie', session)
    .expect(200);
  const status = await request(app())
    .get('/dashboard-api/status')
    .set('Cookie', session)
    .expect(200);
  expect(status.body).toEqual({
    status: 'ok',
    gateway: 'ok',
    database: 'reachable',
    provider: 'simulator',
    realPaymentsEnabled: false,
  });
  for (const value of [reader, otherReader, writer, session]) {
    expect(JSON.stringify([detail.body, status.body]).includes(value)).toBe(false);
    expect(captured.output().includes(value)).toBe(false);
  }
});
it('requires a session; browser Bearer keys never substitute for the session or server key', async () => {
  for (const path of [
    '/dashboard-api/payments',
    '/dashboard-api/payments/' + payment,
    '/dashboard-api/status',
  ]) {
    await request(app()).get(path).expect(401);
    await request(app()).get(path).auth(writer, { type: 'bearer' }).expect(401);
    await request(app())
      .get(path)
      .set('Cookie', session + '; ' + session)
      .expect(401);
  }
  const res = await request(app())
    .get('/dashboard-api/payments')
    .set('Cookie', session)
    .auth(otherReader, { type: 'bearer' })
    .set('X-Operator-Id', otherOperator)
    .expect(200);
  expect((res.body as { payments: { id: string }[] }).payments.map((p) => p.id)).toEqual([payment]);
});
it('isolates two populated operators and conceals another operator payment', async () => {
  await request(app())
    .get('/dashboard-api/payments/' + otherPayment)
    .set('Cookie', session)
    .expect(404);
  await request(app()).get('/dashboard-api/payments').set('Cookie', otherSession).expect(403);
  const other = app({
    DASHBOARD_OPERATOR_ID: otherOperator,
    DASHBOARD_READ_ONLY_API_KEY: otherReader,
  });
  const res = await request(other)
    .get('/dashboard-api/payments')
    .set('Cookie', otherSession)
    .expect(200);
  expect((res.body as { payments: { id: string }[] }).payments.map((p) => p.id)).toEqual([
    otherPayment,
  ]);
  await request(other)
    .get('/dashboard-api/payments/' + payment)
    .set('Cookie', otherSession)
    .expect(404);
});
it.each(['disabled', 'suspended', 'membership', 'expired'])(
  'rejects %s identities on every BFF operation without contacting the gateway',
  async (mode) => {
    if (mode === 'disabled')
      await pool.query("UPDATE dashboard_users SET status = 'disabled' WHERE id = $1", [user]);
    if (mode === 'suspended')
      await pool.query("UPDATE operators SET status = 'suspended' WHERE id = $1", [operator]);
    if (mode === 'membership')
      await pool.query('DELETE FROM dashboard_memberships WHERE user_id = $1', [user]);
    if (mode === 'expired')
      await pool.query(
        "UPDATE dashboard_sessions SET last_seen_at = clock_timestamp() - INTERVAL '31 minutes' WHERE user_id = $1",
        [user],
      );
    const before = gatewayRequests;
    for (const path of [
      '/dashboard-api/payments',
      '/dashboard-api/payments/' + payment,
      '/dashboard-api/status',
    ])
      await request(app()).get(path).set('Cookie', session).expect(401);
    expect(gatewayRequests).toBe(before);
  },
);
it('rejects missing, mismatched, write-enabled and revoked server credentials', async () => {
  expect(() => app({ DASHBOARD_READ_ONLY_API_KEY: '' })).toThrow();
  const before = gatewayRequests;
  for (const key of [writer, otherReader, generateOperatorApiKey().apiKey]) {
    for (const path of [
      '/dashboard-api/payments',
      '/dashboard-api/payments/' + payment,
      '/dashboard-api/status',
    ])
      await request(app({ DASHBOARD_READ_ONLY_API_KEY: key }))
        .get(path)
        .set('Cookie', session)
        .expect(503);
  }
  const active = app();
  await request(active).get('/dashboard-api/status').set('Cookie', session).expect(200);
  const afterValid = gatewayRequests;
  expect(afterValid).toBe(before + 1);
  await pool.query('UPDATE operator_api_keys SET revoked_at = NOW() WHERE id = $1', [readerId]);
  for (const path of [
    '/dashboard-api/payments',
    '/dashboard-api/payments/' + payment,
    '/dashboard-api/status',
  ])
    await request(active).get(path).set('Cookie', session).expect(503);
  expect(gatewayRequests).toBe(afterValid);
});
it('validates filters, pagination, identifiers and rejects authoritative operator or URL input', async () => {
  for (const query of [
    'limit=0',
    'limit=101',
    'limit=1&limit=2',
    'offset=-1',
    'offset=10001',
    'currency=eur',
    'status=unknown',
    'operatorId=' + otherOperator,
    'url=https://hostile.invalid',
    'method=POST',
  ])
    await request(app())
      .get('/dashboard-api/payments?' + query)
      .set('Cookie', session)
      .expect(400);
  await request(app()).get('/dashboard-api/payments/not-a-uuid').set('Cookie', session).expect(400);
  await request(app())
    .get('/dashboard-api/payments/' + payment + '?operatorId=' + otherOperator)
    .set('Cookie', session)
    .expect(400);
  await request(app())
    .get('/dashboard-api/status?url=https://hostile.invalid')
    .set('Cookie', session)
    .expect(400);
  const res = await request(app())
    .get('/dashboard-api/payments?limit=1&offset=1&currency=EUR&status=pending')
    .set('Cookie', session)
    .expect(200);
  expect(res.body).toEqual({ payments: [], pagination: { limit: 1, offset: 1, hasMore: false } });
});
it('blocks write methods and undefined operations without forwarding or modifying payments', async () => {
  const before = gatewayRequests;
  for (const path of [
    '/dashboard-api/payments',
    '/dashboard-api/payments/' + payment + '/simulate',
    '/dashboard-api/refunds',
    '/dashboard-api/keys',
  ]) {
    await request(app())
      .post(path)
      .set('Cookie', session)
      .send({ outcome: 'succeeded' })
      .expect(405);
    await request(app()).delete(path).set('Cookie', session).expect(405);
    await request(app()).put(path).set('Cookie', session).send({}).expect(405);
  }
  await request(app()).head('/dashboard-api/payments').set('Cookie', session).expect(405);
  await request(app()).get('/dashboard-api/proxy').set('Cookie', session).expect(404);
  expect(gatewayRequests).toBe(before);
  expect((await pool.query('SELECT status FROM payments WHERE id = $1', [payment])).rows).toEqual([
    { status: 'pending' },
  ]);
  await request(app())
    .post('/payments')
    .set('Cookie', session)
    .set('Idempotency-Key', randomUUID())
    .send({ amountMinor: 100, currency: 'EUR' })
    .expect(401);
  await request(app())
    .get('/payments/' + payment)
    .auth(reader, { type: 'bearer' })
    .expect(200);
  await request(app())
    .post('/payments/' + payment + '/simulate')
    .auth(reader, { type: 'bearer' })
    .send({ outcome: 'succeeded' })
    .expect(403);
});
it('remains default-off independently of authentication enablement', async () => {
  expect(() => app({ DASHBOARD_ENABLED: 'false' })).toThrow();
  expect(() => app({ DASHBOARD_OPERATOR_ID: '' })).toThrow();
  await request(app({ DASHBOARD_BFF_ENABLED: 'false' }))
    .get('/dashboard-api/payments')
    .set('Cookie', session)
    .expect(404);
  await request(app({ DASHBOARD_BFF_ENABLED: 'false', DASHBOARD_ENABLED: 'false' }))
    .get('/dashboard-api/status')
    .expect(404);
});
it('projects untrusted extra fields and rejects unsafe simulator status', async () => {
  let unsafe = false;
  const fake = http.createServer((_req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Set-Cookie', 'UNTRUSTED_UPSTREAM_COOKIE=value');
    if (unsafe)
      res.end(JSON.stringify({ status: 'ok', service: 'vaultx-pay', realPaymentsEnabled: true }));
    else
      res.end(
        JSON.stringify({
          id: payment,
          amountMinor: 100,
          currency: 'EUR',
          status: 'pending',
          provider: 'simulator',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          apiKey: reader,
          databaseUrl: 'PRIVATE_SYNTHETIC_CONFIG',
        }),
      );
  });
  await new Promise<void>((resolve) => {
    fake.listen(0, '127.0.0.1', resolve);
  });
  try {
    const bounded = app({ PORT: String((fake.address() as AddressInfo).port) });
    const detail = await request(bounded)
      .get('/dashboard-api/payments/' + payment)
      .set('Cookie', session)
      .expect(200);
    expect(JSON.stringify(detail.body).includes(reader)).toBe(false);
    expect(JSON.stringify(detail.body).includes('PRIVATE_SYNTHETIC_CONFIG')).toBe(false);
    expect(detail.headers['set-cookie']).toBeUndefined();
    unsafe = true;
    await request(bounded).get('/dashboard-api/status').set('Cookie', session).expect(502);
  } finally {
    await new Promise<void>((resolve) => {
      fake.close(() => resolve());
    });
  }
});
it('rechecks key permission after a previously successful request', async () => {
  const active = app();
  await request(active).get('/dashboard-api/status').set('Cookie', session).expect(200);
  await pool.query("UPDATE operator_api_keys SET permission = 'read_write' WHERE id = $1", [
    readerId,
  ]);
  const before = gatewayRequests;
  await request(active).get('/dashboard-api/payments').set('Cookie', session).expect(503);
  expect(gatewayRequests).toBe(before);
});
it('serves the BFF and its real internal payment API on the same listener without holding a DB lease', async () => {
  const single = await openTestDatabase();
  single.options.max = 1;
  const shell = express();
  const combined = http.createServer(shell);
  await new Promise<void>((resolve) => {
    combined.listen(0, '127.0.0.1', resolve);
  });
  shell.use(app({ PORT: String((combined.address() as AddressInfo).port) }, single));
  try {
    const res = await request(combined)
      .get('/dashboard-api/payments')
      .set('Cookie', session)
      .expect(200);
    expect((res.body as { payments: { id: string }[] }).payments.map((p) => p.id)).toEqual([
      payment,
    ]);
    await request(combined).get('/dashboard-api/status').set('Cookie', session).expect(200);
  } finally {
    await new Promise<void>((resolve) => {
      combined.close(() => resolve());
    });
    await single.end();
  }
});
function barrier() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
it.each(['ownership', 'permission', 'revoked'])(
  'enforces the bound operator and read_only scope after a concurrent %s change',
  async (mode) => {
    for (const path of [
      '/dashboard-api/payments',
      '/dashboard-api/payments/' + otherPayment,
      '/dashboard-api/status',
    ]) {
      await pool.query(
        "UPDATE operator_api_keys SET operator_id = $2, permission = 'read_only', revoked_at = NULL WHERE id = $1",
        [readerId, operator],
      );
      const entered = barrier(),
        release = barrier();
      upstreamGate = async () => {
        entered.resolve();
        await release.promise;
      };
      const pending = request(app())
        .get(path)
        .set('Cookie', session)
        .then((r) => r);
      try {
        await entered.promise; // BFF key check completed; payment authentication has not run.
        if (mode === 'ownership')
          await pool.query('UPDATE operator_api_keys SET operator_id = $2 WHERE id = $1', [
            readerId,
            otherOperator,
          ]);
        if (mode === 'permission')
          await pool.query("UPDATE operator_api_keys SET permission = 'read_write' WHERE id = $1", [
            readerId,
          ]);
        if (mode === 'revoked')
          await pool.query('UPDATE operator_api_keys SET revoked_at = NOW() WHERE id = $1', [
            readerId,
          ]);
        release.resolve();
        const res = await pending;
        expect(res.status).toBe(503);
        for (const secret of [reader, writer, otherReader, otherPayment]) {
          expect(JSON.stringify(res.body).includes(secret)).toBe(false);
          expect(captured.output().includes(reader)).toBe(false);
        }
      } finally {
        release.resolve();
        await pending;
        upstreamGate = undefined;
      }
    }
  },
);
it('rejects forged, partial or replayed restriction headers, which never substitute for a Bearer key', async () => {
  await request(app())
    .get('/dashboard-api/payments')
    .set('Cookie', session)
    .set('X-Vaultx-Read-Operator', otherOperator)
    .expect(403);
  await request(app())
    .get('/payments')
    .auth(reader, { type: 'bearer' })
    .set('X-Vaultx-Read-Operator', operator)
    .expect(403);
  const restriction = signReadRestriction('/payments', reader, operator);
  await request(app()).get('/payments').set(restriction).expect(403);
  await request(app())
    .get('/payments/' + payment)
    .auth(reader, { type: 'bearer' })
    .set(restriction)
    .expect(403);
  await request(app())
    .post('/payments')
    .auth(writer, { type: 'bearer' })
    .set(restriction)
    .send({ amountMinor: 100, currency: 'EUR' })
    .expect(403);
  await request(app())
    .get('/payments')
    .auth(reader, { type: 'bearer' })
    .set(signReadRestriction('/payments', reader, otherOperator))
    .expect(401);
  await request(app())
    .get('/payments')
    .auth(writer, { type: 'bearer' })
    .set(signReadRestriction('/payments', writer, operator))
    .expect(401);
  await request(app()).get('/payments').auth(reader, { type: 'bearer' }).expect(200);
});
it.each(['disabled', 'membership', 'suspended'])(
  'documents one in-flight read and rejects subsequent requests after %s changes',
  async (mode) => {
    const entered = barrier(),
      release = barrier();
    upstreamGate = async () => {
      entered.resolve();
      await release.promise;
    };
    const active = app();
    const pending = request(active)
      .get('/dashboard-api/payments')
      .set('Cookie', session)
      .then((r) => r);
    try {
      await entered.promise;
      if (mode === 'disabled')
        await pool.query("UPDATE dashboard_users SET status = 'disabled' WHERE id = $1", [user]);
      if (mode === 'membership')
        await pool.query('UPDATE dashboard_memberships SET operator_id = $2 WHERE user_id = $1', [
          user,
          otherOperator,
        ]);
      if (mode === 'suspended')
        await pool.query("UPDATE operators SET status = 'suspended' WHERE id = $1", [operator]);
      release.resolve();
      const result = await pending;
      expect(result.status).toBe(mode === 'suspended' ? 503 : 200);
      if (result.status === 200)
        expect((result.body as { payments: { id: string }[] }).payments.map((p) => p.id)).toEqual([
          payment,
        ]);
      expect(JSON.stringify(result.body).includes(otherPayment)).toBe(false);
      upstreamGate = undefined;
      await request(active).get('/dashboard-api/payments').set('Cookie', session).expect(401);
    } finally {
      release.resolve();
      await pending;
      upstreamGate = undefined;
    }
  },
);
it(
  'bounds locks and statement execution, rolls back failed reads and recovers',
  { timeout: 10000 },
  async () => {
    const schema = 'bff_read_' + randomUUID().replaceAll('-', '');
    await pool.query(`CREATE SCHEMA ${schema}; CREATE TABLE ${schema}.fixture(id INTEGER)`);
    const blocker = await pool.connect();
    try {
      await blocker.query(`BEGIN; LOCK TABLE ${schema}.fixture IN ACCESS EXCLUSIVE MODE`);
      await expect(
        withReadClient(pool, (client) => client.query(`SELECT * FROM ${schema}.fixture`)),
      ).rejects.toBeInstanceOf(ReadUnavailable);
      await blocker.query('ROLLBACK');
      await expect(
        withReadClient(pool, (client) => client.query('SELECT pg_sleep(2)')),
      ).rejects.toBeInstanceOf(ReadUnavailable);
      await expect(
        withReadClient(pool, (client) => client.query('SELECT pg_sleep(2)'), { totalMs: 50 }),
      ).rejects.toBeInstanceOf(ReadUnavailable);
      const recovered = await withReadClient(pool, (client) =>
        client.query<{ ready: number }>('SELECT 1 AS ready'),
      );
      expect(recovered.rows).toEqual([{ ready: 1 }]);
    } finally {
      await blocker.query('ROLLBACK');
      blocker.release();
      await pool.query(`DROP SCHEMA ${schema} CASCADE`);
    }
  },
);
it(
  'bounds queued acquisitions during pool exhaustion and never executes late read work',
  { timeout: 10000 },
  async () => {
    const single = await openTestDatabase();
    single.options.max = 1;
    const held = await single.connect();
    let released = false;
    const work = vi.fn(() => Promise.resolve(true));
    try {
      const pending = Array.from({ length: 4 }, () => withReadClient(single, work));
      await expect(withReadClient(single, work)).rejects.toBeInstanceOf(ReadUnavailable);
      const results = await Promise.allSettled(pending);
      expect(results.every((r) => r.status === 'rejected')).toBe(true);
      await expect(withReadClient(single, work)).rejects.toBeInstanceOf(ReadUnavailable);
      expect(work).not.toHaveBeenCalled();
      const unavailable = await request(app({}, single))
        .get('/dashboard-api/payments')
        .set('Cookie', session)
        .expect(503);
      expect(JSON.stringify(unavailable.body).includes(reader)).toBe(false);
      held.release();
      released = true;
      await single.query('SELECT 1'); // Drains timed-out queued acquisitions; none may run work.
      expect(work).not.toHaveBeenCalled();
      expect(await withReadClient(single, work)).toBe(true);
    } finally {
      if (!released) held.release();
      await single.end();
    }
  },
);
it('recovers after an upstream disconnect, releases admission, and rejects excess concurrent BFF work', async () => {
  upstreamGate = (req) => {
    req.socket.destroy();
    return Promise.resolve();
  };
  const active = app();
  await request(active).get('/dashboard-api/payments').set('Cookie', session).expect(502);
  upstreamGate = undefined;
  await request(active).get('/dashboard-api/payments').set('Cookie', session).expect(200);
  const entered = barrier(),
    release = barrier();
  let count = 0;
  upstreamGate = async () => {
    count++;
    if (count === 4) entered.resolve();
    await release.promise;
  };
  const pending = Array.from({ length: 4 }, () =>
    request(active)
      .get('/dashboard-api/payments')
      .set('Cookie', session)
      .then((r) => r),
  );
  try {
    await entered.promise;
    await request(active).get('/dashboard-api/payments').set('Cookie', session).expect(503);
    release.resolve();
    expect((await Promise.all(pending)).every((r) => r.status === 200)).toBe(true);
  } finally {
    release.resolve();
    await Promise.all(pending);
    upstreamGate = undefined;
  }
  await request(active).get('/dashboard-api/payments').set('Cookie', session).expect(200);
});
it('aborts the upstream socket when the browser disconnects without starting new work', async () => {
  const entered = barrier(),
    release = barrier(),
    closed = barrier();
  upstreamGate = async (req) => {
    req.socket.once('close', () => closed.resolve());
    entered.resolve();
    await release.promise;
  };
  const running = request(app()).get('/dashboard-api/payments').set('Cookie', session);
  const pending = running.then((r) => r).catch(() => undefined);
  try {
    await entered.promise;
    running.abort();
    await closed.promise;
  } finally {
    release.resolve();
    await pending;
    upstreamGate = undefined;
  }
  await request(app()).get('/dashboard-api/status').set('Cookie', session).expect(200);
});
it.each(['wrong-id', 'pagination', 'provider'])(
  'rejects invalid upstream %s payloads without leaking records or credentials',
  async (mode) => {
    const fake = http.createServer((_req, res) => {
      const item = {
        id: mode === 'wrong-id' ? otherPayment : payment,
        amountMinor: 100,
        currency: 'EUR',
        status: 'pending',
        provider: mode === 'provider' ? 'real-provider' : 'simulator',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        apiKey: reader,
      };
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify(
          mode === 'pagination'
            ? {
                payments: [item],
                pagination: { limit: 99, offset: 0, hasMore: false },
                credential: reader,
              }
            : item,
        ),
      );
    });
    await new Promise<void>((resolve) => {
      fake.listen(0, '127.0.0.1', resolve);
    });
    try {
      const bounded = app({ PORT: String((fake.address() as AddressInfo).port) });
      const path =
        mode === 'pagination'
          ? '/dashboard-api/payments?limit=1'
          : '/dashboard-api/payments/' + payment;
      const res = await request(bounded).get(path).set('Cookie', session).expect(502);
      for (const secret of [reader, otherPayment]) {
        expect(JSON.stringify(res.body).includes(secret)).toBe(false);
        expect(captured.output().includes(reader)).toBe(false);
      }
    } finally {
      await new Promise<void>((resolve) => {
        fake.close(() => resolve());
      });
    }
  },
);
it('sanitizes DB failures and rejects PATCH/OPTIONS/TRACE without invoking upstream', async () => {
  const broken = {
    connect: () => Promise.reject(new Error('PRIVATE_DB_DETAIL')),
    query: () => Promise.reject(new Error('PRIVATE_DB_DETAIL')),
  } as unknown as Pool;
  const res = await request(app({}, broken))
    .get('/dashboard-api/payments')
    .set('Cookie', session)
    .expect(503);
  expect(JSON.stringify(res.body).includes('PRIVATE_DB_DETAIL')).toBe(false);
  expect(captured.output().includes('PRIVATE_DB_DETAIL')).toBe(false);
  const before = gatewayRequests;
  for (const method of ['patch', 'options', 'trace'] as const)
    await request(app())[method]('/dashboard-api/payments').set('Cookie', session).expect(405);
  expect(gatewayRequests).toBe(before);
  for (const credential of [reader, writer, otherReader])
    expect(captured.output().includes(credential)).toBe(false);
  expect(captured.output().includes('\"amountMinor\"')).toBe(false);
});
