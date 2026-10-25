import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import type { Pool } from 'pg';
import type { Express } from 'express';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import type { Config } from '../../src/config/index.js';
import { UnsafeConfigurationError } from '../../src/config/safety.js';
import { runMigrations } from '../../src/db/migrate.js';
import { createOperatorWithApiKey, revokeOperatorKey } from '../../src/db/operator-keys.js';
import { captureLogger, testConfig } from '../helpers.js';
import { openTestDatabase } from '../test-database.js';

const config = testConfig();
const { logger } = captureLogger();
let pool: Pool;
let app: Express;

let operatorId = '';
let keyId = '';
let apiKey = '';
const otherOperatorIds: string[] = [];

beforeAll(async () => {
  // No migrations, fixtures, requests, or cleanup can run before verification.
  pool = await openTestDatabase();
  await runMigrations(pool);
  app = createApp({ config, logger, pool });
});

beforeEach(async () => {
  const created = await createOperatorWithApiKey(
    pool,
    'Integration Test Operator',
    `test_${randomUUID().replaceAll('-', '')}`,
  );
  operatorId = created.operatorId;
  keyId = created.keyId;
  apiKey = created.apiKey;
});

afterEach(async () => {
  for (const id of [operatorId, ...otherOperatorIds].filter(Boolean)) {
    await pool.query('DELETE FROM payments WHERE operator_id = $1', [id]);
    await pool.query('DELETE FROM operator_api_keys WHERE operator_id = $1', [id]);
    await pool.query('DELETE FROM operators WHERE id = $1', [id]);
  }
  otherOperatorIds.length = 0;
  operatorId = '';
  keyId = '';
  apiKey = '';
});

afterAll(async () => {
  await pool?.end();
});

describe('GET /health', () => {
  it('returns a simple status without sensitive information', async () => {
    const res = await request(app).get('/health');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      status: 'ok',
      service: 'vaultx-pay',
      realPaymentsEnabled: false,
    });
  });

  it('does not expose the Express technology header', async () => {
    const res = await request(app).get('/health');

    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });
});

describe('request handling', () => {
  it('returns a structured 404 for unknown routes', async () => {
    const res = await request(app).get('/does-not-exist');

    expect(res.status).toBe(404);
    expect(res.body).toMatchObject({ error: { code: 'not_found' } });
  });

  it('rejects payment creation without an API key', async () => {
    const res = await request(app)
      .post('/payments')
      .set('Idempotency-Key', 'test-idem-key')
      .send({ amountMinor: 1000, currency: 'USD' });

    expect(res.status).toBe(401);
  });

  it('rejects a malformed API key without querying the database', async () => {
    const res = await request(app)
      .post('/payments')
      .set('Authorization', 'Bearer not-a-valid-key')
      .set('Idempotency-Key', 'test-idem-key')
      .send({ amountMinor: 1000, currency: 'USD' });

    expect(res.status).toBe(401);
  });

  it('rejects invalid payment bodies', async () => {
    const res = await request(app)
      .post('/payments')
      .set('Authorization', `Bearer ${apiKey}`)
      .set('Idempotency-Key', 'test-idem-key')
      .send({ amountMinor: -1, currency: 'usd' });

    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({ error: { code: 'invalid_request' } });
  });

  it('requires a valid idempotency key', async () => {
    const res = await request(app)
      .post('/payments')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ amountMinor: 1000, currency: 'USD' });

    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({ error: { code: 'invalid_idempotency_key' } });
  });
});

describe('operator API keys', () => {
  it('creates a simulated payment for an authenticated operator', async () => {
    const res = await request(app)
      .post('/payments')
      .set('Authorization', `Bearer ${apiKey}`)
      .set('Idempotency-Key', 'payment-create-123')
      .send({ amountMinor: 1000, currency: 'USD' });

    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      amountMinor: 1000,
      currency: 'USD',
      status: 'pending',
      provider: 'simulator',
    });
    expect(res.body.id).toEqual(expect.any(String));
  });

  it('returns the original payment for an identical retry', async () => {
    const sendPayment = () =>
      request(app)
        .post('/payments')
        .set('Authorization', `Bearer ${apiKey}`)
        .set('Idempotency-Key', 'payment-retry-123')
        .send({ amountMinor: 2500, currency: 'EUR' });

    const first = await sendPayment();
    const second = await sendPayment();

    expect(first.status).toBe(201);
    expect(second.status).toBe(200);
    expect(second.body.id).toBe(first.body.id);
  });

  it('rejects reuse of an idempotency key with a different amount', async () => {
    const first = await request(app)
      .post('/payments')
      .set('Authorization', `Bearer ${apiKey}`)
      .set('Idempotency-Key', 'payment-conflict-123')
      .send({ amountMinor: 2500, currency: 'EUR' });

    const second = await request(app)
      .post('/payments')
      .set('Authorization', `Bearer ${apiKey}`)
      .set('Idempotency-Key', 'payment-conflict-123')
      .send({ amountMinor: 2600, currency: 'EUR' });

    expect(first.status).toBe(201);
    expect(second.status).toBe(409);
    expect(second.body).toMatchObject({ error: { code: 'idempotency_conflict' } });
  });

  it('returns the same payment for concurrent identical requests', async () => {
    const sendPayment = () =>
      request(app)
        .post('/payments')
        .set('Authorization', `Bearer ${apiKey}`)
        .set('Idempotency-Key', 'payment-concurrent-123')
        .send({ amountMinor: 5000, currency: 'GBP' });

    const [first, second] = await Promise.all([sendPayment(), sendPayment()]);

    expect([first.status, second.status].sort()).toEqual([200, 201]);
    expect(first.body.id).toBe(second.body.id);
  });

  it('rejects a revoked API key', async () => {
    expect(await revokeOperatorKey(pool, keyId, operatorId)).toBe(true);

    const res = await request(app)
      .post('/payments')
      .set('Authorization', `Bearer ${apiKey}`)
      .set('Idempotency-Key', 'payment-revoked-123')
      .send({ amountMinor: 1000, currency: 'USD' });

    expect(res.status).toBe(401);
  });

  it('does not allow one operator to revoke another operator key', async () => {
    const other = await createOperatorWithApiKey(
      pool,
      'Other Integration Operator',
      `other_${randomUUID().replaceAll('-', '')}`,
    );

    try {
      expect(await revokeOperatorKey(pool, keyId, other.operatorId)).toBe(false);
    } finally {
      await pool.query('DELETE FROM operator_api_keys WHERE operator_id = $1', [other.operatorId]);
      await pool.query('DELETE FROM operators WHERE id = $1', [other.operatorId]);
    }
  });
});

describe('configuration safety', () => {
  it('rejects unsafe live-payment configuration', () => {
    const unsafe = {
      ...config,
      liveModeEnabled: true,
    } as unknown as Config;

    expect(() => createApp({ config: unsafe, logger, pool })).toThrow(UnsafeConfigurationError);
  });
});

describe('simulated payment lifecycle', () => {
  function create(key = randomUUID(), credential = apiKey) {
    return request(app)
      .post('/payments')
      .set('Authorization', `Bearer ${credential}`)
      .set('Idempotency-Key', key)
      .send({ amountMinor: 2500, currency: 'EUR' });
  }
  function retrieve(id: string, credential = apiKey) {
    return request(app).get(`/payments/${id}`).set('Authorization', `Bearer ${credential}`);
  }
  function simulate(id: string, outcome: string, credential = apiKey) {
    return request(app)
      .post(`/payments/${id}/simulate`)
      .set('Authorization', `Bearer ${credential}`)
      .send({ outcome });
  }
  async function otherOperator() {
    const other = await createOperatorWithApiKey(pool, 'Lifecycle Other', `other_${randomUUID()}`);
    otherOperatorIds.push(other.operatorId);
    return other;
  }

  it('persists and retrieves the complete pending payment', async () => {
    const created = await create();
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({
      status: 'pending',
      provider: 'simulator',
      amountMinor: 2500,
      currency: 'EUR',
    });
    const found = await retrieve(created.body.id);
    expect(found.status).toBe(200);
    expect(found.body).toEqual(created.body);
    const persisted = await pool.query<{ created_at: Date; updated_at: Date }>(
      'SELECT * FROM payments WHERE id = $1',
      [created.body.id],
    );
    expect(persisted.rows[0]).toMatchObject({
      operator_id: operatorId,
      amount_minor: '2500',
      currency: 'EUR',
      status: 'pending',
      provider: 'simulator',
    });
    expect(created.body.createdAt).toBe(persisted.rows[0]!.created_at.toISOString());
    expect(created.body.updatedAt).toBe(persisted.rows[0]!.updated_at.toISOString());
  });

  it.each(['succeeded', 'failed'])(
    'persists %s and makes identical retries read-only',
    async (outcome) => {
      const created = await create();
      const completed = await simulate(created.body.id, outcome);
      expect(completed.status).toBe(200);
      expect(completed.body).toMatchObject({
        ...created.body,
        status: outcome,
        updatedAt: expect.any(String),
      });
      expect(Date.parse(completed.body.updatedAt)).toBeGreaterThanOrEqual(
        Date.parse(created.body.updatedAt),
      );
      const retried = await simulate(created.body.id, outcome);
      expect(retried.status).toBe(200);
      expect(retried.body).toEqual(completed.body);
      expect((await retrieve(created.body.id)).body).toEqual(completed.body);
      const persisted = await pool.query<{ status: string; updated_at: Date }>(
        'SELECT status, updated_at FROM payments WHERE id = $1',
        [created.body.id],
      );
      expect(persisted.rows[0]!.status).toBe(outcome);
      expect(persisted.rows[0]!.updated_at.toISOString()).toBe(completed.body.updatedAt);
    },
  );

  it.each([
    ['succeeded', 'failed'],
    ['failed', 'succeeded'],
  ])('refuses reversal from %s to %s', async (first, second) => {
    const created = await create();
    const completed = await simulate(created.body.id, first);
    const conflict = await simulate(created.body.id, second);
    expect(conflict.status).toBe(409);
    expect(conflict.body.error.code).toBe('invalid_payment_transition');
    expect((await retrieve(created.body.id)).body).toEqual(completed.body);
  });

  it('keeps a completed payment when creation is retried', async () => {
    const key = randomUUID();
    const created = await create(key);
    const completed = await simulate(created.body.id, 'succeeded');
    const retried = await create(key);
    expect(retried.status).toBe(200);
    expect(retried.body).toEqual(completed.body);
    const conflict = await request(app)
      .post('/payments')
      .set('Authorization', `Bearer ${apiKey}`)
      .set('Idempotency-Key', key)
      .send({ amountMinor: 2500, currency: 'USD' });
    expect(conflict.status).toBe(409);
    expect((await retrieve(created.body.id)).body).toEqual(completed.body);
  });

  it('serializes concurrent conflicting outcomes to one durable final state', async () => {
    const created = await create();
    const responses = await Promise.all([
      simulate(created.body.id, 'succeeded'),
      simulate(created.body.id, 'failed'),
    ]);
    expect(responses.map((res) => res.status).sort()).toEqual([200, 409]);
    const winner = responses.find((res) => res.status === 200)!;
    expect((await retrieve(created.body.id)).body).toEqual(winner.body);
  });

  it('handles concurrent identical simulation requests idempotently', async () => {
    const created = await create();
    const [first, second] = await Promise.all([
      simulate(created.body.id, 'succeeded'),
      simulate(created.body.id, 'succeeded'),
    ]);
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(first.body).toEqual(second.body);
  });

  it('creates only one row for concurrent conflicting creation requests', async () => {
    const key = randomUUID();
    const responses = await Promise.all([
      create(key),
      request(app)
        .post('/payments')
        .set('Authorization', `Bearer ${apiKey}`)
        .set('Idempotency-Key', key)
        .send({ amountMinor: 2600, currency: 'EUR' }),
    ]);
    expect(responses.map((res) => res.status).sort()).toEqual([201, 409]);
    const result = await pool.query(
      'SELECT count(*)::int AS count FROM payments WHERE operator_id = $1 AND idempotency_key = $2',
      [operatorId, key],
    );
    expect(result.rows[0].count).toBe(1);
  });

  it('isolates idempotency keys between operators', async () => {
    const other = await otherOperator();
    const key = randomUUID();
    const first = await create(key);
    const second = await create(key, other.apiKey);
    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    expect(first.body.id).not.toBe(second.body.id);
  });

  it('conceals and protects other operators payments', async () => {
    const created = await create();
    const other = await otherOperator();
    expect((await retrieve(created.body.id, other.apiKey)).status).toBe(404);
    expect((await simulate(created.body.id, 'succeeded', other.apiKey)).status).toBe(404);
    expect((await retrieve(created.body.id)).body).toEqual(created.body);
  });

  it.each(['missing', 'unknown', 'revoked', 'suspended'])(
    'rejects %s credentials across the lifecycle',
    async (kind) => {
      const created = await create();
      let credential = apiKey;
      if (kind === 'missing') credential = '';
      if (kind === 'unknown') credential = `vxp_${'0'.repeat(64)}`;
      if (kind === 'revoked') await revokeOperatorKey(pool, keyId, operatorId);
      if (kind === 'suspended')
        await pool.query("UPDATE operators SET status = 'suspended' WHERE id = $1", [operatorId]);
      expect((await create(randomUUID(), credential)).status).toBe(401);
      expect((await retrieve(created.body.id, credential)).status).toBe(401);
      expect((await simulate(created.body.id, 'succeeded', credential)).status).toBe(401);
      const persisted = await pool.query('SELECT status FROM payments WHERE id = $1', [
        created.body.id,
      ]);
      expect(persisted.rows[0].status).toBe('pending');
    },
  );

  it('validates UUIDs and returns 404 for nonexistent payments', async () => {
    expect((await retrieve('invalid-id')).status).toBe(400);
    expect((await simulate('invalid-id', 'succeeded')).status).toBe(400);
    expect((await retrieve(randomUUID())).status).toBe(404);
    expect((await simulate(randomUUID(), 'failed')).status).toBe(404);
  });

  it.each([
    {},
    { outcome: 'pending' },
    { outcome: 'success' },
    { outcome: 'cancelled' },
    { outcome: 'succeeded', amountMinor: 1 },
    { outcome: 'failed', provider: 'real' },
  ])('rejects invalid simulation input %j', async (body) => {
    const created = await create();
    const invalid = await request(app)
      .post(`/payments/${created.body.id}/simulate`)
      .set('Authorization', `Bearer ${apiKey}`)
      .send(body);
    expect(invalid.status).toBe(400);
    expect((await retrieve(created.body.id)).body).toEqual(created.body);
  });

  it.each([
    { amountMinor: 0, currency: 'EUR' },
    { amountMinor: 1.5, currency: 'EUR' },
    { amountMinor: 100_000_001, currency: 'EUR' },
    { amountMinor: 100, currency: 'eur' },
    { amountMinor: 100, currency: 'EUR', status: 'succeeded' },
  ])('rejects invalid creation input %j', async (body) => {
    const response = await request(app)
      .post('/payments')
      .set('Authorization', `Bearer ${apiKey}`)
      .set('Idempotency-Key', randomUUID())
      .send(body);
    expect(response.status).toBe(400);
  });

  it('supports simulator processing in production configuration with debug controls disabled', async () => {
    const productionApp = createApp({
      config: testConfig({ NODE_ENV: 'production' }),
      logger,
      pool,
    });
    const created = await request(productionApp)
      .post('/payments')
      .set('Authorization', `Bearer ${apiKey}`)
      .set('Idempotency-Key', randomUUID())
      .send({ amountMinor: 100, currency: 'EUR' });
    expect(created.status).toBe(201);
    const completed = await request(productionApp)
      .post(`/payments/${created.body.id}/simulate`)
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ outcome: 'succeeded' });
    expect(completed.status).toBe(200);
    expect(completed.body.status).toBe('succeeded');
    expect((await request(productionApp).get('/health')).body.realPaymentsEnabled).toBe(false);
  });
});

// Exercise the exact distributed client controller against the real gateway and
// independently verified disposable PostgreSQL, reusing this suite's fixture key.
it('runs the Windows smoke-test controller through the persisted simulator lifecycle', async () => {
  const { run } = createRequire(import.meta.url)('../../tools/simulated-payment-test/flow.js') as {
    run(
      this: void,
      options: {
        request(
          method: 'GET' | 'POST',
          route: string,
          body: Record<string, unknown> | undefined,
          settings: { auth?: boolean; idempotencyKey?: string },
        ): Promise<{ status: number; body: unknown }>;
        confirm(): Promise<string>;
        begin(record: Record<string, unknown>): Promise<void>;
        record(record: Record<string, unknown>): Promise<void>;
      },
    ): Promise<{ result: string; paymentId: string }>;
  };
  const records: Record<string, unknown>[] = [];
  const result = await run({
    request: async (method, route, body, settings) => {
      const operation = method === 'GET' ? request(app).get(route) : request(app).post(route);
      if (settings.auth !== false) operation.set('Authorization', `Bearer ${apiKey}`);
      if (settings.idempotencyKey) operation.set('Idempotency-Key', settings.idempotencyKey);
      if (body) operation.send(body);
      const response = await operation;
      return { status: response.status, body: response.body };
    },
    confirm: () => Promise.resolve('RUN ONE SIMULATED PAYMENT'),
    begin: (value) => {
      records.push(value);
      return Promise.resolve();
    },
    record: (value) => {
      records.push(value);
      return Promise.resolve();
    },
  });
  expect(result.result).toBe('SIMULATED_PAYMENT_VERIFIED');
  const persisted = await pool.query(
    'SELECT id,status,provider,amount_minor FROM payments WHERE operator_id=$1',
    [operatorId],
  );
  expect(persisted.rowCount).toBe(1);
  expect(persisted.rows[0]).toMatchObject({
    id: result.paymentId,
    status: 'succeeded',
    provider: 'simulator',
    amount_minor: '100',
  });
  expect(JSON.stringify(records).includes(apiKey)).toBe(false);
});
