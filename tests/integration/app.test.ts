import { randomUUID } from 'node:crypto';
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
  if (operatorId) {
    await pool.query('DELETE FROM payments WHERE operator_id = $1', [operatorId]);
    await pool.query('DELETE FROM operator_api_keys WHERE operator_id = $1', [operatorId]);
    await pool.query('DELETE FROM operators WHERE id = $1', [operatorId]);
  }
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
