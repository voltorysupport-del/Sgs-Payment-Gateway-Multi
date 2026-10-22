import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import type { Config } from '../../src/config/index.js';
import { UnsafeConfigurationError } from '../../src/config/safety.js';
import { captureLogger, testConfig } from '../helpers.js';

function buildApp() {
  const { logger, output } = captureLogger();
  const app = createApp({ config: testConfig(), logger });
  return { app, logs: output };
}

describe('GET /health', () => {
  it('returns 200 with a simple status and no sensitive information', async () => {
    const { app } = buildApp();
    const res = await request(app).get('/health');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      status: 'ok',
      service: 'vaultx-pay',
      realPaymentsEnabled: false,
    });
  });
});

describe('security headers', () => {
  it('sets standard security headers and hides the framework name', async () => {
    const { app } = buildApp();
    const res = await request(app).get('/health');

    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
    expect(res.headers['strict-transport-security']).toBeDefined();
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});

describe('request IDs', () => {
  it('adds a new request ID to every response', async () => {
    const { app } = buildApp();
    const res = await request(app).get('/health');
    expect(res.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('reuses a safe incoming request ID', async () => {
    const { app } = buildApp();
    const res = await request(app).get('/health').set('X-Request-Id', 'abc12345-from-client');
    expect(res.headers['x-request-id']).toBe('abc12345-from-client');
  });

  it('replaces an unsafe incoming request ID', async () => {
    const { app } = buildApp();
    const res = await request(app).get('/health').set('X-Request-Id', '<script>alert(1)</script>');
    expect(res.headers['x-request-id']).not.toContain('<script>');
  });
});

describe('error format', () => {
  it('returns a consistent JSON error for unknown routes', async () => {
    const { app } = buildApp();
    const res = await request(app).get('/v1/payments/pay_123');

    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('not_found');
    expect(typeof res.body.error.message).toBe('string');
    expect(res.body.error.requestId).toBe(res.headers['x-request-id']);
  });

  it('rejects invalid JSON with a 400, without leaking internals', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .post('/anything')
      .set('Content-Type', 'application/json')
      .send('{"not valid json');

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('invalid_json');
    expect(JSON.stringify(res.body)).not.toMatch(/stack|SyntaxError/);
  });

  it('rejects bodies larger than 100kb', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .post('/anything')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify({ data: 'x'.repeat(150_000) }));

    expect(res.status).toBe(413);
    expect(res.body.error.code).toBe('payload_too_large');
  });
});

describe('logging', () => {
  it('never writes the Authorization header or query strings to the logs', async () => {
    const { app, logs } = buildApp();
    await request(app)
      .get('/health?token=QUERY_SECRET_SHOULD_NOT_APPEAR')
      .set('Authorization', 'Bearer vxp_test_KEY_SHOULD_NOT_APPEAR');

    const text = logs();
    expect(text).toContain('/health');
    expect(text).not.toContain('KEY_SHOULD_NOT_APPEAR');
    expect(text).not.toContain('QUERY_SECRET_SHOULD_NOT_APPEAR');
  });
});

describe('payment safety at app start-up', () => {
  it('refuses to build the app if live mode is somehow enabled', () => {
    const { logger } = captureLogger();
    const unsafe = { ...testConfig(), liveModeEnabled: true } as unknown as Config;
    expect(() => createApp({ config: unsafe, logger })).toThrow(UnsafeConfigurationError);
  });

  it('has no payment endpoints in Step 1', async () => {
    const { app } = buildApp();
    const res = await request(app)
      .post('/v1/payments')
      .set('Content-Type', 'application/json')
      .send({ amount_minor: 5000, currency: 'EUR' });
    expect(res.status).toBe(404);
  });
});
