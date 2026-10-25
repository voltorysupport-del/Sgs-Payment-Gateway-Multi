import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { expect, it } from 'vitest';
import type { Pool } from 'pg';
import { createApp } from '../../src/app.js';
import { captureLogger, testConfig } from '../helpers.js';
it('serves only the gated public shell/assets with restrictive CSP and no-store, without API fallbacks', async () => {
  const pool = {
    query: () => {
      throw new Error('Static views must not query PostgreSQL');
    },
  } as unknown as Pool;
  const logger = captureLogger().logger;
  const disabled = createApp({ pool, logger, config: testConfig() });
  await request(disabled).get('/dashboard/').expect(404);
  const authOnly = createApp({
    pool,
    logger,
    config: testConfig({
      DASHBOARD_ENABLED: 'true',
      DASHBOARD_PUBLIC_ORIGIN: 'https://dashboard.example.invalid',
    }),
  });
  await request(authOnly).get('/dashboard/').expect(404);
  const app = createApp({
    pool,
    logger,
    config: testConfig({
      DASHBOARD_ENABLED: 'true',
      DASHBOARD_BFF_ENABLED: 'true',
      DASHBOARD_PUBLIC_ORIGIN: 'https://dashboard.example.invalid',
      DASHBOARD_OPERATOR_ID: randomUUID(),
      DASHBOARD_READ_ONLY_API_KEY: 'vxp_' + 'a'.repeat(64),
    }),
  });
  const html = await request(app).get('/dashboard/').expect(200);
  expect(html.headers['cache-control']).toBe('no-store');
  expect(html.headers['content-security-policy']).toContain("script-src 'self'");
  expect(html.headers['content-security-policy']).not.toMatch(/unsafe-inline|unsafe-eval/);
  expect(html.headers['content-security-policy']).toContain("frame-ancestors 'none'");
  expect(html.headers['referrer-policy']).toBe('no-referrer');
  expect(html.text).not.toContain('vxp_');
  const script = /src="(\/dashboard\/assets\/[^"?]+\.js)"/.exec(html.text)?.[1];
  expect(script).toBeDefined();
  const bundle = await request(app).get(script!).expect(200);
  expect(bundle.headers['cache-control']).toBe('no-store');
  expect(bundle.text).not.toMatch(/vxp_[a-f0-9]{64}|postgres(?:ql)?:\/\//);
  expect(bundle.text).not.toMatch(/localStorage|sessionStorage/);
  expect(bundle.text).not.toMatch(/DATABASE_URL|DASHBOARD_READ_ONLY_API_KEY|Bearer /);
  expect(bundle.text).not.toContain('jsxDEV');
  for (const path of [
    '/dashboard/.env',
    '/dashboard/not-a-route',
    '/dashboard-api/not-a-route',
    '/dashboard-api/payments',
    '/not-a-route',
  ])
    await request(app)
      .get(path)
      .expect(path.startsWith('/dashboard-api') ? 401 : 404);
  await request(app).get('/health').expect(200);
});
