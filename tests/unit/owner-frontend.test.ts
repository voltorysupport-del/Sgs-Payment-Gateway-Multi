import express from 'express';
import request from 'supertest';
import { expect, it } from 'vitest';
import { createOwnerFrontend } from '../../src/management/frontend.js';
import { testConfig } from '../helpers.js';

function app(enabled = true) {
  const app = express();
  app.set('trust proxy', ['127.0.0.1/32', '::1/128']);
  app.use(
    '/owner',
    createOwnerFrontend(
      testConfig({
        OWNER_ENABLED: String(enabled),
        OWNER_ORIGIN: 'https://owner.example.invalid',
        DASHBOARD_PUBLIC_ORIGIN: 'https://client.example.invalid',
      }),
    ),
  );
  app.use((_req, res) => {
    res.status(404).end();
  });
  return app;
}
it('hosts the separate built owner bundle only at its explicit secure origin with restrictive CSP and no caching', async () => {
  const response = await request(app())
    .get('/owner/')
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .expect(200);
  expect(response.headers['cache-control']).toBe('no-store');
  expect(response.headers['content-security-policy']).toContain("default-src 'none'");
  expect(response.headers['content-security-policy']).not.toContain('unsafe-inline');
  expect(response.text).toContain('/owner/assets/');
  expect(response.text).not.toContain('/dashboard/assets/');
});
it('denies owner assets on client hosts, insecure transport, sibling-origin requests and disabled configuration', async () => {
  for (const headers of [
    { Host: 'client.example.invalid', 'X-Forwarded-Proto': 'https' },
    { Host: 'owner.example.invalid', 'X-Forwarded-Proto': 'http' },
    {
      Host: 'owner.example.invalid',
      'X-Forwarded-Proto': 'https',
      Origin: 'https://client.example.invalid',
    },
    { Host: 'owner.example.invalid', 'X-Forwarded-Proto': 'https', 'Sec-Fetch-Site': 'same-site' },
  ])
    await request(app()).get('/owner/').set(headers).expect(404);
  await request(app(false))
    .get('/owner/')
    .set('Host', 'owner.example.invalid')
    .set('X-Forwarded-Proto', 'https')
    .expect(404);
});
it('does not serve source paths, dotfiles or arbitrary SPA fallbacks', async () => {
  for (const path of [
    '/owner/.env',
    '/owner/src/app.ts',
    '/owner/unknown',
    '/owner/%2e%2e/%2e%2e/package.json',
  ]) {
    const res = await request(app())
      .get(path)
      .set('Host', 'owner.example.invalid')
      .set('X-Forwarded-Proto', 'https');
    expect([400, 403, 404]).toContain(res.status);
    expect(res.text).not.toContain('DATABASE_URL');
  }
});
