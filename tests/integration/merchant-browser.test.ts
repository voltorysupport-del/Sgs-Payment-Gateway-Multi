/// <reference lib="dom" />
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { chromium, expect as browserExpect, type Browser } from '@playwright/test';
import { expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { runMigrations } from '../../src/db/migrate.js';
import { captureLogger, testConfig } from '../helpers.js';
import { openTestDatabase } from '../test-database.js';
import {
  createMerchantBrowserFixture,
  cleanupMerchantBrowserFixture,
} from '../merchant-browser-fixture.js';
import { policyTransaction } from '../viewer-policy-fixtures.js';

it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'real HTTPS built merchant UI uses existing client session, scoped APIs and clears invalidated records',
  async () => {
    const pool = await openTestDatabase();
    const directory = await mkdtemp(path.join(tmpdir(), 'vaultx-merchant-browser-'));
    const logs = captureLogger();
    let browser: Browser | undefined, server: https.Server | undefined;
    let fixture: Awaited<ReturnType<typeof createMerchantBrowserFixture>> | undefined;
    try {
      await runMigrations(pool);
      fixture = await createMerchantBrowserFixture(pool);
      execFileSync(
        'openssl',
        [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-nodes',
          '-keyout',
          path.join(directory, 'key.pem'),
          '-out',
          path.join(directory, 'cert.pem'),
          '-days',
          '1',
          '-subj',
          '/CN=localhost',
          '-addext',
          'subjectAltName=DNS:localhost,IP:127.0.0.1',
        ],
        { stdio: 'ignore' },
      );
      server = https.createServer({
        key: await readFile(path.join(directory, 'key.pem')),
        cert: await readFile(path.join(directory, 'cert.pem')),
      });
      await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
      const origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
      server.on(
        'request',
        createApp({
          pool,
          logger: logs.logger,
          config: testConfig({
            DASHBOARD_ENABLED: 'true',
            MERCHANT_MANAGEMENT_ENABLED: 'true',
            DASHBOARD_PUBLIC_ORIGIN: origin,
            OWNER_ENABLED: 'true',
            OWNER_ORIGIN: 'https://owner.example.invalid',
          }),
        }),
      );
      browser = await chromium.launch({
        headless: true,
        executablePath: process.env.VAULTX_CHROMIUM_EXECUTABLE,
      });
      // Self-signed trust exception applies ONLY to the ephemeral localhost fixture.
      const context = await browser.newContext({ ignoreHTTPSErrors: true });
      await context.addCookies([
        {
          name: '__Host-vaultx_session',
          value: fixture.token,
          url: origin + '/',
          secure: true,
          httpOnly: true,
          sameSite: 'Lax',
        },
      ]);
      const external: string[] = [],
        errors: string[] = [];
      await context.route('**/*', (route) => {
        if (new URL(route.request().url()).origin !== origin) {
          external.push('external-request');
          return route.abort();
        }
        return route.continue();
      });
      const page = await context.newPage();
      page.on('pageerror', () => errors.push('pageerror'));
      const response = await page.goto(origin + '/merchant/');
      expect(response?.status()).toBe(200);
      expect(response?.headers()['cache-control']).toBe('no-store');
      expect(response?.headers()['content-security-policy']).toContain("connect-src 'self'");
      await browserExpect(
        page.getByRole('heading', { name: 'Authorized merchant workspace' }),
      ).toBeVisible();
      expect((await context.request.get(origin + '/owner-api/auth/me')).status()).toBe(403);
      const ownerOnly = await browser.newContext({ ignoreHTTPSErrors: true });
      await ownerOnly.addCookies([
        {
          name: '__Host-vaultx_owner_session',
          value: fixture.owner.token,
          url: origin + '/',
          secure: true,
          httpOnly: true,
          sameSite: 'Strict',
        },
      ]);
      expect((await ownerOnly.request.get(origin + '/dashboard-api/auth/me')).status()).toBe(401);
      expect((await ownerOnly.request.get(origin + '/merchant-api/me')).status()).toBe(401);
      await ownerOnly.close();
      await page.getByRole('button', { name: 'Team and permissions', exact: true }).click();
      await browserExpect(page.getByText(fixture.childUsername, { exact: true })).toBeVisible();
      await browserExpect(
        page.getByRole('button', { name: 'Record pending invitation' }),
      ).toBeVisible();
      await page.getByRole('button', { name: 'Terminals', exact: true }).click();
      await browserExpect(
        page.getByRole('heading', { name: 'Synthetic browser terminal' }),
      ).toBeVisible();
      await page.getByRole('button', { name: 'Audit activity', exact: true }).click();
      await browserExpect(
        page.getByRole('heading', { name: 'Merchant audit history' }),
      ).toBeVisible();
      await browserExpect(page.getByText('members.list', { exact: true })).toBeVisible();
      await page.getByRole('button', { name: 'Team and permissions', exact: true }).click();
      await browserExpect(page.getByText(fixture.childUsername, { exact: true })).toBeVisible();
      await policyTransaction(pool, fixture.operator, async (client) => {
        await client.query(
          "UPDATE public.membership_permission_grants SET revoked_at=statement_timestamp(),revocation_reason='withdrawn',revocation_policy_version=(SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=$1) WHERE membership_id=$2 AND permission_code='client.users.read' AND revoked_at IS NULL",
          [fixture!.operator, fixture!.member],
        );
      });
      await page.evaluate(() => window.dispatchEvent(new Event('pageshow')));
      await browserExpect(page.getByRole('form', { name: 'Merchant sign-in' })).toBeVisible();
      await browserExpect(page.getByText(fixture.childUsername, { exact: true })).toHaveCount(0);
      expect((await context.request.get(origin + '/merchant-api/members')).status()).toBe(401);
      expect(external).toEqual([]);
      expect(errors).toEqual([]);
      expect(logs.output()).not.toContain(fixture.token);
      expect(logs.output()).not.toContain(fixture.owner.token);
    } finally {
      await browser?.close();
      if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
      if (fixture) await cleanupMerchantBrowserFixture(pool, fixture);
      await pool.end();
      await rm(directory, { recursive: true, force: true });
    }
  },
  90000,
);
