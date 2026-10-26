/// <reference lib="dom" />
import { randomUUID, createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import {
  chromium,
  expect as browserExpect,
  type Browser,
  type BrowserContext,
} from '@playwright/test';
import axe from 'axe-core';
import { expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { runMigrations } from '../../src/db/migrate.js';
import { createOperatorWithApiKey } from '../../src/db/operator-keys.js';
import { hashDashboardPassword } from '../../src/dashboard/passwords.js';
import { captureLogger, testConfig } from '../helpers.js';
import { openTestDatabase } from '../test-database.js';

it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'real HTTPS browser login, isolation, pagination, detail, status, cookies, expiration and logout',
  async () => {
    const pool = await openTestDatabase();
    const directory = await mkdtemp(path.join(tmpdir(), 'vaultx-browser-'));
    const logs = captureLogger();
    let gateway: http.Server | undefined, secure: https.Server | undefined;
    let browser: Browser | undefined;
    let context: BrowserContext | undefined;
    const operators: string[] = [],
      users: string[] = [];
    const csrfTokens: string[] = [];
    const rateKeys: string[] = [];
    const fixtureIp = '198.51.100.211';
    try {
      browser = await chromium.launch({
        headless: true,
        executablePath: process.env.VAULTX_CHROMIUM_EXECUTABLE,
      });
      await runMigrations(pool);
      const first = await createOperatorWithApiKey(
        pool,
        'Synthetic browser operator',
        'browser_' + randomUUID(),
        'Synthetic read only',
        'read_only',
      );
      const other = await createOperatorWithApiKey(
        pool,
        'Other synthetic browser operator',
        'browser_' + randomUUID(),
        'Synthetic read only',
        'read_only',
      );
      operators.push(first.operatorId, other.operatorId);
      const user = randomUUID(),
        membership = randomUUID(),
        username = 'browser_' + randomUUID();
      users.push(user);
      rateKeys.push('csrf-ip:' + fixtureIp, 'login-ip:' + fixtureIp, 'login-user:' + username);
      const password = 'Synthetic browser fixture password only';
      await pool.query('INSERT INTO dashboard_users(id,username,password_hash) VALUES ($1,$2,$3)', [
        user,
        username,
        await hashDashboardPassword(password),
      ]);
      await pool.query(
        'INSERT INTO dashboard_memberships(id,user_id,operator_id) VALUES ($1,$2,$3)',
        [membership, user, first.operatorId],
      );
      const alternateUser = randomUUID(),
        alternateName = 'browser_' + randomUUID();
      users.push(alternateUser);
      rateKeys.push('login-user:' + alternateName);
      await pool.query(
        'INSERT INTO dashboard_users(id,username,password_hash) SELECT $1,$2,password_hash FROM dashboard_users WHERE id=$3',
        [alternateUser, alternateName, user],
      );
      await pool.query(
        'INSERT INTO dashboard_memberships(id,user_id,operator_id) VALUES ($1,$2,$3)',
        [randomUUID(), alternateUser, first.operatorId],
      );
      const ids = Array.from({ length: 11 }, () => randomUUID());
      for (const [i, id] of ids.entries())
        await pool.query(
          "INSERT INTO payments(id,operator_id,amount_minor,currency,status,idempotency_key,created_at) VALUES ($1,$2,100,'EUR',$3,$4,NOW()-($5::int * INTERVAL '1 minute'))",
          [id, first.operatorId, i === 10 ? 'failed' : 'succeeded', randomUUID(), i],
        );
      const foreign = randomUUID();
      await pool.query(
        "INSERT INTO payments(id,operator_id,amount_minor,currency,idempotency_key) VALUES ($1,$2,999,'EUR',$3)",
        [foreign, other.operatorId, randomUUID()],
      );
      gateway = http.createServer(createApp({ pool, logger: logs.logger, config: testConfig() }));
      await new Promise<void>((resolve) => gateway!.listen(0, '127.0.0.1', resolve));
      const gatewayPort = (gateway.address() as AddressInfo).port;
      // Ephemeral localhost test certificate only. No committed key/certificate or production trust override.
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
      secure = https.createServer({
        key: await readFile(path.join(directory, 'key.pem')),
        cert: await readFile(path.join(directory, 'cert.pem')),
      });
      await new Promise<void>((resolve) => secure!.listen(0, '127.0.0.1', resolve));
      const origin = `https://127.0.0.1:${(secure.address() as AddressInfo).port}`;
      const secureApp = createApp({
        pool,
        logger: logs.logger,
        config: testConfig({
          DASHBOARD_ENABLED: 'true',
          DASHBOARD_BFF_ENABLED: 'true',
          DASHBOARD_PUBLIC_ORIGIN: origin,
          DASHBOARD_TRUSTED_PROXIES: '127.0.0.1/32',
          DASHBOARD_OPERATOR_ID: first.operatorId,
          DASHBOARD_READ_ONLY_API_KEY: first.apiKey,
          PORT: String(gatewayPort),
        }),
      });
      // Hold a real committed response before headers/Set-Cookie reach Chromium.
      let gatePath = '';
      let entered = () => {};
      let releaseResponse = () => {};
      let releaseGate = Promise.resolve();
      const hold = (endpoint: string) => {
        gatePath = endpoint;
        const seen = new Promise<void>((resolve) => {
          entered = resolve;
        });
        releaseGate = new Promise<void>((resolve) => {
          releaseResponse = resolve;
        });
        return {
          seen,
          release: () => {
            gatePath = '';
            releaseResponse();
          },
        };
      };
      secure.on('request', (req, res) => {
        if (req.method === 'POST' && req.url === gatePath) {
          const original = res.end.bind(res);
          res.end = ((...args: Parameters<typeof res.end>) => {
            entered();
            void releaseGate
              .then(() => {
                res.end = original;
                original(...args);
              })
              .catch(() => res.destroy());
            return res;
          }) as typeof res.end;
        }
        secureApp(req, res);
      });
      // Self-signed certificate exception is scoped solely to this synthetic localhost browser context.
      context = await browser.newContext({
        ignoreHTTPSErrors: true,
        extraHTTPHeaders: { 'X-Forwarded-For': fixtureIp },
      });
      const page = await context.newPage();
      const browserErrors: string[] = [];
      page.on('pageerror', () => browserErrors.push('pageerror'));
      const login = async (heading = 'Overview') => {
        await page.getByLabel('Username', { exact: true }).fill(username);
        await page.getByLabel('Password', { exact: true }).fill(password);
        await page.getByRole('button', { name: 'Sign in securely →' }).click();
        await browserExpect(
          page.getByRole('heading', { name: heading, exact: true }),
        ).toBeVisible();
        await browserExpect(page.getByRole('table').locator('tbody tr')).toHaveCount(10);
      };
      await page.goto(origin + '/dashboard/');
      await browserExpect(
        page.getByRole('heading', { name: 'Welcome back', level: 1 }),
      ).toBeFocused();
      for (const width of [1280, 390]) {
        await page.setViewportSize({ width, height: 844 });
        await page.evaluate(axe.source);
        expect(
          await page.evaluate(async () =>
            (await (window as unknown as { axe: typeof axe }).axe.run(document)).violations.map(
              (v) => v.id,
            ),
          ),
        ).toEqual([]);
      }
      await page.setViewportSize({ width: 1280, height: 900 });
      await login();
      await browserExpect(
        page.getByRole('heading', { name: 'Overview', exact: true }),
      ).toBeFocused();
      const cookies = await context.cookies();
      const session = cookies.find((c) => c.name === '__Host-vaultx_session');
      expect(session).toMatchObject({
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
        path: '/',
      });
      expect(await page.evaluate(() => document.cookie)).not.toContain('__Host-vaultx_session');
      expect(
        await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })),
      ).toEqual({ local: 0, session: 0 });
      // Automation evaluates axe outside page script loading; production CSP stays enforced.
      await page.evaluate(axe.source);
      const accessibility = await page.evaluate(async () => {
        const w = window as unknown as { axe: typeof axe };
        return (await w.axe.run(document)).violations.map((v) => ({ id: v.id, impact: v.impact }));
      });
      expect(accessibility).toEqual([]);
      await mkdir('test-results/dashboard', { recursive: true });
      await page.screenshot({
        path: 'test-results/dashboard/overview-desktop.png',
        fullPage: true,
      });
      await page.getByRole('link', { name: 'Payments', exact: true }).click();
      await page.getByRole('button', { name: 'Next →' }).click();
      await browserExpect(page.getByRole('table').locator('tbody tr')).toHaveCount(1);
      await page.getByLabel('Status', { exact: true }).selectOption('failed');
      await page.getByRole('button', { name: 'Apply filters' }).click();
      await browserExpect(page.getByRole('table').locator('tbody tr')).toHaveCount(1);
      await page.getByRole('link', { name: /View details/ }).click();
      await browserExpect(page.getByText(ids[10]!, { exact: true })).toBeVisible();
      await page.goto(origin + '/dashboard/#/payments/' + foreign);
      await browserExpect(page.getByRole('alert')).toHaveText('Payment not found.');
      await page.getByRole('link', { name: 'System status', exact: true }).click();
      await browserExpect(
        page.getByRole('heading', { name: 'Gateway is responding' }),
      ).toBeVisible();
      await page.setViewportSize({ width: 390, height: 844 });
      await page.getByRole('link', { name: 'Overview', exact: true }).click();
      await browserExpect(page.getByRole('table').locator('tbody tr')).toHaveCount(10);
      await page.screenshot({ path: 'test-results/dashboard/overview-mobile.png', fullPage: true });
      const overflowing = await page.evaluate(() =>
        Array.from(document.querySelectorAll('body *'))
          .filter(
            (el) => !el.closest('.table-wrap') && el.getBoundingClientRect().right > innerWidth + 1,
          )
          .map((el) => ({
            tag: el.tagName,
            className: el.className,
            right: el.getBoundingClientRect().right,
          }))
          .slice(0, 12),
      );
      expect(overflowing).toEqual([]);
      const overflowMetrics = await page.evaluate(() => ({
        width: innerWidth,
        document: document.documentElement.scrollWidth,
        elements: Array.from(document.querySelectorAll('body *'))
          .filter((el) => !el.closest('.table-wrap') && el.scrollWidth > el.clientWidth + 1)
          .map((el) => ({
            tag: el.tagName,
            className: el.className,
            width: el.clientWidth,
            scroll: el.scrollWidth,
            overflow: getComputedStyle(el).overflow,
            whiteSpace: getComputedStyle(el).whiteSpace,
          }))
          .slice(0, 15),
      }));
      expect(overflowMetrics.document, JSON.stringify(overflowMetrics)).toBeLessThanOrEqual(
        overflowMetrics.width,
      );
      await pool.query(
        "UPDATE dashboard_sessions SET last_seen_at = NOW()-INTERVAL '31 minutes' WHERE user_id=$1",
        [user],
      );
      await page.getByRole('link', { name: 'Payments', exact: true }).click();
      await browserExpect(page.getByRole('heading', { name: 'Welcome back' })).toBeFocused();
      await browserExpect(page.getByRole('table')).toHaveCount(0);
      await login('Payments');
      await page.getByRole('button', { name: 'Sign out', exact: true }).click();
      await browserExpect(page.getByRole('heading', { name: 'Welcome back' })).toBeFocused();
      await browserExpect(page.getByRole('table')).toHaveCount(0);
      await page.reload();
      await browserExpect(page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
      for (const cookie of await context.cookies())
        if (cookie.name === '__Host-vaultx_session')
          csrfTokens.push(createHash('sha256').update(cookie.value).digest('hex'));
      await page.screenshot({ path: 'test-results/dashboard/login-mobile.png', fullPage: true });
      // A pending real login must keep ownership through hide/show, including a late Set-Cookie.
      let gate = hold('/dashboard-api/auth/login');
      await page.getByLabel('Username', { exact: true }).fill(username);
      await page.getByLabel('Password', { exact: true }).fill(password);
      await page.getByRole('button', { name: 'Sign in securely →' }).click();
      await gate.seen;
      const cycle = async () => {
        await page.evaluate(() => {
          Object.defineProperty(document, 'visibilityState', {
            configurable: true,
            value: 'hidden',
          });
          document.dispatchEvent(new Event('visibilitychange'));
        });
        await page.evaluate(() => {
          Object.defineProperty(document, 'visibilityState', {
            configurable: true,
            value: 'visible',
          });
          document.dispatchEvent(new Event('visibilitychange'));
          window.dispatchEvent(new Event('pageshow'));
        });
      };
      await cycle();
      await browserExpect(page.getByRole('button', { name: 'Sign in securely →' })).toHaveCount(0);
      await browserExpect(page.getByRole('table')).toHaveCount(0);
      gate.release();
      await browserExpect(
        page.getByRole('heading', { name: 'Payments', exact: true }),
      ).toBeFocused();
      await browserExpect(page.getByRole('table').locator('tbody tr')).toHaveCount(10);
      // Both with and without BroadcastChannel, committed logout cannot be undone by lifecycle checks.
      for (const withChannel of [true, false]) {
        if (!withChannel) {
          await page.addInitScript(() => {
            Object.defineProperty(window, 'BroadcastChannel', { value: undefined });
          });
          await page.reload();
          await browserExpect(page.getByRole('table').locator('tbody tr')).toHaveCount(10);
        }
        gate = hold('/dashboard-api/auth/logout');
        await page.getByRole('button', { name: 'Sign out', exact: true }).click();
        await gate.seen;
        await cycle();
        await browserExpect(page.getByRole('table')).toHaveCount(0);
        gate.release();
        await browserExpect(page.getByRole('heading', { name: 'Welcome back' })).toBeFocused();
        await cycle();
        await browserExpect(page.getByRole('heading', { name: 'Welcome back' })).toBeFocused();
        await browserExpect(page.getByRole('table')).toHaveCount(0);
        if (withChannel) await login('Payments');
      }
      // Separate tabs share real HttpOnly cookies. Notifications never contain identities or credentials.
      const second = await context.newPage();
      await second.goto(origin + '/dashboard/');
      await browserExpect(second.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
      const third = await context.newPage();
      await third.goto(origin + '/dashboard/');
      await browserExpect(third.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
      await second.getByLabel('Username', { exact: true }).fill(username);
      await second.getByLabel('Password', { exact: true }).fill(password);
      await second.getByRole('button', { name: 'Sign in securely →' }).click();
      await browserExpect(
        second.getByRole('heading', { name: 'Overview', exact: true }),
      ).toBeFocused();
      await browserExpect(
        third.getByRole('heading', { name: 'Overview', exact: true }),
      ).toBeFocused();
      await second.route('**/dashboard-api/auth/logout', (route) => route.abort('failed'));
      await second.getByRole('button', { name: 'Sign out', exact: true }).click();
      await browserExpect(
        second.getByRole('heading', { name: 'Session needs attention' }),
      ).toBeFocused();
      await second.evaluate(() => window.dispatchEvent(new Event('pageshow')));
      await browserExpect(second.getByRole('table')).toHaveCount(0);
      await browserExpect(
        third.getByRole('heading', { name: 'Session needs attention' }),
      ).toBeVisible();
      await second.getByRole('button', { name: 'Check session again' }).click();
      await third.getByRole('button', { name: 'Check session again' }).click();
      await browserExpect(
        second.getByRole('heading', { name: 'Overview', exact: true }),
      ).toBeFocused();
      await second.unroute('**/dashboard-api/auth/logout');
      // The original page intentionally has no channel: pageshow/visibility are its fallback.
      await cycle();
      await browserExpect(
        page.getByRole('heading', { name: 'Payments', exact: true }),
      ).toBeFocused();
      await second.getByRole('button', { name: 'Sign out', exact: true }).click();
      await browserExpect(second.getByRole('heading', { name: 'Welcome back' })).toBeFocused();
      await cycle();
      await browserExpect(page.getByRole('heading', { name: 'Welcome back' })).toBeFocused();
      await browserExpect(third.getByRole('heading', { name: 'Welcome back' })).toBeFocused();
      await second.getByLabel('Username', { exact: true }).fill(alternateName);
      await second.getByLabel('Password', { exact: true }).fill(password);
      await second.getByRole('button', { name: 'Sign in securely →' }).click();
      await browserExpect(third.locator('.account')).toContainText(alternateName);
      await cycle();
      await browserExpect(page.locator('.account')).toContainText(alternateName);
      await pool.query("UPDATE dashboard_users SET status='disabled' WHERE id=$1", [alternateUser]);
      await third.getByRole('link', { name: 'Payments', exact: true }).click();
      await browserExpect(third.getByRole('heading', { name: 'Welcome back' })).toBeFocused();
      await cycle();
      await browserExpect(page.getByRole('heading', { name: 'Welcome back' })).toBeFocused();
      await third.close();
      await second.close();
      expect(browserErrors).toEqual([]);
      expect(logs.output()).not.toContain(password);
      expect(logs.output()).not.toContain(first.apiKey);
      await context.close();
    } finally {
      // Retain only digests for fixture cleanup; never print cookie values.
      for (const cookie of (await context?.cookies().catch(() => [])) ?? [])
        if (cookie.name === '__Host-vaultx_session')
          csrfTokens.push(createHash('sha256').update(cookie.value).digest('hex'));
      await browser?.close();
      if (secure) await new Promise<void>((resolve) => secure!.close(() => resolve()));
      if (gateway) await new Promise<void>((resolve) => gateway!.close(() => resolve()));
      for (const user of users) await pool.query('DELETE FROM dashboard_users WHERE id=$1', [user]);
      for (const op of operators) {
        await pool.query('DELETE FROM payments WHERE operator_id=$1', [op]);
        await pool.query('DELETE FROM operator_api_keys WHERE operator_id=$1', [op]);
        await pool.query('DELETE FROM operators WHERE id=$1', [op]);
      }
      await pool.query('DELETE FROM dashboard_sessions WHERE token_hash=ANY($1::text[])', [
        csrfTokens,
      ]);
      await pool.query('DELETE FROM dashboard_login_limits WHERE bucket_hash=ANY($1::text[])', [
        rateKeys.map((value) => createHash('sha256').update(value).digest('hex')),
      ]);
      await pool.end();
      await rm(directory, { recursive: true, force: true });
    }
  },
  90000,
);
