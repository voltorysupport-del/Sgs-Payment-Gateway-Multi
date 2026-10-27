/// <reference lib="dom" />
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { chromium, expect as browserExpect, type Page } from '@playwright/test';
import axe from 'axe-core';
import { expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { runMigrations } from '../../src/db/migrate.js';
import { generateOperatorApiKey } from '../../src/db/operator-keys.js';
import { createMerchantInvitation } from '../../src/management/merchant-domain.js';
import { issueSyntheticInvitationToken } from '../../src/enrollment/service.js';
import { captureLogger, testConfig } from '../helpers.js';
import { openTestDatabase } from '../test-database.js';
import { policyTransaction } from '../viewer-policy-fixtures.js';
import {
  createMerchantBrowserFixture,
  cleanupMerchantBrowserFixture,
} from '../merchant-browser-fixture.js';

async function localUi() {
  const pool = await openTestDatabase(),
    directory = await mkdtemp(path.join(tmpdir(), 'vaultx-passkey-ui-'));
  await runMigrations(pool);
  const fixture = await createMerchantBrowserFixture(pool),
    logs = captureLogger(),
    key = generateOperatorApiKey();
  await pool.query(
    "INSERT INTO operator_api_keys(id,operator_id,name,key_hash,permission) VALUES($1,$2,'Synthetic browser reader',$3,'read_only')",
    [randomUUID(), fixture.operator, key.keyHash],
  );
  const gateway = http.createServer(createApp({ pool, logger: logs.logger, config: testConfig() }));
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', resolve));
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
      'subjectAltName=DNS:localhost',
    ],
    { stdio: 'ignore' },
  );
  const server = https.createServer({
    key: await readFile(path.join(directory, 'key.pem')),
    cert: await readFile(path.join(directory, 'cert.pem')),
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `https://localhost:${(server.address() as AddressInfo).port}`;
  server.on(
    'request',
    createApp({
      pool,
      logger: logs.logger,
      config: testConfig({
        DASHBOARD_ENABLED: 'true',
        DASHBOARD_BFF_ENABLED: 'true',
        DASHBOARD_OPERATOR_ID: fixture.operator,
        DASHBOARD_READ_ONLY_API_KEY: key.apiKey,
        PORT: String((gateway.address() as AddressInfo).port),
        MERCHANT_MANAGEMENT_ENABLED: 'true',
        PHASE3_ENROLLMENT_ENABLED: 'true',
        DASHBOARD_PUBLIC_ORIGIN: origin,
      }),
    }),
  );
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.VAULTX_CHROMIUM_EXECUTABLE,
  });
  // This trust exception is solely for the ephemeral synthetic localhost certificate.
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.route('**/*', (route) =>
    new URL(route.request().url()).origin === origin ? route.continue() : route.abort(),
  );
  const page = await context.newPage(),
    cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  const username = 'ui_invited_' + randomUUID(),
    password = 'Synthetic browser passkey password!';
  const invitation = await policyTransaction(pool, fixture.operator, (c) =>
    createMerchantInvitation(c, {
      operatorId: fixture.operator,
      ownerId: fixture.owner.id,
      username,
      kind: 'merchant_admin',
      permissions: ['client.users.read', 'client.status.read', 'client.payments.read'],
      terminalIds: [],
    }),
  );
  const token = await issueSyntheticInvitationToken(pool, invitation.invitationId);
  const close = async () => {
    await browser.close();
    await Promise.all([
      new Promise<void>((r, j) => server.close((e) => (e ? j(e) : r()))),
      new Promise<void>((r, j) => gateway.close((e) => (e ? j(e) : r()))),
    ]);
    await pool.query('DELETE FROM payments WHERE operator_id=$1', [fixture.operator]);
    await pool.query('DELETE FROM operator_api_keys WHERE operator_id=$1', [fixture.operator]);
    await cleanupMerchantBrowserFixture(pool, fixture);
    await pool.query('DELETE FROM dashboard_sessions WHERE user_id IS NULL');
    await pool.query('DELETE FROM dashboard_login_limits');
    await pool.end();
    await rm(directory, { recursive: true, force: true });
  };
  return {
    pool,
    fixture,
    logs,
    key,
    origin,
    context,
    page,
    cdp,
    authenticatorId,
    username,
    password,
    token,
    close,
  };
}
async function fillInvitation(page: Page, token: string, password: string) {
  await page.getByRole('button', { name: 'Accept a test invitation' }).click();
  await page.getByLabel('Private invitation value').fill(token);
  await page.getByLabel('Create password', { exact: true }).fill(password);
  await page.getByLabel('Confirm password').fill(password);
  await page.getByRole('button', { name: 'Enroll passkey', exact: true }).click();
}
async function login(page: Page, username: string, password: string) {
  await page.getByLabel('Username', { exact: true }).fill(username);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in securely', exact: true }).click();
  await browserExpect(
    page.getByRole('heading', { name: 'Passkey verification required' }),
  ).toBeVisible();
}
async function accessible(page: Page) {
  await page.evaluate(axe.source);
  expect(
    await page.evaluate(async () =>
      (await (window as unknown as { axe: typeof axe }).axe.run(document)).violations.map((v) => ({
        id: v.id,
        impact: v.impact,
      })),
    ),
  ).toEqual([]);
}
it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'built UI enrolls and authenticates through real UV ceremonies, handles cancellation, preserves viewer/BFF scope and clears revoked sessions',
  async () => {
    const f = await localUi();
    try {
      const paths: string[] = [],
        urls: string[] = [];
      f.page.on('request', (req) => {
        paths.push(new URL(req.url()).pathname);
        urls.push(req.url());
      });
      const unsupported = await f.context.newPage();
      await unsupported.addInitScript(() =>
        Object.defineProperty(window, 'PublicKeyCredential', { value: undefined }),
      );
      await unsupported.goto(f.origin + '/merchant/');
      await unsupported.getByRole('button', { name: 'Accept a test invitation' }).click();
      await browserExpect(
        unsupported.getByRole('button', { name: 'Enroll passkey', exact: true }),
      ).toBeDisabled();
      await browserExpect(unsupported.getByRole('alert')).toContainText('does not support');
      await unsupported.close();
      // If event handling is unavailable, native submission must POST, never
      // put private form values into a GET URL. No CSRF header means refusal.
      const fallback = await f.context.newPage();
      await fallback.goto(f.origin + '/merchant/');
      await fallback.getByRole('button', { name: 'Accept a test invitation' }).click();
      await fallback.getByLabel('Private invitation value').fill('a'.repeat(64));
      await fallback.getByLabel('Create password', { exact: true }).fill(f.password);
      await fallback.getByLabel('Confirm password').fill(f.password);
      const native = fallback.waitForRequest(
        (req) => req.url().endsWith('/dashboard-api/auth/passkeys/enrollment/options'),
        { timeout: 5000 },
      );
      await fallback.evaluate(() => {
        const form = document.querySelector<HTMLFormElement>(
          'form[aria-label="Invitation acceptance"]',
        );
        if (!form) throw new Error('Synthetic invitation form missing.');
        HTMLFormElement.prototype.submit.call(form);
      });
      expect((await native).method()).toBe('POST');
      expect((await native).url()).not.toContain(f.password);
      await fallback.close();
      await f.page.bringToFront();
      await f.page.goto(f.origin + '/merchant/');
      await f.page.getByRole('button', { name: 'Accept a test invitation' }).click();
      await browserExpect(
        f.page.getByRole('heading', { name: 'Accept an invitation' }),
      ).toBeFocused();
      await accessible(f.page);
      await f.page.keyboard.press('Tab');
      await browserExpect(f.page.getByLabel('Private invitation value')).toBeFocused();
      await mkdir('test-results/dashboard', { recursive: true });
      await f.page.screenshot({
        path: 'test-results/dashboard/phase3-enrollment.png',
        fullPage: true,
      });
      await f.page.getByRole('button', { name: 'Back to sign in' }).click();
      // Unknown/expired/used tokens share one generic, non-enumerating error path.
      await fillInvitation(f.page, 'a'.repeat(64), f.password);
      await browserExpect(f.page.getByRole('alert')).toContainText('expired, used or invalid');
      await fillInvitation(f.page, f.token, f.password);
      await browserExpect(f.page.getByRole('status')).toContainText('Passkey enrollment completed');
      expect(paths.filter((p) => p.endsWith('/enrollment/verify'))).toHaveLength(1);
      await login(f.page, f.username, f.password);
      expect((await f.context.request.get(f.origin + '/merchant-api/me')).status()).toBe(401);
      expect(
        (
          (await (await f.context.request.get(f.origin + '/dashboard-api/auth/me')).json()) as {
            authentication: unknown;
          }
        ).authentication,
      ).toEqual({
        passkeyRequired: true,
        passkeyVerified: false,
        passkeyFresh: false,
        passkeysEnabled: true,
      });
      await accessible(f.page);
      await f.page.screenshot({
        path: 'test-results/dashboard/phase3-passkey.png',
        fullPage: true,
      });
      await f.cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
        authenticatorId: f.authenticatorId,
        enabled: false,
      });
      await f.page.getByRole('button', { name: 'Verify passkey', exact: true }).click();
      await f.page.getByRole('button', { name: 'Cancel browser prompt' }).click();
      await browserExpect(f.page.getByRole('alert')).toContainText('cancelled');
      await browserExpect(
        f.page.getByRole('button', { name: 'Verify passkey', exact: true }),
      ).toBeDisabled();
      expect(paths.filter((p) => p.endsWith('/authentication/verify'))).toHaveLength(0);
      await f.page.getByRole('button', { name: 'Sign out', exact: true }).click();
      await login(f.page, f.username, f.password);
      await f.cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
        authenticatorId: f.authenticatorId,
        enabled: true,
      });
      await f.page.getByRole('button', { name: 'Verify passkey', exact: true }).click();
      await browserExpect(
        f.page.getByRole('heading', { name: 'Authorized merchant workspace' }),
      ).toBeVisible();
      await accessible(f.page);
      await f.page.screenshot({
        path: 'test-results/dashboard/phase3-merchant.png',
        fullPage: true,
      });
      const second = await f.context.newPage();
      await second.goto(f.origin + '/merchant/');
      await browserExpect(
        second.getByRole('heading', { name: 'Authorized merchant workspace' }),
      ).toBeVisible();
      await second.getByRole('button', { name: 'Sign out', exact: true }).click();
      await f.page.bringToFront();
      await browserExpect(f.page.getByRole('form', { name: 'Merchant sign-in' })).toBeVisible();
      await browserExpect(f.page.getByText(f.username, { exact: true })).toHaveCount(0);
      await second.close();
      await login(f.page, f.username, f.password);
      await f.page.getByRole('button', { name: 'Verify passkey', exact: true }).click();
      await browserExpect(
        f.page.getByRole('heading', { name: 'Authorized merchant workspace' }),
      ).toBeVisible();
      await f.page.goto(f.origin + '/dashboard/');
      await browserExpect(
        f.page.getByRole('heading', { name: 'Overview', exact: true }),
      ).toBeVisible();
      await f.page.setViewportSize({ width: 390, height: 844 });
      await accessible(f.page);
      await f.page.screenshot({ path: 'test-results/dashboard/phase3-mobile.png', fullPage: true });
      expect(await f.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
        true,
      );
      const user = (
        await f.pool.query<{ id: string }>('SELECT id FROM dashboard_users WHERE username=$1', [
          f.username,
        ])
      ).rows[0]!.id;
      await policyTransaction(f.pool, f.fixture.operator, (c) =>
        c.query("UPDATE dashboard_users SET status='disabled' WHERE id=$1", [user]),
      );
      await f.page.evaluate(() => window.dispatchEvent(new Event('pageshow')));
      await browserExpect(f.page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
      expect(
        await f.page.evaluate(() => ({
          local: localStorage.length,
          session: sessionStorage.length,
        })),
      ).toEqual({ local: 0, session: 0 });
      expect(urls.some((url) => url.includes(f.token) || url.includes(f.password))).toBe(false);
      expect(await f.page.evaluate(async () => (await indexedDB.databases()).length)).toBe(0);
      expect(f.page.url()).not.toContain(f.token);
      expect(f.logs.output()).not.toContain(f.token);
      expect(f.logs.output()).not.toContain(f.password);
      expect(f.logs.output()).not.toContain(f.key.apiKey);
    } finally {
      await f.close();
    }
  },
  60000,
);
it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'lost enrollment COMMIT acknowledgement keeps the built UI blocked without duplicate verification or secret storage',
  async () => {
    const f = await localUi();
    try {
      let verifies = 0;
      await f.context.route('**/dashboard-api/auth/passkeys/enrollment/verify', async (route) => {
        verifies++;
        const committed = await route.fetch();
        expect(committed.status()).toBe(200);
        await route.abort('connectionfailed');
      });
      await f.page.goto(f.origin + '/merchant/');
      await fillInvitation(f.page, f.token, f.password);
      await browserExpect(f.page.getByRole('alert')).toContainText('Do not repeat the invitation');
      await f.page.getByRole('button', { name: 'Check session', exact: true }).click();
      await browserExpect(f.page.getByRole('alert')).toContainText('Do not repeat the invitation');
      expect(verifies).toBe(1);
      expect(
        (
          await f.pool.query<{ count: string }>(
            'SELECT count(*) FROM dashboard_users WHERE username=$1',
            [f.username],
          )
        ).rows[0]!.count,
      ).toBe('1');
      expect(await f.page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
      await browserExpect(
        f.page.getByRole('button', { name: 'Accept a test invitation' }),
      ).toHaveCount(0);
      expect(f.logs.output()).not.toContain(f.token);
      expect(f.logs.output()).not.toContain(f.password);
    } finally {
      await f.close();
    }
  },
  60000,
);
it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'another tab cannot re-enable a cancelled passkey ceremony with a broadcast alone; a fresh local password login and cross-tab logout still work',
  async () => {
    const f = await localUi();
    try {
      let logins = 0,
        options = 0,
        verifications = 0;
      f.context.on('request', (req) => {
        const path = new URL(req.url()).pathname;
        if (path === '/dashboard-api/auth/login') logins++;
        if (path.endsWith('/passkeys/authentication/options')) options++;
        if (path.endsWith('/passkeys/authentication/verify')) verifications++;
      });
      await f.page.goto(f.origin + '/merchant/');
      await fillInvitation(f.page, f.token, f.password);
      await browserExpect(f.page.getByRole('status')).toContainText('Passkey enrollment completed');
      await login(f.page, f.username, f.password);
      await f.cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
        authenticatorId: f.authenticatorId,
        enabled: false,
      });
      await f.page.getByRole('button', { name: 'Verify passkey', exact: true }).click();
      await f.page.getByRole('button', { name: 'Cancel browser prompt' }).click();
      await browserExpect(
        f.page.getByRole('button', { name: 'Verify passkey', exact: true }),
      ).toBeDisabled();
      const other = await f.context.newPage();
      await other.goto(f.origin + '/merchant/');
      await browserExpect(
        other.getByRole('heading', { name: 'Passkey verification required' }),
      ).toBeVisible();
      await f.page.bringToFront();
      await browserExpect(
        f.page.getByRole('button', { name: 'Verify passkey', exact: true }),
      ).toBeDisabled();
      const rechecked = f.page.waitForResponse(
        (r) =>
          new URL(r.url()).pathname === '/dashboard-api/auth/me' && r.request().method() === 'GET',
      );
      await other.evaluate(() => {
        const channel = new BroadcastChannel('vaultx-dashboard-session');
        channel.postMessage('auth-changed');
        channel.close();
      });
      await rechecked;
      await browserExpect(
        f.page.getByRole('button', { name: 'Verify passkey', exact: true }),
      ).toBeDisabled();
      expect(logins).toBe(1);
      expect(options).toBe(1);
      expect(verifications).toBe(0);
      expect(
        (
          (await (await f.context.request.get(f.origin + '/dashboard-api/auth/me')).json()) as {
            authentication: { passkeyVerified: boolean };
          }
        ).authentication.passkeyVerified,
      ).toBe(false);
      await f.page.getByRole('button', { name: 'Sign out', exact: true }).click();
      await login(f.page, f.username, f.password);
      await browserExpect(
        f.page.getByRole('button', { name: 'Verify passkey', exact: true }),
      ).toBeEnabled();
      await f.cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
        authenticatorId: f.authenticatorId,
        enabled: true,
      });
      await f.page.getByRole('button', { name: 'Verify passkey', exact: true }).click();
      await browserExpect(
        f.page.getByRole('heading', { name: 'Authorized merchant workspace' }),
      ).toBeVisible();
      await other.bringToFront();
      await browserExpect(
        other.getByRole('heading', { name: 'Authorized merchant workspace' }),
      ).toBeVisible();
      await other.getByRole('button', { name: 'Sign out', exact: true }).click();
      await f.page.bringToFront();
      await browserExpect(f.page.getByRole('form', { name: 'Merchant sign-in' })).toBeVisible();
      await browserExpect(f.page.getByText(f.username, { exact: true })).toHaveCount(0);
      expect(logins).toBe(2);
      expect(verifications).toBe(1);
    } finally {
      await f.close();
    }
  },
  60000,
);
function rendezvous() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'cancelling after authentication verification was submitted does not abort, duplicate or open protected UI before settlement',
  async () => {
    const f = await localUi(),
      entered = rendezvous(),
      release = rendezvous();
    try {
      await f.page.goto(f.origin + '/merchant/');
      await fillInvitation(f.page, f.token, f.password);
      await browserExpect(f.page.getByRole('status')).toContainText('Passkey enrollment completed');
      await login(f.page, f.username, f.password);
      let verifies = 0;
      await f.context.route(
        '**/dashboard-api/auth/passkeys/authentication/verify',
        async (route) => {
          verifies++;
          const response = await route.fetch();
          expect(response.status()).toBe(200);
          entered.resolve();
          await release.promise;
          await route.fulfill({ response });
        },
      );
      await f.page.getByRole('button', { name: 'Verify passkey', exact: true }).click();
      await entered.promise;
      await f.page.getByRole('button', { name: 'Cancel browser prompt' }).click();
      await browserExpect(
        f.page.getByRole('heading', { name: 'Verify your passkey' }),
      ).toBeVisible();
      await browserExpect(
        f.page.getByRole('heading', { name: 'Authorized merchant workspace' }),
      ).toHaveCount(0);
      expect(verifies).toBe(1);
      release.resolve();
      await browserExpect(
        f.page.getByRole('heading', { name: 'Authorized merchant workspace' }),
      ).toBeVisible();
      expect(verifies).toBe(1);
    } finally {
      release.resolve();
      await f.close();
    }
  },
  60000,
);
it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'an ambiguous authentication response keeps protected views closed until an explicit server-assurance check',
  async () => {
    const f = await localUi();
    try {
      await f.page.goto(f.origin + '/merchant/');
      await fillInvitation(f.page, f.token, f.password);
      await browserExpect(f.page.getByRole('status')).toContainText('Passkey enrollment completed');
      await login(f.page, f.username, f.password);
      let verifies = 0;
      await f.context.route(
        '**/dashboard-api/auth/passkeys/authentication/verify',
        async (route) => {
          verifies++;
          const response = await route.fetch();
          expect(response.status()).toBe(200);
          // Preserve actual Set-Cookie but lose the successful JSON acknowledgement.
          await route.fulfill({ response, body: 'Malformed synthetic acknowledgement' });
        },
      );
      await f.page.getByRole('button', { name: 'Verify passkey', exact: true }).click();
      await browserExpect(f.page.getByRole('alert')).toContainText('could not be confirmed');
      await browserExpect(
        f.page.getByRole('heading', { name: 'Authorized merchant workspace' }),
      ).toHaveCount(0);
      expect(verifies).toBe(1);
      await f.page.getByRole('button', { name: 'Check session', exact: true }).click();
      await browserExpect(
        f.page.getByRole('heading', { name: 'Authorized merchant workspace' }),
      ).toBeVisible();
      expect(verifies).toBe(1);
    } finally {
      await f.close();
    }
  },
  60000,
);
