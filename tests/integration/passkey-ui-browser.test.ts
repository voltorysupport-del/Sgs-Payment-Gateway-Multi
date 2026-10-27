import { createPayment } from '../../src/db/payments.js';
import { createOperatorWithApiKey } from '../../src/db/operator-keys.js';
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

async function cancelAuthenticationPrompt(page: Page) {
  // The busy screen precedes identity preflight completion. Wait until the
  // AbortController-backed ceremony exists; never rely on click timing.
  const ready = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === '/dashboard-api/auth/passkeys/authentication/options' &&
      response.status() === 200,
  );
  await page.getByRole('button', { name: 'Verify passkey', exact: true }).click();
  await ready;
  await page.getByRole('button', { name: 'Cancel browser prompt' }).click();
}

async function localUi(
  options: { submerchant?: boolean; paymentsOnly?: boolean; terminalReads?: boolean } = {},
) {
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
  const uiConfig = testConfig({
    DASHBOARD_ENABLED: 'true',
    DASHBOARD_BFF_ENABLED: 'true',
    DASHBOARD_OPERATOR_ID: fixture.operator,
    DASHBOARD_READ_ONLY_API_KEY: key.apiKey,
    PORT: String((gateway.address() as AddressInfo).port),
    MERCHANT_MANAGEMENT_ENABLED: 'true',
    PHASE3_ENROLLMENT_ENABLED: 'true',
    DASHBOARD_PUBLIC_ORIGIN: origin,
    TERMINAL_SCOPED_READS_ENABLED: String(options.terminalReads ?? false),
  });
  if (options.submerchant) {
    gateway.removeAllListeners('request');
    gateway.on('request', createApp({ pool, logger: logs.logger, config: uiConfig }));
  }
  server.on(
    'request',
    createApp({
      pool,
      logger: logs.logger,
      config: uiConfig,
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
  const invitation = await policyTransaction(pool, fixture.operator, async (c) =>
    createMerchantInvitation(c, {
      operatorId: fixture.operator,
      ...(options.submerchant
        ? { sponsorMembershipId: fixture.member }
        : { ownerId: fixture.owner.id }),
      username,
      kind: options.submerchant ? 'submerchant' : 'merchant_admin',
      permissions: options.submerchant
        ? options.paymentsOnly
          ? ['client.payments.read']
          : ['client.payments.read', 'client.status.read']
        : ['client.users.read', 'client.status.read', 'client.payments.read'],
      terminalIds: options.submerchant
        ? [
            (
              await c.query('SELECT id FROM public.merchant_terminals WHERE operator_id=$1', [
                fixture.operator,
              ])
            ).rows[0].id as string,
          ]
        : [],
    }),
  );
  const token = await issueSyntheticInvitationToken(pool, invitation.invitationId);
  const visibleIds: string[] = [],
    hiddenIds: string[] = [];
  let assignedTerminal = '';
  let foreignOperator = '';
  if (options.submerchant) {
    assignedTerminal = (
      await pool.query('SELECT id FROM public.merchant_terminals WHERE operator_id=$1', [
        fixture.operator,
      ])
    ).rows[0].id as string;
    const extra = randomUUID();
    await pool.query(
      "INSERT INTO public.merchant_terminals(id,operator_id,code,name) VALUES($1,$2,'unassigned-demo','Synthetic unassigned terminal')",
      [extra, fixture.operator],
    );
    for (let index = 0; index < 11; index++) {
      const payment = await createPayment(
        pool,
        fixture.operator,
        randomUUID(),
        (index + 1) * 100,
        'EUR',
        assignedTerminal,
      );
      visibleIds.push(payment.payment.id);
      await pool.query(
        "UPDATE public.payments SET status=$2,created_at='2026-01-02T12:00:00Z' WHERE id=$1",
        [
          payment.payment.id,
          index % 3 === 0 ? 'failed' : index % 3 === 1 ? 'succeeded' : 'pending',
        ],
      );
    }
    hiddenIds.push(
      (await createPayment(pool, fixture.operator, randomUUID(), 7700, 'EUR', extra)).payment.id,
    );
    hiddenIds.push(
      (await createPayment(pool, fixture.operator, randomUUID(), 8800, 'EUR')).payment.id,
    );
    const foreign = await createOperatorWithApiKey(
      pool,
      'Synthetic foreign operator',
      'foreign_ui_' + randomUUID(),
    );
    foreignOperator = foreign.operatorId;
    hiddenIds.push(
      (await createPayment(pool, foreignOperator, randomUUID(), 9900, 'EUR')).payment.id,
    );
    visibleIds.sort().reverse();
  }
  const close = async () => {
    await browser.close();
    await Promise.all([
      new Promise<void>((r, j) => server.close((e) => (e ? j(e) : r()))),
      new Promise<void>((r, j) => gateway.close((e) => (e ? j(e) : r()))),
    ]);
    await pool.query('DELETE FROM payments WHERE operator_id=$1', [fixture.operator]);
    await pool.query('DELETE FROM operator_api_keys WHERE operator_id=$1', [fixture.operator]);
    await cleanupMerchantBrowserFixture(pool, fixture);
    if (foreignOperator) {
      await pool.query('DELETE FROM public.payments WHERE operator_id=$1', [foreignOperator]);
      await pool.query('DELETE FROM public.operator_api_keys WHERE operator_id=$1', [
        foreignOperator,
      ]);
      await pool.query('DELETE FROM public.operators WHERE id=$1', [foreignOperator]);
    }
    await pool.query('DELETE FROM dashboard_sessions WHERE user_id IS NULL');
    await pool.query('DELETE FROM dashboard_login_limits');
    await pool.end();
    await rm(directory, { recursive: true, force: true });
  };
  return {
    pool,
    visibleIds,
    hiddenIds,
    assignedTerminal,
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
  await page.getByRole('button', { name: /^Sign in securely(?: →)?$/ }).click();
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
      await cancelAuthenticationPrompt(f.page);
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
      await cancelAuthenticationPrompt(f.page);
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

async function openSubmerchant(f: Awaited<ReturnType<typeof localUi>>) {
  await f.page.goto(f.origin + '/dashboard/#/payments');
  await fillInvitation(f.page, f.token, f.password);
  await browserExpect(f.page.getByRole('status')).toContainText('Passkey enrollment completed');
  await login(f.page, f.username, f.password);
  await browserExpect(f.page.getByRole('table')).toHaveCount(0);
  await f.page.getByRole('button', { name: 'Verify passkey', exact: true }).click();
  await browserExpect(f.page.getByRole('heading', { name: 'Payments', exact: true })).toBeVisible();
}
it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'submerchant browser displays only BFF-authorized records, supports detail/back/pagination/mobile and has no accessibility violations',
  async () => {
    const f = await localUi({ submerchant: true, paymentsOnly: true, terminalReads: true });
    try {
      await openSubmerchant(f);
      await browserExpect(f.page.getByText('Showing 1–10')).toBeVisible();
      expect(await f.page.getByRole('row').count()).toBe(11);
      await browserExpect(f.page.getByText('Submerchant viewer')).toBeVisible();
      await browserExpect(f.page.getByRole('link', { name: 'System status' })).toHaveCount(0);
      for (const id of f.hiddenIds) expect(await f.page.textContent('body')).not.toContain(id);
      await accessible(f.page);
      await mkdir('test-results/phase4c', { recursive: true });
      await f.page.screenshot({ path: 'test-results/phase4c/desktop.png', fullPage: true });
      await f.page
        .getByRole('link', { name: `View details → for payment ${f.visibleIds[0]}` })
        .click();
      await browserExpect(f.page.getByRole('heading', { name: 'Payment details' })).toBeVisible();
      await browserExpect(f.page.getByText(f.visibleIds[0]!, { exact: true })).toBeVisible();
      await f.page.screenshot({ path: 'test-results/phase4c/detail.png', fullPage: true });
      await f.page.goBack();
      await browserExpect(f.page.getByText('Showing 1–10')).toBeVisible();
      await f.page.getByRole('button', { name: 'Next →' }).click();
      await browserExpect(f.page.getByText('Showing 11–11')).toBeVisible();
      await browserExpect(f.page.getByRole('button', { name: 'Next →' })).toBeDisabled();
      await f.page.getByRole('button', { name: '← Previous' }).click();
      await browserExpect(f.page.getByText('Showing 1–10')).toBeVisible();
      await f.page.setViewportSize({ width: 390, height: 844 });
      await accessible(f.page);
      expect(await f.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
        true,
      );
      await f.page.getByRole('region', { name: 'Simulated payment history' }).focus();
      await browserExpect(
        f.page.getByRole('region', { name: 'Simulated payment history' }),
      ).toBeFocused();
      await f.page.evaluate(() => scrollTo(0, 0));
      await f.page.screenshot({ path: 'test-results/phase4c/mobile.png', fullPage: true });
      for (const id of f.hiddenIds) {
        await f.page.goto(f.origin + '/dashboard/#/payments/' + id);
        await browserExpect(f.page.getByRole('alert')).toContainText('Payment not found');
        expect(await f.page.textContent('body')).not.toContain(id);
      }
      expect(
        await f.page.evaluate(() => ({
          local: Object.keys(localStorage),
          session: Object.keys(sessionStorage),
        })),
      ).toEqual({ local: [], session: [] });
      expect(f.logs.output()).not.toContain(f.key.apiKey);
    } finally {
      await f.close();
    }
  },
  60000,
);

it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'submerchant cancellation never opens records; fresh password/passkey login, cross-tab logout and browser restore clear payment state',
  async () => {
    const f = await localUi({ submerchant: true, terminalReads: true });
    try {
      await f.page.goto(f.origin + '/dashboard/#/payments');
      await fillInvitation(f.page, f.token, f.password);
      await browserExpect(f.page.getByRole('status')).toContainText('Passkey enrollment completed');
      await login(f.page, f.username, f.password);
      await f.cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
        authenticatorId: f.authenticatorId,
        enabled: false,
      });
      await cancelAuthenticationPrompt(f.page);
      await browserExpect(
        f.page.getByRole('button', { name: 'Verify passkey', exact: true }),
      ).toBeDisabled();
      await browserExpect(f.page.getByRole('table')).toHaveCount(0);
      await f.page.getByRole('button', { name: 'Sign out', exact: true }).click();
      await login(f.page, f.username, f.password);
      await f.cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
        authenticatorId: f.authenticatorId,
        enabled: true,
      });
      await f.page.getByRole('button', { name: 'Verify passkey', exact: true }).click();
      await browserExpect(f.page.getByRole('table')).toBeVisible();
      const other = await f.context.newPage();
      await other.goto(f.origin + '/dashboard/#/payments');
      await browserExpect(other.getByRole('table')).toBeVisible();
      await other.getByRole('button', { name: 'Sign out', exact: true }).click();
      await f.page.bringToFront();
      await browserExpect(f.page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
      await browserExpect(f.page.getByRole('table')).toHaveCount(0);
      await f.page.evaluate(() =>
        dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })),
      );
      await browserExpect(f.page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
      for (const id of f.visibleIds) expect(await f.page.textContent('body')).not.toContain(id);
    } finally {
      await f.close();
    }
  },
  60000,
);

it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'submerchant terminal revocation is detected by bounded refresh and removes records; gate-off view never requests payments',
  async () => {
    const f = await localUi({ submerchant: true, terminalReads: true });
    try {
      await f.page.clock.install();
      await openSubmerchant(f);
      await browserExpect(f.page.getByRole('table')).toBeVisible();
      await policyTransaction(f.pool, f.fixture.operator, (c) =>
        c.query("UPDATE public.merchant_terminals SET status='suspended' WHERE id=$1", [
          f.assignedTerminal,
        ]),
      );
      const denied = f.page.waitForResponse(
        (r) => new URL(r.url()).pathname === '/dashboard-api/payments' && r.status() === 401,
      );
      await f.page.clock.runFor(16000);
      await denied;
      await browserExpect(f.page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
      await browserExpect(f.page.getByRole('table')).toHaveCount(0);
      for (const id of f.visibleIds) expect(await f.page.textContent('body')).not.toContain(id);
    } finally {
      await f.close();
    }
    const disabled = await localUi({ submerchant: true, terminalReads: false });
    try {
      let reads = 0;
      disabled.page.on('request', (r) => {
        if (new URL(r.url()).pathname === '/dashboard-api/payments') reads++;
      });
      await disabled.page.goto(disabled.origin + '/dashboard/#/payments');
      await fillInvitation(disabled.page, disabled.token, disabled.password);
      await browserExpect(disabled.page.getByRole('status')).toContainText(
        'Passkey enrollment completed',
      );
      await login(disabled.page, disabled.username, disabled.password);
      await disabled.page.getByRole('button', { name: 'Verify passkey', exact: true }).click();
      await browserExpect(
        disabled.page.getByRole('heading', { name: 'Read access unavailable' }),
      ).toBeVisible();
      expect(reads).toBe(0);
      await accessible(disabled.page);
      await mkdir('test-results/phase4c', { recursive: true });
      await disabled.page.screenshot({ path: 'test-results/phase4c/denied.png', fullPage: true });
    } finally {
      await disabled.close();
    }
  },
  60000,
);

it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'browser back navigation cannot restore payments after membership disablement',
  async () => {
    const f = await localUi({ submerchant: true, paymentsOnly: true, terminalReads: true });
    try {
      await openSubmerchant(f);
      await browserExpect(f.page.getByRole('table')).toBeVisible();
      await f.page.goto(f.origin + '/health');
      await policyTransaction(f.pool, f.fixture.operator, (c) =>
        c.query(
          "UPDATE public.dashboard_memberships SET status='disabled' WHERE user_id=(SELECT id FROM public.dashboard_users WHERE username=$1)",
          [f.username],
        ),
      );
      await f.page.goBack();
      await browserExpect(f.page.getByRole('heading', { name: 'Welcome back' })).toBeVisible();
      await browserExpect(f.page.getByRole('table')).toHaveCount(0);
      for (const id of f.visibleIds) expect(await f.page.textContent('body')).not.toContain(id);
    } finally {
      await f.close();
    }
  },
  60000,
);
