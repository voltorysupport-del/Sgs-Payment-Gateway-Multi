/// <reference lib="dom" />
import { randomUUID } from 'node:crypto';
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
  createOwnerFixture,
  cleanupOwnerFixture,
  managementFixtureGuard,
} from '../management-fixtures.js';

it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'real HTTPS owner UI uses separate secure realm, versioned metadata changes, audit, and logout',
  async () => {
    const pool = await openTestDatabase();
    const directory = await mkdtemp(path.join(tmpdir(), 'vaultx-owner-browser-'));
    const logs = captureLogger();
    let browser: Browser | undefined, server: https.Server | undefined, ownerId: string | undefined;
    const operator = randomUUID(),
      code = 'owner_browser_' + randomUUID();
    try {
      await runMigrations(pool);
      const guard = await pool.connect();
      try {
        await managementFixtureGuard(guard);
      } finally {
        guard.release();
      }
      await pool.query('INSERT INTO public.operators(id,name,code) VALUES($1,$2,$3)', [
        operator,
        'Synthetic owner browser client',
        code,
      ]);
      const owner = await createOwnerFixture(pool);
      ownerId = owner.id;
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
            OWNER_ENABLED: 'true',
            DASHBOARD_ENABLED: 'true',
            OWNER_ORIGIN: origin,
            DASHBOARD_PUBLIC_ORIGIN: 'https://client.example.invalid',
          }),
        }),
      );
      browser = await chromium.launch({
        headless: true,
        executablePath: process.env.VAULTX_CHROMIUM_EXECUTABLE,
      });
      // Self-signed trust exception is confined to this ephemeral localhost fixture.
      const context = await browser.newContext({ ignoreHTTPSErrors: true });
      await context.addCookies([
        {
          name: '__Host-vaultx_owner_session',
          value: owner.token,
          url: origin + '/',
          secure: true,
          httpOnly: true,
          sameSite: 'Strict',
        },
      ]);
      const page = await context.newPage();
      const errors: string[] = [];
      page.on('pageerror', () => errors.push('pageerror'));
      await page.goto(origin + '/owner/');
      await browserExpect(
        page.getByRole('heading', { name: 'Owner overview', exact: true }),
      ).toBeVisible();
      const cookie = (await context.cookies()).find(
        (c) => c.name === '__Host-vaultx_owner_session',
      );
      expect(cookie).toMatchObject({ secure: true, httpOnly: true, sameSite: 'Strict', path: '/' });
      expect((await context.request.get(origin + '/dashboard-api/auth/me')).status()).toBe(401);
      await page.getByRole('link', { name: 'Operators', exact: true }).click();
      await page.getByRole('button', { name: 'Inspect ' + code, exact: true }).click();
      const name = page.getByLabel('Display name');
      await browserExpect(name).toHaveValue('Synthetic owner browser client');
      await name.fill('Updated owner browser client');
      const mutationResponse = page.waitForResponse(
        (response) =>
          response.request().method() === 'PATCH' &&
          response.url() === origin + '/owner-api/clients/' + operator,
      );
      await page.getByRole('button', { name: 'Save display name' }).click();
      expect((await mutationResponse).status()).toBe(200);
      await browserExpect(name).toHaveValue('Updated owner browser client');
      expect(
        (await pool.query('SELECT name FROM public.operators WHERE id=$1', [operator])).rows[0]
          ?.name,
      ).toBe('Updated owner browser client');
      await page.getByRole('link', { name: 'Audit activity', exact: true }).click();
      await browserExpect(page.getByRole('table')).toBeVisible();
      const audit = await pool.query(
        'SELECT action FROM public.management_audit WHERE actor_id=$1 AND operator_id=$2',
        [owner.id, operator],
      );
      expect(audit.rows.some((row) => String(row.action).includes('update'))).toBe(true);
      await page.getByRole('button', { name: 'Sign out owner', exact: true }).click();
      await browserExpect(
        page.getByRole('heading', { name: 'Owner signed out', exact: true }),
      ).toBeVisible();
      expect(
        (
          await pool.query('SELECT token_hash FROM public.owner_sessions WHERE owner_id=$1', [
            owner.id,
          ])
        ).rowCount,
      ).toBe(0);
      expect(errors).toEqual([]);
      expect(logs.output()).not.toContain(owner.token);
    } finally {
      await browser?.close();
      if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
      if (ownerId) await cleanupOwnerFixture(pool, ownerId);
      await pool.query('DELETE FROM public.operators WHERE id=$1', [operator]);
      await pool.end();
      await rm(directory, { recursive: true, force: true });
    }
  },
  90000,
);
