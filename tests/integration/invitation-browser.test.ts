/// <reference lib="dom" />
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { chromium, type Browser } from '@playwright/test';
import { expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { runMigrations } from '../../src/db/migrate.js';
import { createMerchantInvitation } from '../../src/management/merchant-domain.js';
import { issueSyntheticInvitationToken } from '../../src/enrollment/service.js';
import { captureLogger, testConfig } from '../helpers.js';
import { openTestDatabase } from '../test-database.js';
import { policyTransaction } from '../viewer-policy-fixtures.js';
import {
  createMerchantBrowserFixture,
  cleanupMerchantBrowserFixture,
} from '../merchant-browser-fixture.js';

it.skipIf(process.env.VAULTX_BROWSER_TESTS !== 'true')(
  'real HTTPS browser enrolls a UV passkey, requires MFA after password login and rotates secure cookies',
  async () => {
    const pool = await openTestDatabase(),
      directory = await mkdtemp(path.join(tmpdir(), 'vaultx-passkey-browser-'));
    let browser: Browser | undefined,
      server: https.Server | undefined,
      fixture: Awaited<ReturnType<typeof createMerchantBrowserFixture>> | undefined;
    const logs = captureLogger();
    try {
      await runMigrations(pool);
      fixture = await createMerchantBrowserFixture(pool);
      const username = 'passkey_browser_' + randomUUID(),
        password = 'Synthetic browser enrollment password!';
      const invitation = await policyTransaction(pool, fixture.operator, (c) =>
        createMerchantInvitation(c, {
          operatorId: fixture!.operator,
          ownerId: fixture!.owner.id,
          username,
          kind: 'merchant_admin',
          permissions: ['client.users.read', 'client.status.read'],
          terminalIds: [],
        }),
      );
      const token = await issueSyntheticInvitationToken(pool, invitation.invitationId);
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
      server = https.createServer({
        key: await readFile(path.join(directory, 'key.pem')),
        cert: await readFile(path.join(directory, 'cert.pem')),
      });
      await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
      const origin = `https://localhost:${(server.address() as AddressInfo).port}`;
      server.on(
        'request',
        createApp({
          pool,
          logger: logs.logger,
          config: testConfig({
            DASHBOARD_ENABLED: 'true',
            MERCHANT_MANAGEMENT_ENABLED: 'true',
            PHASE3_ENROLLMENT_ENABLED: 'true',
            DASHBOARD_PUBLIC_ORIGIN: origin,
          }),
        }),
      );
      browser = await chromium.launch({
        headless: true,
        executablePath: process.env.VAULTX_CHROMIUM_EXECUTABLE,
      });
      // Trust exception for this synthetic ephemeral localhost certificate only.
      const context = await browser.newContext({ ignoreHTTPSErrors: true }),
        page = await context.newPage();
      await context.route('**/*', (route) =>
        new URL(route.request().url()).origin === origin ? route.continue() : route.abort(),
      );
      const cdp = await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable');
      await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'internal',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      });
      await page.goto(origin + '/health');
      const result = await page.evaluate(
        async ({ token, password, username }) => {
          const b64 = (v: ArrayBuffer) =>
            btoa(String.fromCharCode(...new Uint8Array(v)))
              .replaceAll('+', '-')
              .replaceAll('/', '_')
              .replaceAll('=', '');
          const bytes = (s: string) =>
            Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), (c) =>
              c.charCodeAt(0),
            );
          const post = async (route: string, body: unknown, csrf: string) =>
            fetch('/dashboard-api/auth/' + route, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf },
              body: JSON.stringify(body),
            });
          let csrf = (
            (await (await fetch('/dashboard-api/auth/csrf')).json()) as { csrfToken: string }
          ).csrfToken;
          const opts = (await (
            await post('passkeys/enrollment/options', { invitationToken: token, password }, csrf)
          ).json()) as Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user'> & {
            challenge: string;
            user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string };
          };
          const registered = (await navigator.credentials.create({
            publicKey: {
              ...opts,
              challenge: bytes(opts.challenge),
              user: { ...opts.user, id: bytes(opts.user.id) },
            },
          })) as PublicKeyCredential;
          const att = registered.response as AuthenticatorAttestationResponse;
          const enrolled = await post(
            'passkeys/enrollment/verify',
            {
              credential: {
                id: registered.id,
                rawId: b64(registered.rawId),
                type: 'public-key',
                clientExtensionResults: registered.getClientExtensionResults(),
                response: {
                  clientDataJSON: b64(att.clientDataJSON),
                  attestationObject: b64(att.attestationObject),
                },
              },
            },
            csrf,
          );
          csrf = ((await (await fetch('/dashboard-api/auth/csrf')).json()) as { csrfToken: string })
            .csrfToken;
          const login = (await (await post('login', { username, password }, csrf)).json()) as {
            csrfToken: string;
          };
          csrf = login.csrfToken;
          const passwordOnly = (await fetch('/merchant-api/me')).status;
          const auth = (await (
            await post('passkeys/authentication/options', {}, csrf)
          ).json()) as Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
            challenge: string;
            allowCredentials: { id: string; type: 'public-key' }[];
          };
          const assertion = (await navigator.credentials.get({
            publicKey: {
              ...auth,
              challenge: bytes(auth.challenge),
              allowCredentials: auth.allowCredentials.map((c) => ({ ...c, id: bytes(c.id) })),
            },
          })) as PublicKeyCredential;
          const ar = assertion.response as AuthenticatorAssertionResponse;
          const body = {
            credential: {
              id: assertion.id,
              rawId: b64(assertion.rawId),
              type: 'public-key',
              clientExtensionResults: assertion.getClientExtensionResults(),
              response: {
                clientDataJSON: b64(ar.clientDataJSON),
                authenticatorData: b64(ar.authenticatorData),
                signature: b64(ar.signature),
                userHandle: ar.userHandle ? b64(ar.userHandle) : undefined,
              },
            },
          };
          const verified = await post('passkeys/authentication/verify', body, csrf);
          const identity = await fetch('/merchant-api/me');
          const replay = await post('passkeys/authentication/verify', body, csrf);
          return {
            enrolled: enrolled.status,
            passwordOnly,
            verified: verified.status,
            identity: identity.status,
            replay: replay.status,
          };
        },
        { token, password, username },
      );
      expect(result).toEqual({
        enrolled: 200,
        passwordOnly: 401,
        verified: 200,
        identity: 200,
        replay: 403,
      });
      const cookies = await context.cookies();
      expect(cookies.find((c) => c.name === '__Host-vaultx_session')).toMatchObject({
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
        path: '/',
      });
      expect(logs.output()).not.toContain(token);
      expect(logs.output()).not.toContain(password);
    } finally {
      await browser?.close();
      if (server)
        await new Promise<void>((resolve, reject) =>
          server!.close((e) => (e ? reject(e) : resolve())),
        );
      if (fixture) await cleanupMerchantBrowserFixture(pool, fixture);
      await pool.query('DELETE FROM public.dashboard_sessions WHERE user_id IS NULL');
      await pool.query('DELETE FROM public.dashboard_login_limits');
      await pool.end();
      await rm(directory, { recursive: true, force: true });
    }
  },
  30000,
);
