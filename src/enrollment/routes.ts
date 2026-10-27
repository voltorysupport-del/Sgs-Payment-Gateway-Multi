import { json, Router, type Request } from 'express';
import type { Pool } from 'pg';
import { z } from 'zod';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import type { Config } from '../config/index.js';
import { DASHBOARD_SESSION_COOKIE } from '../dashboard/sessions.js';
import {
  beginEnrollment,
  finishEnrollment,
  beginAuthentication,
  finishAuthentication,
} from './service.js';
import { sendError } from '../shared/http-errors.js';

const enrollment = z
  .object({
    invitationToken: z.string().regex(/^[a-f0-9]{64}$/),
    password: z.string().min(15).max(128),
  })
  .strict();
// The verifier validates the binary/WebAuthn structure. This outer envelope
// bounds work and rejects URL/query/header authority; never accept RP/origin here.
const response = z
  .object({
    credential: z
      .object({
        id: z.string().min(1).max(1400),
        rawId: z.string().min(1).max(1400),
        type: z.literal('public-key'),
        authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
        response: z.record(z.string(), z.unknown()),
        clientExtensionResults: z.record(z.string(), z.unknown()),
      })
      .strict(),
  })
  .strict();
export function createPasskeyRouter(
  pool: Pool,
  config: Config,
  security: {
    authorize: (req: Request) => Promise<{ hash: string; authenticated: boolean } | undefined>;
    admit: (req: Request) => Promise<boolean>;
  },
) {
  const router = Router();
  let active = 0;
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      sendError(res, 405, 'method_not_allowed', 'Request refused.');
      return;
    }
    if (req.header('origin') !== config.dashboardPublicOrigin || Object.keys(req.query).length) {
      sendError(res, 403, 'forbidden', 'Request refused.');
      return;
    }
    next();
  });
  router.use(json({ limit: '16kb' }));
  router.post(
    [
      'enrollment/options',
      'enrollment/verify',
      'authentication/options',
      'authentication/verify',
    ].map((p) => '/' + p),
    async (req, res) => {
      if (!(await security.admit(req))) {
        sendError(res, 429, 'rate_limited', 'Try again later.');
        return;
      }
      const session = await security.authorize(req);
      if (!session) {
        sendError(res, 403, 'forbidden', 'Request refused.');
        return;
      }
      if (active >= 2) {
        sendError(res, 429, 'rate_limited', 'Try again later.');
        return;
      }
      active++;
      try {
        const origin = config.dashboardPublicOrigin!;
        // Express matches case-insensitively and permits a trailing slash.
        // Dispatch exactly the same route it matched, never a fallback ceremony.
        const path = req.path.toLowerCase().replace(/\/+$/, '');
        const registering = path.startsWith('/enrollment/');
        if (registering === session.authenticated) throw new Error('Request refused.');
        if (path === '/enrollment/options') {
          const input = enrollment.parse(req.body);
          res.json(
            await beginEnrollment(
              pool,
              session.hash,
              input.invitationToken,
              input.password,
              origin,
            ),
          );
        } else if (path === '/enrollment/verify') {
          const input = response.parse(req.body);
          await finishEnrollment(
            pool,
            session.hash,
            input.credential as unknown as RegistrationResponseJSON,
            origin,
          );
          res.clearCookie(DASHBOARD_SESSION_COOKIE, {
            secure: true,
            httpOnly: true,
            sameSite: 'lax',
            path: '/',
          });
          res.json({ enrolled: true, privilegedAccess: false });
        } else if (path === '/authentication/options') {
          z.object({}).strict().parse(req.body);
          res.json(await beginAuthentication(pool, session.hash, origin));
        } else {
          const input = response.parse(req.body);
          const result = await finishAuthentication(
            pool,
            session.hash,
            input.credential as unknown as AuthenticationResponseJSON,
            origin,
          );
          res.cookie(DASHBOARD_SESSION_COOKIE, result.token, {
            secure: true,
            httpOnly: true,
            sameSite: 'lax',
            path: '/',
          });
          res.json({ authenticated: true, csrfToken: result.csrf });
        }
      } catch {
        // No verifier, input, DB error, credential ID or tenant metadata is logged.
        sendError(res, 400, 'invalid_request', 'Unable to complete authentication.');
      } finally {
        active--;
      }
    },
  );
  router.use((_req, res) => {
    sendError(res, 404, 'not_found', 'Resource not found.');
  });
  return router;
}
