import { isIP } from 'node:net';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { json, Router, type Request, type ErrorRequestHandler } from 'express';
import type { Pool } from 'pg';
import { z } from 'zod';
import type { Config } from '../config/index.js';
import { sendError } from '../shared/http-errors.js';
import { dummyPasswordHash, verifyDashboardPassword } from './passwords.js';

const cookieName = '__Host-vaultx_session';
const cookieOptions = { secure: true, httpOnly: true, sameSite: 'lax' as const, path: '/' };
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const token = () => randomBytes(32).toString('hex');
function sessionToken(req: Request): string | undefined {
  const values = (req.headers.cookie ?? '')
    .split(';')
    .map((v) => v.trim())
    .filter((v) => v.startsWith(cookieName + '='));
  if (values.length !== 1) return undefined;
  const value = values[0]!.slice(cookieName.length + 1);
  return /^[a-f0-9]{64}$/.test(value) ? value : undefined;
}
interface Session {
  token_hash: string;
  csrf_hash: string;
  user_id: string | null;
  username: string | null;
  operator_id: string | null;
}
async function session(pool: Pool, req: Request): Promise<Session | undefined> {
  const value = sessionToken(req);
  if (!value) return undefined;
  const result = await pool.query<Session>(
    `SELECT s.token_hash, s.csrf_hash, s.user_id, u.username, m.operator_id
    FROM dashboard_sessions s
    LEFT JOIN dashboard_users u ON u.id = s.user_id
    LEFT JOIN dashboard_memberships m ON m.id = s.membership_id AND m.user_id = s.user_id
    LEFT JOIN operators o ON o.id = m.operator_id
    WHERE s.token_hash = $1 AND (
      (s.user_id IS NULL AND s.created_at > NOW() - INTERVAL '10 minutes') OR
      (u.status = 'active' AND o.status = 'active' AND s.auth_version = u.auth_version
       AND s.created_at > NOW() - INTERVAL '8 hours'
       AND s.last_seen_at > NOW() - INTERVAL '30 minutes'))`,
    [digest(value)],
  );
  return result.rows[0];
}
function csrf(req: Request, s: Session, origin: string): boolean {
  const supplied = req.header('x-csrf-token');
  return (
    req.header('origin') === origin &&
    typeof supplied === 'string' &&
    /^[a-f0-9]{64}$/.test(supplied) &&
    timingSafeEqual(Buffer.from(digest(supplied)), Buffer.from(s.csrf_hash))
  );
}
// Normalize IPv6 spellings (and mapped IPv4) before allocating IP buckets.
function clientAddress(req: Request): string {
  const address = req.ip ?? '';
  if (isIP(address) === 4) return address;
  if (isIP(address) === 6) {
    const canonical = new URL('http://[' + address + ']').hostname.slice(1, -1);
    const mapped = /^::ffff:([a-f0-9]+):([a-f0-9]+)$/.exec(canonical);
    if (mapped) {
      const upper = parseInt(mapped[1]!, 16),
        lower = parseInt(mapped[2]!, 16);
      return [upper >> 8, upper & 255, lower >> 8, lower & 255].join('.');
    }
    return canonical;
  }
  return 'unknown'; // Missing/invalid address shares one conservative bucket.
}
async function rate(pool: Pool, key: string, maximum: number): Promise<boolean> {
  const result = await pool.query<{ attempts: number }>(
    `INSERT INTO dashboard_login_limits(bucket_hash, attempts, expires_at)
    VALUES ($1, 1, NOW() + INTERVAL '15 minutes') ON CONFLICT (bucket_hash) DO UPDATE
    SET attempts = CASE WHEN dashboard_login_limits.expires_at <= NOW() THEN 1 ELSE LEAST(dashboard_login_limits.attempts + 1, 1000000) END,
        expires_at = CASE WHEN dashboard_login_limits.expires_at <= NOW() THEN NOW() + INTERVAL '15 minutes' ELSE dashboard_login_limits.expires_at END
    RETURNING attempts`,
    [digest(key)],
  );
  return result.rows[0]!.attempts <= maximum;
}
const credentials = z
  .object({
    username: z
      .string()
      .max(80)
      .transform((v) => v.toLowerCase())
      .pipe(z.string().regex(/^[a-z0-9][a-z0-9_.-]{2,79}$/)),
    password: z.string().min(15).max(128),
  })
  .strict();

export function createDashboardAuthRouter(pool: Pool, config: Config): Router {
  const router = Router();
  // Bound expensive verification concurrency without an unbounded password queue.
  let verifying = 0;
  router.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  router.use(json({ limit: '4kb' }));
  router.get('/csrf', async (req, res) => {
    // No cross-origin token vending, even if CORS is accidentally enabled later.
    if (
      (req.header('origin') && req.header('origin') !== config.dashboardPublicOrigin) ||
      req.header('sec-fetch-site') === 'cross-site'
    ) {
      sendError(res, 403, 'forbidden', 'Request refused.');
      return;
    }
    if (!(await rate(pool, 'csrf-ip:' + clientAddress(req), 60))) {
      res.setHeader('Retry-After', '900');
      sendError(res, 429, 'rate_limited', 'Try again later.');
      return;
    }
    const existing = await session(pool, req);
    const csrfToken = token();
    if (existing) {
      await pool.query('UPDATE dashboard_sessions SET csrf_hash = $2 WHERE token_hash = $1', [
        existing.token_hash,
        digest(csrfToken),
      ]);
    } else {
      const value = token();
      await pool.query('INSERT INTO dashboard_sessions(token_hash, csrf_hash) VALUES ($1, $2)', [
        digest(value),
        digest(csrfToken),
      ]);
      res.cookie(cookieName, value, { ...cookieOptions, maxAge: 10 * 60 * 1000 });
    }
    res.json({ csrfToken });
  });
  router.post('/login', async (req, res) => {
    const ipAllowed = await rate(pool, 'login-ip:' + clientAddress(req), 30);
    if (!ipAllowed) {
      res.setHeader('Retry-After', '900');
      sendError(res, 429, 'rate_limited', 'Try again later.');
      return;
    }
    const parsed = credentials.safeParse(req.body);
    const accountAllowed = parsed.success
      ? await rate(pool, 'login-user:' + parsed.data.username, 5)
      : true;
    if (!accountAllowed) {
      res.setHeader('Retry-After', '900');
      sendError(res, 429, 'rate_limited', 'Try again later.');
      return;
    }
    const pre = await session(pool, req);
    if (!pre || pre.user_id !== null || !csrf(req, pre, config.dashboardPublicOrigin!)) {
      sendError(res, 403, 'forbidden', 'Request refused.');
      return;
    }
    if (!parsed.success) {
      sendError(res, 401, 'unauthorized', 'Invalid credentials.');
      return;
    }
    // Admission must be checked after the asynchronous session lookup.
    if (verifying >= 2) {
      res.setHeader('Retry-After', '1');
      sendError(res, 429, 'rate_limited', 'Try again later.');
      return;
    }
    verifying++;
    try {
      const users = await pool.query<{ id: string; password_hash: string }>(
        'SELECT id, password_hash FROM dashboard_users WHERE username = $1',
        [parsed.data.username],
      );
      const user = users.rows[0];
      const valid = await verifyDashboardPassword(
        user?.password_hash ?? (await dummyPasswordHash()),
        parsed.data.password,
      );
      if (!valid || !user) {
        sendError(res, 401, 'unauthorized', 'Invalid credentials.');
        return;
      }
      const client = await pool.connect();
      const value = token(),
        csrfToken = token();
      try {
        await client.query('BEGIN');
        // Consume pre-auth token atomically: parallel submissions cannot both log in.
        const consumed = await client.query(
          `DELETE FROM dashboard_sessions WHERE token_hash = $1 AND csrf_hash = $2
          AND user_id IS NULL AND created_at > NOW() - INTERVAL '10 minutes' RETURNING token_hash`,
          [pre.token_hash, pre.csrf_hash],
        );
        const inserted = consumed.rowCount
          ? await client.query(
              `INSERT INTO dashboard_sessions(token_hash, csrf_hash, user_id, membership_id, auth_version)
          SELECT $1, $2, u.id, m.id, u.auth_version FROM dashboard_users u
          JOIN dashboard_memberships m ON m.user_id = u.id JOIN operators o ON o.id = m.operator_id
          WHERE u.id = $3 AND u.password_hash = $4 AND u.status = 'active' AND o.status = 'active'
          FOR SHARE OF u, m, o RETURNING token_hash`,
              [digest(value), digest(csrfToken), user.id, user.password_hash],
            )
          : undefined;
        if (!inserted?.rowCount) {
          await client.query('ROLLBACK');
          sendError(res, 401, 'unauthorized', 'Invalid credentials.');
          return;
        }
        await client.query('COMMIT');
      } catch {
        await client.query('ROLLBACK').catch(() => undefined);
        throw new Error('Dashboard persistence failure.');
      } finally {
        client.release();
      }
      res.cookie(cookieName, value, { ...cookieOptions, maxAge: 8 * 60 * 60 * 1000 });
      res.json({ authenticated: true, csrfToken });
    } finally {
      verifying--;
    }
  });
  router.get('/me', async (req, res) => {
    const s = await session(pool, req);
    if (!s?.user_id) {
      sendError(res, 401, 'unauthorized', 'Authentication required.');
      return;
    }
    await pool.query('UPDATE dashboard_sessions SET last_seen_at = NOW() WHERE token_hash = $1', [
      s.token_hash,
    ]);
    res.json({
      user: { id: s.user_id, username: s.username },
      operator: { id: s.operator_id },
      role: 'viewer',
    });
  });
  router.post('/logout', async (req, res) => {
    const s = await session(pool, req);
    if (!s || !csrf(req, s, config.dashboardPublicOrigin!)) {
      sendError(res, 403, 'forbidden', 'Request refused.');
      return;
    }
    await pool.query('DELETE FROM dashboard_sessions WHERE token_hash = $1', [s.token_hash]);
    res.clearCookie(cookieName, cookieOptions);
    res.status(204).end();
  });
  const errors: ErrorRequestHandler = (_err: unknown, req, res, _next) => {
    // Do not serialize database/Argon2 errors or supplied authentication material.
    const type = (_err as { type?: unknown } | null)?.type;
    if (type === 'entity.parse.failed') {
      sendError(res, 400, 'invalid_json', 'Invalid JSON.');
      return;
    }
    if (type === 'entity.too.large') {
      sendError(res, 413, 'payload_too_large', 'Request too large.');
      return;
    }
    req.log.error('Dashboard authentication operation failed');
    sendError(res, 503, 'unavailable', 'Authentication temporarily unavailable.');
  };
  router.use(errors);
  return router;
}
