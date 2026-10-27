import { createHash, randomBytes } from 'node:crypto';
import { Router, json, type Request, type RequestHandler, type ErrorRequestHandler } from 'express';
import type { Pool } from 'pg';
import { z } from 'zod';
import type { Config } from '../config/index.js';
import { sendError } from '../shared/http-errors.js';
import { MERCHANT_PERMISSIONS } from './merchant-domain.js';
import { executeManagement, type ManagementCommand } from './domain.js';

export const OWNER_SESSION_COOKIE = '__Host-vaultx_owner_session';
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const uuid = z.uuid();
const pageSchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(50).default(20),
    offset: z.coerce.number().int().min(0).max(10000).default(0),
  })
  .strict();
const empty = z.object({}).strict();
const expectedVersion = z.number().int().min(1).max(2147483647);
const updateSchema = z
  .object({
    expectedVersion,
    name: z.string().trim().min(1).max(120).optional(),
    status: z.enum(['active', 'suspended']).optional(),
  })
  .strict()
  .refine((value) => value.name !== undefined || value.status !== undefined);
const withdrawalSchema = z.object({ expectedVersion }).strict();
const permission = z.enum(['client.payments.read', 'client.status.read']);
function tokenHash(req: Request): string | undefined {
  const matches = (req.headers.cookie ?? '')
    .split(';')
    .map((value) => value.trim())
    .filter((value) => value.startsWith(OWNER_SESSION_COOKIE + '='));
  if (matches.length !== 1) return undefined;
  const raw = matches[0]!.slice(OWNER_SESSION_COOKIE.length + 1);
  return /^[a-f0-9]{64}$/.test(raw) ? hash(raw) : undefined;
}
function csrfHash(req: Request): string | undefined {
  const raw = req.header('x-csrf-token');
  return typeof raw === 'string' && /^[a-f0-9]{64}$/.test(raw) ? hash(raw) : undefined;
}
const statuses = {
  unauthorized: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  invalid_input: 400,
  unavailable: 503,
} as const;
const messages = {
  unauthorized: 'Owner authentication required.',
  forbidden: 'Owner action is not permitted.',
  not_found: 'Resource not found.',
  conflict: 'The resource changed. Refresh before trying again.',
  invalid_input: 'Invalid owner request.',
  unavailable: 'Owner operation temporarily unavailable.',
} as const;
/** Separate realm and ingress; no client-cookie/Bearer elevation or generic proxy. */
export function createManagementRouter(pool: Pool, config: Config): Router {
  const router = Router();
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    if (!config.ownerEnabled || config.nodeEnv === 'production' || !config.ownerOrigin) {
      sendError(res, 404, 'not_found', 'Resource not found.');
      return;
    }
    const owner = new URL(config.ownerOrigin);
    if (
      !req.secure ||
      req.headers.host !== owner.host ||
      (req.header('origin') !== undefined && req.header('origin') !== owner.origin) ||
      (req.header('sec-fetch-site') !== undefined &&
        !['same-origin', 'none'].includes(req.header('sec-fetch-site')!)) ||
      req.header('authorization') !== undefined
    ) {
      sendError(res, 403, 'forbidden', 'Owner request refused.');
      return;
    }
    if (!['GET', 'POST', 'PATCH'].includes(req.method)) {
      sendError(res, 405, 'method_not_allowed', 'Method not allowed.');
      return;
    }
    if (!tokenHash(req)) {
      sendError(res, 401, 'unauthorized', 'Owner authentication required.');
      return;
    }
    if (
      req.method !== 'GET' &&
      (req.header('origin') !== owner.origin || !csrfHash(req) || !req.is('application/json'))
    ) {
      sendError(res, 403, 'forbidden', 'Owner request refused.');
      return;
    }
    next();
  });
  router.use(json({ limit: '4kb', inflate: false }));
  const method =
    (expected: string): RequestHandler =>
    (req, res, next) => {
      if (req.method !== expected) {
        sendError(res, 405, 'method_not_allowed', 'Method not allowed.');
        return;
      }
      next();
    };
  const run = async (
    req: Request,
    res: Parameters<RequestHandler>[1],
    command: ManagementCommand,
  ) => {
    const result = await executeManagement(
      pool,
      tokenHash(req)!,
      command,
      typeof req.id === 'string' ? req.id : undefined,
    );
    if (!result.ok) {
      sendError(res, statuses[result.error], result.error, messages[result.error]);
      return false;
    }
    return { value: result.value };
  };
  const invalid = (res: Parameters<RequestHandler>[1]) =>
    sendError(res, 400, 'invalid_input', 'Invalid owner request.');
  router.all('/auth/me', method('GET'), async (req, res) => {
    if (!empty.safeParse(req.query).success) return invalid(res);
    const result = await run(req, res, { action: 'identity' });
    if (result) res.json(result.value);
  });
  router.all('/auth/csrf', method('GET'), async (req, res) => {
    if (!empty.safeParse(req.query).success) return invalid(res);
    const token = randomBytes(32).toString('hex');
    const result = await run(req, res, { action: 'csrf.rotate', newCsrfHash: hash(token) });
    if (result) res.json({ csrfToken: token });
  });
  router.all('/auth/logout', method('POST'), async (req, res) => {
    if (!empty.safeParse(req.query).success || !empty.safeParse(req.body).success)
      return invalid(res);
    const result = await run(req, res, { action: 'logout', csrfHash: csrfHash(req)! });
    if (result) {
      res.clearCookie(OWNER_SESSION_COOKIE, {
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        path: '/',
      });
      res.status(204).end();
    }
  });
  router.post('/clients', async (req, res) => {
    const body = z
      .object({
        code: z.string().regex(/^[a-z][a-z0-9_-]{2,63}$/),
        name: z
          .string()
          .trim()
          .min(1)
          .max(120)
          .refine(
            (v) =>
              !Array.from(v).some(
                (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
              ),
          ),
      })
      .strict()
      .safeParse(req.body);
    if (!body.success || !empty.safeParse(req.query).success) return invalid(res);
    const result = await run(req, res, {
      action: 'operators.create',
      ...body.data,
      csrfHash: csrfHash(req)!,
    });
    if (result) res.status(201).json(result.value);
  });
  router.post('/clients/:id/administrator-invitations', async (req, res) => {
    const id = uuid.safeParse(req.params.id);
    const body = z
      .object({
        username: z.string().regex(/^[a-z0-9][a-z0-9_.-]{2,79}$/),
        permissions: z
          .array(z.enum(MERCHANT_PERMISSIONS))
          .min(1)
          .max(MERCHANT_PERMISSIONS.length)
          .refine((v) => new Set(v).size === v.length),
        terminalIds: z
          .array(uuid)
          .max(50)
          .refine((v) => new Set(v).size === v.length),
      })
      .strict()
      .safeParse(req.body);
    if (!id.success || !body.success || !empty.safeParse(req.query).success) return invalid(res);
    const result = await run(req, res, {
      action: 'invitations.create_admin',
      targetId: id.data,
      ...body.data,
      csrfHash: csrfHash(req)!,
    });
    if (result) res.status(201).json(result.value);
  });
  router.all('/clients', method('GET'), async (req, res) => {
    const parsed = pageSchema.safeParse(req.query);
    if (!parsed.success) return invalid(res);
    const result = await run(req, res, { action: 'operators.list', ...parsed.data });
    if (result) res.json(result.value);
  });
  router.all('/clients/:id', async (req, res) => {
    if (!['GET', 'PATCH'].includes(req.method)) {
      sendError(res, 405, 'method_not_allowed', 'Method not allowed.');
      return;
    }
    const id = uuid.safeParse(req.params.id);
    if (!id.success || !empty.safeParse(req.query).success) return invalid(res);
    if (req.method === 'GET') {
      const result = await run(req, res, { action: 'operators.detail', targetId: id.data });
      if (result) res.json(result.value);
      return;
    }
    const parsed = updateSchema.safeParse(req.body);
    if (!parsed.success) return invalid(res);
    const { expectedVersion: version, ...patch } = parsed.data;
    const result = await run(req, res, {
      action: 'operators.update',
      targetId: id.data,
      expectedVersion: version,
      patch,
      csrfHash: csrfHash(req)!,
    });
    if (result) res.json(result.value);
  });
  router.all('/clients/:id/members', method('GET'), async (req, res) => {
    const id = uuid.safeParse(req.params.id),
      page = pageSchema.safeParse(req.query);
    if (!id.success || !page.success) return invalid(res);
    const result = await run(req, res, { action: 'members.list', targetId: id.data, ...page.data });
    if (result) res.json(result.value);
  });
  router.all('/clients/:id/members/:membershipId', method('GET'), async (req, res) => {
    const id = uuid.safeParse(req.params.id),
      member = uuid.safeParse(req.params.membershipId);
    if (!id.success || !member.success || !empty.safeParse(req.query).success) return invalid(res);
    const result = await run(req, res, {
      action: 'members.detail',
      targetId: id.data,
      membershipId: member.data,
    });
    if (result) res.json(result.value);
  });
  router.all('/clients/:id/entitlements/:permission/withdraw', method('POST'), async (req, res) => {
    const id = uuid.safeParse(req.params.id),
      code = permission.safeParse(req.params.permission),
      body = withdrawalSchema.safeParse(req.body);
    if (!id.success || !code.success || !body.success || !empty.safeParse(req.query).success)
      return invalid(res);
    const result = await run(req, res, {
      action: 'entitlements.withdraw',
      targetId: id.data,
      permission: code.data,
      expectedVersion: body.data.expectedVersion,
      csrfHash: csrfHash(req)!,
    });
    if (result) res.json(result.value);
  });
  router.all('/audit', method('GET'), async (req, res) => {
    const parsed = pageSchema.safeParse(req.query);
    if (!parsed.success) return invalid(res);
    const result = await run(req, res, { action: 'audit.list', ...parsed.data });
    if (result) res.json(result.value);
  });
  router.use((_req, res) => sendError(res, 404, 'not_found', 'Resource not found.'));
  const errors: ErrorRequestHandler = (error: unknown, req, res, _next) => {
    const type = (error as { type?: unknown } | null)?.type;
    if (type === 'entity.parse.failed') {
      sendError(res, 400, 'invalid_json', 'Invalid owner request.');
      return;
    }
    if (type === 'entity.too.large') {
      sendError(res, 413, 'payload_too_large', 'Invalid owner request.');
      return;
    }
    if (type === 'encoding.unsupported') {
      sendError(res, 415, 'unsupported_encoding', 'Invalid owner request.');
      return;
    }
    req.log?.error('Owner operation unavailable');
    sendError(res, 503, 'unavailable', 'Owner operation temporarily unavailable.');
  };
  router.use(errors);
  return router;
}
