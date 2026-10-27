import { createHash } from 'node:crypto';
import { Router, json, type ErrorRequestHandler, type Request, type Response } from 'express';
import type { Pool } from 'pg';
import { z } from 'zod';
import type { Config } from '../config/index.js';
import { dashboardSessionToken } from '../dashboard/sessions.js';
import { sendError } from '../shared/http-errors.js';
import { executeMerchantCommand, type MerchantCommand } from './merchant-session.js';

const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const empty = z.object({}).strict();
const id = z.uuid();
const permission = z.enum(['client.payments.read', 'client.status.read']);
const version = z.number().int().min(1).max(2147483647);
const page = z
  .object({
    limit: z.coerce.number().int().min(1).max(50).default(20),
    offset: z.coerce.number().int().min(0).max(10000).default(0),
  })
  .strict();
const invitation = z
  .object({
    username: z.string().regex(/^[a-z0-9][a-z0-9_.-]{2,79}$/),
    permissions: z
      .array(permission)
      .min(1)
      .max(2)
      .refine((v) => new Set(v).size === v.length),
    terminalIds: z
      .array(id)
      .max(50)
      .refine((v) => new Set(v).size === v.length),
  })
  .strict();
const statuses = {
  unauthorized: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  invalid_input: 400,
  unavailable: 503,
} as const;
/** Same client authentication realm, never a viewer-cookie -> owner elevation.
 * Tenant identity and current capability are derived under one database gate.
 */
export function createMerchantRouter(pool: Pool, config: Config): Router {
  const router = Router();
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    if (
      !config.dashboardEnabled ||
      !config.merchantManagementEnabled ||
      config.nodeEnv === 'production' ||
      !config.dashboardPublicOrigin
    ) {
      sendError(res, 404, 'not_found', 'Resource not found.');
      return;
    }
    const origin = new URL(config.dashboardPublicOrigin);
    if (
      !req.secure ||
      req.headers.host !== origin.host ||
      req.header('authorization') !== undefined ||
      (req.header('origin') !== undefined && req.header('origin') !== origin.origin) ||
      (req.header('sec-fetch-site') !== undefined &&
        !['same-origin', 'none'].includes(req.header('sec-fetch-site')!))
    ) {
      sendError(res, 403, 'forbidden', 'Merchant request refused.');
      return;
    }
    if (!['GET', 'POST'].includes(req.method)) {
      sendError(res, 405, 'method_not_allowed', 'Method not allowed.');
      return;
    }
    if (!dashboardSessionToken(req)) {
      sendError(res, 401, 'unauthorized', 'Authentication required.');
      return;
    }
    if (
      req.method !== 'GET' &&
      (req.header('origin') !== origin.origin ||
        !/^[a-f0-9]{64}$/.test(req.header('x-csrf-token') ?? '') ||
        !req.is('application/json'))
    ) {
      sendError(res, 403, 'forbidden', 'Merchant request refused.');
      return;
    }
    next();
  });
  router.use(json({ limit: '4kb', inflate: false }));
  const invalid = (res: Response) =>
    sendError(res, 400, 'invalid_input', 'Invalid merchant request.');
  const run = async (req: Request, res: Response, command: MerchantCommand, created = false) => {
    const rawCsrf = req.header('x-csrf-token');
    const result = await executeMerchantCommand(
      pool,
      digest(dashboardSessionToken(req)!),
      command,
      rawCsrf && /^[a-f0-9]{64}$/.test(rawCsrf) ? digest(rawCsrf) : undefined,
      typeof req.id === 'string' ? req.id : undefined,
    );
    if (!result.ok) {
      sendError(
        res,
        statuses[result.error],
        result.error,
        'Merchant request unavailable or not permitted.',
      );
      return;
    }
    res.status(created ? 201 : 200).json(result.value);
  };
  router.get('/me', async (req, res) => {
    if (!empty.safeParse(req.query).success) return invalid(res);
    await run(req, res, { action: 'identity' });
  });
  router.get('/members', async (req, res) => {
    const parsed = page.safeParse(req.query);
    if (!parsed.success) return invalid(res);
    await run(req, res, { action: 'members.list', ...parsed.data });
  });
  router.get('/terminals', async (req, res) => {
    const parsed = page.safeParse(req.query);
    if (!parsed.success) return invalid(res);
    await run(req, res, { action: 'terminals.list', ...parsed.data });
  });
  router.get('/audit', async (req, res) => {
    const parsed = page.safeParse(req.query);
    if (!parsed.success) return invalid(res);
    await run(req, res, { action: 'audit.list', ...parsed.data });
  });
  router.post('/invitations', async (req, res) => {
    const body = invitation.safeParse(req.body);
    if (!body.success || !empty.safeParse(req.query).success) return invalid(res);
    await run(req, res, { action: 'invitations.create', ...body.data }, true);
  });
  router.post('/members/:membershipId/disable', async (req, res) => {
    const member = id.safeParse(req.params.membershipId),
      body = z.object({ expectedVersion: version }).strict().safeParse(req.body);
    if (!member.success || !body.success || !empty.safeParse(req.query).success)
      return invalid(res);
    await run(req, res, { action: 'members.disable', membershipId: member.data, ...body.data });
  });
  router.post('/members/:membershipId/grants/:permission/withdraw', async (req, res) => {
    const member = id.safeParse(req.params.membershipId),
      code = permission.safeParse(req.params.permission),
      body = z.object({ expectedVersion: version }).strict().safeParse(req.body);
    if (!member.success || !code.success || !body.success || !empty.safeParse(req.query).success)
      return invalid(res);
    await run(req, res, {
      action: 'grants.withdraw',
      membershipId: member.data,
      permission: code.data,
      ...body.data,
    });
  });
  router.use((_req, res) => sendError(res, 404, 'not_found', 'Resource not found.'));
  const errors: ErrorRequestHandler = (_error, req, res, _next) => {
    const type = (_error as { type?: unknown } | null)?.type;
    const status =
      type === 'entity.too.large'
        ? 413
        : type === 'encoding.unsupported'
          ? 415
          : type === 'entity.parse.failed'
            ? 400
            : 503;
    if (status === 503) req.log?.error('Merchant operation unavailable');
    sendError(
      res,
      status,
      status === 503 ? 'unavailable' : 'invalid_input',
      'Merchant request unavailable or invalid.',
    );
  };
  router.use(errors);
  return router;
}
