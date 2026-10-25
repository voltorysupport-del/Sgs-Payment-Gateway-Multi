import { createHash } from 'node:crypto';
import { Router, type ErrorRequestHandler } from 'express';
import type { Pool } from 'pg';
import { z } from 'zod';
import type { Config } from '../config/index.js';
import { authenticateOperatorKey } from '../db/operator-keys.js';
import { paymentHistoryQuerySchema } from '../payments/history-contract.js';
import { sendError } from '../shared/http-errors.js';
import { dashboardSessionToken, touchDashboardSession } from './sessions.js';
import { GatewayReadError, readGateway } from './gateway-reader.js';

// Output projection deliberately strips unknown upstream fields.
const payment = z.object({
  id: z.uuid().transform((value) => value.toLowerCase()),
  amountMinor: z.number().int().positive().max(100_000_000),
  currency: z.string().regex(/^[A-Z]{3}$/),
  status: z.enum(['pending', 'succeeded', 'failed', 'cancelled']),
  provider: z.literal('simulator'),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
const history = z.object({
  payments: z.array(payment).max(100),
  pagination: z.object({
    limit: z.number().int().min(1).max(100),
    offset: z.number().int().min(0).max(10000),
    hasMore: z.boolean(),
  }),
});
const health = z.object({
  status: z.literal('ok'),
  service: z.literal('vaultx-pay'),
  realPaymentsEnabled: z.literal(false),
});
const emptyQuery = z.object({}).strict();

export function createDashboardBff(pool: Pool, config: Config): Router {
  const router = Router();
  router.use(async (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      sendError(res, 405, 'method_not_allowed', 'Only defined read operations are available.');
      return;
    }
    const raw = dashboardSessionToken(req);
    const identity = raw
      ? await touchDashboardSession(pool, createHash('sha256').update(raw).digest('hex'))
      : undefined;
    if (!identity) {
      sendError(res, 401, 'unauthorized', 'Authentication required.');
      return;
    }
    // Defence in depth even if a Config object bypassed environment validation.
    if (
      !config.dashboardEnabled ||
      !config.dashboardBffEnabled ||
      !config.dashboardOperatorId ||
      !config.dashboardReadOnlyApiKey
    ) {
      sendError(res, 503, 'unavailable', 'Dashboard reads unavailable.');
      return;
    }
    if (identity.operator_id !== config.dashboardOperatorId) {
      sendError(res, 403, 'forbidden', 'Dashboard access is not configured for this operator.');
      return;
    }
    const key = await authenticateOperatorKey(pool, config.dashboardReadOnlyApiKey);
    if (!key || key.id !== identity.operator_id || key.permission !== 'read_only') {
      sendError(res, 503, 'unavailable', 'Dashboard reads unavailable.');
      return;
    }
    next();
  });
  router.get('/payments', async (req, res) => {
    const parsed = paymentHistoryQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      sendError(res, 400, 'invalid_request', 'Invalid payment history filters or pagination.');
      return;
    }
    const value = history.safeParse(
      await readGateway(config.port, config.dashboardReadOnlyApiKey!, {
        kind: 'history',
        query: parsed.data,
      }),
    );
    if (
      !value.success ||
      value.data.payments.length > parsed.data.limit ||
      value.data.pagination.limit !== parsed.data.limit ||
      value.data.pagination.offset !== parsed.data.offset
    )
      throw new GatewayReadError(502);
    res.json(value.data);
  });
  router.get('/payments/:paymentId', async (req, res) => {
    const id = z
      .uuid()
      .transform((value) => value.toLowerCase())
      .safeParse(req.params.paymentId);
    if (!id.success || !emptyQuery.safeParse(req.query).success) {
      sendError(res, 400, 'invalid_request', 'Invalid payment detail request.');
      return;
    }
    const value = payment.safeParse(
      await readGateway(config.port, config.dashboardReadOnlyApiKey!, {
        kind: 'detail',
        id: id.data,
      }),
    );
    if (!value.success || value.data.id !== id.data) throw new GatewayReadError(502);
    res.json(value.data);
  });
  router.get('/status', async (req, res) => {
    if (!emptyQuery.safeParse(req.query).success) {
      sendError(res, 400, 'invalid_request', 'Invalid status request.');
      return;
    }
    if (
      !health.safeParse(
        await readGateway(config.port, config.dashboardReadOnlyApiKey!, { kind: 'health' }),
      ).success
    )
      throw new GatewayReadError(502);
    // Session and key validation already queried PostgreSQL; no infrastructure details.
    res.json({
      status: 'ok',
      gateway: 'ok',
      database: 'reachable',
      provider: 'simulator',
      realPaymentsEnabled: false,
    });
  });
  router.use((_req, res) => {
    sendError(res, 404, 'not_found', 'Resource not found.');
  });
  const errors: ErrorRequestHandler = (error: unknown, req, res, _next) => {
    const status = error instanceof GatewayReadError ? error.status : 503;
    req.log.warn({ status }, 'Dashboard read request failed');
    sendError(
      res,
      status,
      status === 404 ? 'not_found' : 'unavailable',
      status === 404 ? 'Payment not found.' : 'Dashboard reads unavailable.',
    );
  };
  router.use(errors);
  return router;
}
