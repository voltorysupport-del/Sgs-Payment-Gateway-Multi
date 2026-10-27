import { paymentHistoryQuerySchema } from './history-contract.js';
import { readRestriction, InvalidReadRestriction } from './internal-read.js';
import { ReadUnavailable } from '../db/read-client.js';
import { Router, type ErrorRequestHandler } from 'express';
import type { Pool } from 'pg';
import { z } from 'zod';
import { authenticateOperatorKey, type AuthenticatedOperator } from '../db/operator-keys.js';
import {
  createPayment,
  getPayment,
  listPayments,
  PaymentConflict,
  TerminalUnavailable,
  simulatePayment,
} from '../db/payments.js';
import { sendError } from '../shared/http-errors.js';

const paymentSchema = z
  .object({
    amountMinor: z.number().int().positive().max(100_000_000),
    currency: z.string().regex(/^[A-Z]{3}$/),
    terminalId: z
      .uuid()
      .transform((id) => id.toLowerCase())
      .optional(),
  })
  .strict();
const idempotencySchema = z
  .string()
  .min(8)
  .max(128)
  .regex(/^[A-Za-z0-9_-]+$/);
const paymentIdSchema = z.uuid();
const simulationSchema = z.object({ outcome: z.enum(['succeeded', 'failed']) }).strict();

export function createPaymentsRouter(pool: Pool): Router {
  const router = Router();
  router.use(async (req, res, next) => {
    const authorization = req.header('authorization');
    const apiKey = authorization?.startsWith('Bearer ') ? authorization.slice(7) : '';
    let restriction;
    try {
      restriction = readRestriction(req, apiKey);
    } catch {
      sendError(res, 403, 'forbidden', 'Internal read authorization refused.');
      return;
    }
    const operator = apiKey
      ? await authenticateOperatorKey(pool, apiKey, {
          restriction,
          bounded: req.method === 'GET' || req.method === 'HEAD',
        })
      : null;
    if (!operator) {
      sendError(res, 401, 'unauthorized', 'A valid operator API key is required.');
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD' && operator.permission !== 'read_write') {
      sendError(res, 403, 'forbidden', 'This credential permits read-only access.');
      return;
    }
    res.locals.operator = operator;
    next();
  });

  router.get('/', async (req, res) => {
    const query = paymentHistoryQuerySchema.safeParse(req.query);
    if (!query.success) {
      sendError(res, 400, 'invalid_request', 'Invalid payment history filters or pagination.');
      return;
    }
    const operator = res.locals.operator as AuthenticatedOperator;
    res.json(await listPayments(pool, operator.id, query.data));
  });

  router.post('/', async (req, res) => {
    const operator = res.locals.operator as AuthenticatedOperator;
    const key = idempotencySchema.safeParse(req.header('idempotency-key'));
    if (!key.success) {
      sendError(res, 400, 'invalid_idempotency_key', 'A valid Idempotency-Key header is required.');
      return;
    }
    const body = paymentSchema.safeParse(req.body);
    if (!body.success) {
      sendError(res, 400, 'invalid_request', 'The payment request is invalid.');
      return;
    }
    const result = await createPayment(
      pool,
      operator.id,
      key.data,
      body.data.amountMinor,
      body.data.currency,
      body.data.terminalId,
    );
    res.status(result.created ? 201 : 200).json(result.payment);
  });

  router.get('/:paymentId', async (req, res) => {
    const operator = res.locals.operator as AuthenticatedOperator;
    const id = paymentIdSchema.safeParse(req.params.paymentId);
    if (!id.success) {
      sendError(res, 400, 'invalid_payment_id', 'A valid payment UUID is required.');
      return;
    }
    const payment = await getPayment(pool, operator.id, id.data);
    if (!payment) {
      sendError(res, 404, 'not_found', 'The payment was not found.');
      return;
    }
    res.json(payment);
  });

  // This is the simulator provider's normal processing operation, available in
  // staging with NODE_ENV=production. It is not a debug/control override and
  // never uses SIMULATOR_CONTROLS_ENABLED or invokes an external provider.
  router.post('/:paymentId/simulate', async (req, res) => {
    const operator = res.locals.operator as AuthenticatedOperator;
    const id = paymentIdSchema.safeParse(req.params.paymentId);
    if (!id.success) {
      sendError(res, 400, 'invalid_payment_id', 'A valid payment UUID is required.');
      return;
    }
    const body = simulationSchema.safeParse(req.body);
    if (!body.success) {
      sendError(
        res,
        400,
        'invalid_request',
        'Outcome must be succeeded or failed, with no extra fields.',
      );
      return;
    }
    const payment = await simulatePayment(pool, operator.id, id.data, body.data.outcome);
    if (!payment) {
      sendError(res, 404, 'not_found', 'The payment was not found.');
      return;
    }
    res.json(payment);
  });

  const conflictHandler: ErrorRequestHandler = (error: unknown, _req, res, next) => {
    if (error instanceof ReadUnavailable || error instanceof InvalidReadRestriction) {
      sendError(res, 503, 'unavailable', 'Payment reads temporarily unavailable.');
      return;
    }
    if (error instanceof TerminalUnavailable) {
      sendError(res, 400, 'invalid_terminal', 'The requested terminal is unavailable.');
      return;
    }
    if (error instanceof PaymentConflict) {
      sendError(res, 409, error.code, error.message);
      return;
    }
    next(error);
  };
  router.use(conflictHandler);
  return router;
}
