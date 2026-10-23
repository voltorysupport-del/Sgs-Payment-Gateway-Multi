import { randomUUID } from 'node:crypto';
import express, { type ErrorRequestHandler, type Express } from 'express';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import { z } from 'zod';
import type { Pool } from 'pg';
import type { Config } from './config/index.js';
import { assertRealPaymentsDisabled } from './config/safety.js';
import { authenticateOperatorKey } from './db/operator-keys.js';
import { sendError } from './shared/http-errors.js';
import type { Logger } from './shared/logger.js';

const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{8,64}$/;

export interface AppDependencies {
  config: Config;
  logger: Logger;
  pool: Pool;
}

const paymentSchema = z
  .object({
    amountMinor: z.number().int().positive().max(100_000_000),
    currency: z.string().regex(/^[A-Z]{3}$/),
  })
  .strict();

const idempotencySchema = z
  .string()
  .min(8)
  .max(128)
  .regex(/^[A-Za-z0-9_-]+$/);

export function createApp({ config, logger, pool }: AppDependencies): Express {
  assertRealPaymentsDisabled(config);

  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());

  app.use(
    pinoHttp({
      logger,
      genReqId: (req, res) => {
        const incoming = req.headers['x-request-id'];
        const id =
          typeof incoming === 'string' && SAFE_REQUEST_ID.test(incoming) ? incoming : randomUUID();
        res.setHeader('x-request-id', id);
        return id;
      },
      serializers: {
        req: (req: { id?: unknown; method?: string; url?: string }) => ({
          id: req.id,
          method: req.method,
          path: req.url?.split('?')[0],
        }),
        res: (res: { statusCode?: number }) => ({ statusCode: res.statusCode }),
      },
      customLogLevel: (_req, res, err) => {
        if (err !== undefined || res.statusCode >= 500) return 'error';
        if (res.statusCode >= 400) return 'warn';
        return 'info';
      },
    }),
  );

  app.use(express.json({ limit: '100kb' }));

  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'vaultx-pay',
      realPaymentsEnabled: false,
    });
  });

  app.post('/payments', async (req, res, next) => {
    try {
      const authorization = req.header('authorization');
      const apiKey = authorization?.startsWith('Bearer ')
        ? authorization.slice('Bearer '.length)
        : '';

      if (!apiKey) {
        sendError(res, 401, 'unauthorized', 'A valid operator API key is required.');
        return;
      }

      const operator = await authenticateOperatorKey(pool, apiKey);
      if (!operator) {
        sendError(res, 401, 'unauthorized', 'A valid operator API key is required.');
        return;
      }

      const idempotencyKey = req.header('idempotency-key');
      const parsedIdempotency = idempotencySchema.safeParse(idempotencyKey);
      if (!parsedIdempotency.success) {
        sendError(
          res,
          400,
          'invalid_idempotency_key',
          'A valid Idempotency-Key header is required.',
        );
        return;
      }

      const parsedBody = paymentSchema.safeParse(req.body);
      if (!parsedBody.success) {
        sendError(res, 400, 'invalid_request', 'The payment request is invalid.');
        return;
      }

      const { amountMinor, currency } = parsedBody.data;
      const existing = await pool.query(
        `SELECT id, amount_minor, currency, status, provider
         FROM payments
         WHERE operator_id = $1 AND idempotency_key = $2`,
        [operator.id, parsedIdempotency.data],
      );

      if (existing.rows.length > 0) {
        const payment = existing.rows[0] as {
          id: string;
          amount_minor: string;
          currency: string;
          status: string;
          provider: string;
        };

        if (Number(payment.amount_minor) !== amountMinor || payment.currency.trim() !== currency) {
          sendError(
            res,
            409,
            'idempotency_conflict',
            'This idempotency key was already used with a different request.',
          );
          return;
        }

        res.status(200).json({
          id: payment.id,
          amountMinor: Number(payment.amount_minor),
          currency: payment.currency.trim(),
          status: payment.status,
          provider: payment.provider,
        });
        return;
      }

      const paymentId = randomUUID();
      const inserted = await pool.query(
        `INSERT INTO payments
           (id, operator_id, provider, amount_minor, currency, status, idempotency_key)
         VALUES ($1, $2, 'simulator', $3, $4, 'pending', $5)
         ON CONFLICT (operator_id, idempotency_key) DO NOTHING
         RETURNING id, amount_minor, currency, status, provider`,
        [paymentId, operator.id, amountMinor, currency, parsedIdempotency.data],
      );

      let paymentRow = inserted.rows[0] as
        | {
            id: string;
            amount_minor: string;
            currency: string;
            status: string;
            provider: string;
          }
        | undefined;

      // A concurrent request may have inserted the same key after our initial lookup.
      // Read the winning row and apply the same idempotency rules instead of returning
      // a spurious conflict for an identical request.
      if (!paymentRow) {
        const concurrent = await pool.query(
          `SELECT id, amount_minor, currency, status, provider
           FROM payments
           WHERE operator_id = $1 AND idempotency_key = $2`,
          [operator.id, parsedIdempotency.data],
        );
        paymentRow = concurrent.rows[0] as typeof paymentRow;
      }

      if (!paymentRow) {
        sendError(res, 409, 'idempotency_conflict', 'The idempotency key could not be resolved.');
        return;
      }

      if (
        Number(paymentRow.amount_minor) !== amountMinor ||
        paymentRow.currency.trim() !== currency
      ) {
        sendError(
          res,
          409,
          'idempotency_conflict',
          'This idempotency key was already used with a different request.',
        );
        return;
      }

      const payment = paymentRow;
      const wasCreated = inserted.rows.length > 0;

      res.status(wasCreated ? 201 : 200).json({
        id: payment.id,
        amountMinor: Number(payment.amount_minor),
        currency: payment.currency.trim(),
        status: payment.status,
        provider: payment.provider,
      });
    } catch (error) {
      next(error);
    }
  });

  app.use((_req, res) => {
    sendError(res, 404, 'not_found', 'The requested resource was not found.');
  });

  const errorHandler: ErrorRequestHandler = (err: unknown, req, res, _next) => {
    const type = (err as { type?: unknown } | null)?.type;

    if (type === 'entity.parse.failed') {
      sendError(res, 400, 'invalid_json', 'The request body is not valid JSON.');
      return;
    }
    if (type === 'entity.too.large') {
      sendError(res, 413, 'payload_too_large', 'The request body is too large.');
      return;
    }

    req.log.error({ err }, 'Unhandled error');
    sendError(res, 500, 'internal_error', 'An unexpected error occurred.');
  };
  app.use(errorHandler);

  return app;
}
