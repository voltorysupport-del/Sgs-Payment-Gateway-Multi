/**
 * Builds the Express application. It does NOT start listening on a port;
 * server.ts does that. Keeping them separate lets tests use the app directly.
 *
 * Step 1 contains only the shared foundations: security headers, request IDs,
 * structured request logging, body size limits, a health check and a single
 * consistent error format. Payment endpoints arrive in later steps.
 */
import { randomUUID } from 'node:crypto';
import express, { type ErrorRequestHandler, type Express } from 'express';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import type { Config } from './config/index.js';
import { assertRealPaymentsDisabled } from './config/safety.js';
import { sendError } from './shared/http-errors.js';
import type { Logger } from './shared/logger.js';

/** Incoming X-Request-Id values are only reused if they look harmless. */
const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{8,64}$/;

export interface AppDependencies {
  config: Config;
  logger: Logger;
}

export function createApp({ config, logger }: AppDependencies): Express {
  // Defence in depth: check the payment safety locks again before building anything.
  assertRealPaymentsDisabled(config);

  const app = express();

  // Don't advertise which framework we use.
  app.disable('x-powered-by');

  // Standard security headers (no sniffing, no framing, strict transport, etc.).
  app.use(helmet());

  // Structured request logging with a request ID on every request and response.
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
      // Log only what we need. Headers (which may contain API keys) are never logged,
      // and query strings are stripped from URLs.
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

  // Accept JSON bodies only up to a small size, to limit abuse.
  app.use(express.json({ limit: '100kb' }));

  // Health check: is the service running? (A database check is added in Step 2.)
  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'vaultx-pay',
      realPaymentsEnabled: false,
    });
  });

  // Anything else is "not found", in the standard error format.
  app.use((_req, res) => {
    sendError(res, 404, 'not_found', 'The requested resource was not found.');
  });

  // Central error handler: log the details, send the caller a safe message only.
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
