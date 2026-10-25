import { randomUUID } from 'node:crypto';
import express, { type ErrorRequestHandler, type Express } from 'express';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import type { Pool } from 'pg';
import type { Config } from './config/index.js';
import { assertRealPaymentsDisabled } from './config/safety.js';
import { createDashboardBff } from './dashboard/bff.js';
import { createDashboardAuthRouter } from './dashboard/routes.js';
import { createPaymentsRouter } from './payments/routes.js';
import { sendError } from './shared/http-errors.js';
import type { Logger } from './shared/logger.js';

const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{8,64}$/;

export interface AppDependencies {
  config: Config;
  logger: Logger;
  pool: Pool;
}

export function createApp({ config, logger, pool }: AppDependencies): Express {
  assertRealPaymentsDisabled(config);

  const app = express();
  app.disable('x-powered-by');
  // Trust only independently verified proxy addresses; never trust hop counts or all proxies.
  if (config.dashboardEnabled) app.set('trust proxy', [...config.dashboardTrustedProxies]);
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

  if (config.dashboardEnabled)
    app.use('/dashboard-api/auth', createDashboardAuthRouter(pool, config));

  if (config.dashboardEnabled && config.dashboardBffEnabled)
    app.use('/dashboard-api', createDashboardBff(pool, config));

  app.use(express.json({ limit: '100kb' }));

  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'vaultx-pay',
      realPaymentsEnabled: false,
    });
  });

  app.use('/payments', createPaymentsRouter(pool));

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
