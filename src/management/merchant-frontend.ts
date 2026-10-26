import { fileURLToPath } from 'node:url';
import { Router, static as serveStatic } from 'express';
import helmet from 'helmet';
import type { Config } from '../config/index.js';

/** Same client realm; runtime tenant authority never comes from static assets. */
export function createMerchantFrontend(config: Config): Router {
  const router = Router();
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    const origin = config.dashboardPublicOrigin ? new URL(config.dashboardPublicOrigin) : undefined;
    if (
      !config.dashboardEnabled ||
      !config.merchantManagementEnabled ||
      config.nodeEnv === 'production' ||
      !origin ||
      !req.secure ||
      req.headers.host !== origin.host ||
      (req.headers.origin && req.headers.origin !== origin.origin) ||
      (req.headers['sec-fetch-site'] !== undefined &&
        !['same-origin', 'none'].includes(String(req.headers['sec-fetch-site'])))
    ) {
      res.status(404).end();
      return;
    }
    next();
  });
  router.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'none'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          connectSrc: ["'self'"],
          imgSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          baseUri: ["'none'"],
          frameAncestors: ["'none'"],
          formAction: ["'self'"],
          upgradeInsecureRequests: [],
        },
      },
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );
  router.use(
    serveStatic(fileURLToPath(new URL('../../dist/merchant-ui/', import.meta.url)), {
      index: 'merchant.html',
      redirect: true,
      dotfiles: 'deny',
      etag: false,
      lastModified: false,
      setHeaders: (res) => {
        res.setHeader('Cache-Control', 'no-store');
      },
    }),
  );
  return router;
}
