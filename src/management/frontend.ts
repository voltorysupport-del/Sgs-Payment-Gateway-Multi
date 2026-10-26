import { fileURLToPath } from 'node:url';
import { Router, static as serveStatic } from 'express';
import helmet from 'helmet';
import type { Config } from '../config/index.js';

/** Separate owner-origin assets; never share the client authentication controller. */
export function createOwnerFrontend(config: Config): Router {
  const router = Router();
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    const origin = config.ownerOrigin ? new URL(config.ownerOrigin) : undefined;
    if (
      !config.ownerEnabled ||
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
    serveStatic(fileURLToPath(new URL('../../dist/owner-ui/', import.meta.url)), {
      index: 'owner.html',
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
