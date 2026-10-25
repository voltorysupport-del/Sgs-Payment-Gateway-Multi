import { fileURLToPath } from 'node:url';
import { Router, static as serveStatic } from 'express';
import helmet from 'helmet';

// Only public static assets live here. Data always comes from session-authenticated APIs.
export function createDashboardFrontend(): Router {
  const router = Router();
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
  router.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  router.use(
    serveStatic(fileURLToPath(new URL('../../dist/dashboard-ui/', import.meta.url)), {
      index: 'index.html',
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
