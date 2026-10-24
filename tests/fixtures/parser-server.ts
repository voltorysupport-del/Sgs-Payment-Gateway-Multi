import type { Pool } from 'pg';
import { createApp } from '../../src/app.js';
import { loadConfig } from '../../src/config/index.js';
import { createLogger } from '../../src/shared/logger.js';

// Exercise the real middleware, but never instantiate a database pool, load
// .env, issue credentials, or start the production entry point/migrations.
const pool = {
  query: () => {
    throw new Error('Database access is forbidden in parser regression tests.');
  },
} as unknown as Pool;
const app = createApp({
  config: loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: 'postgres://config-only.invalid/no_connection',
  }),
  logger: createLogger({ level: 'silent' }),
  pool,
});
const server = app.listen(0, '127.0.0.1', () => {
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Parser fixture failed to listen.');
  process.send?.({ port: address.port });
});
process.on('message', (message: unknown) => {
  if (message === 'stop')
    server.close(() => {
      process.exit(0);
    });
});
process.on('disconnect', () => {
  server.close(() => {
    process.exit(0);
  });
});
