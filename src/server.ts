/**
 * Entry point: loads settings, connects to PostgreSQL, applies migrations,
 * and starts the HTTP server.
 *
 * Real payment processing remains disabled.
 */
import { existsSync } from 'node:fs';
import { dummyPasswordHash } from './dashboard/passwords.js';
import { createApp } from './app.js';
import { ConfigError, loadConfig, type Config } from './config/index.js';
import { checkDatabase, createPool } from './db/pool.js';
import { runMigrations } from './db/migrate.js';
import { createLogger } from './shared/logger.js';

// Load a local .env file if one exists (local development only).
// Existing environment variables are not overwritten.
if (process.env.NODE_ENV !== 'test' && existsSync('.env')) {
  process.loadEnvFile('.env');
}

async function start(): Promise<void> {
  let config: Config;

  try {
    config = loadConfig(process.env);
  } catch (error) {
    if (error instanceof ConfigError) {
      // The logger isn't set up yet, so write directly to stderr.
      // eslint-disable-next-line no-console
      console.error(`VaultX Pay did not start.\n${error.message}`);
      process.exit(1);
    }
    throw error;
  }

  const logger = createLogger({
    level: config.logLevel,
    pretty: config.nodeEnv === 'development' && process.stdout.isTTY,
  });

  const pool = createPool(config);

  try {
    await checkDatabase(pool);
    await runMigrations(pool);
    if (config.dashboardEnabled) await dummyPasswordHash();
  } catch (error) {
    logger.error({ err: error }, 'Database initialization failed');
    await pool.end();
    process.exitCode = 1;
    return;
  }

  const app = createApp({ config, logger, pool });

  const server = app.listen(config.port, '0.0.0.0', () => {
    logger.info(
      {
        port: config.port,
        nodeEnv: config.nodeEnv,
        liveModeEnabled: config.liveModeEnabled,
        allowedProviders: config.allowedProviders,
        simulatorControlsEnabled: config.simulatorControlsEnabled,
      },
      'VaultX Pay started (real payment processing is DISABLED)',
    );
  });

  let shuttingDown = false;

  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;

    logger.info({ signal }, 'Shutting down');

    const forceExit = setTimeout(() => {
      logger.error('Shutdown timed out');
      process.exit(1);
    }, 10_000);
    forceExit.unref();

    server.close((error) => {
      if (error) {
        logger.error({ err: error }, 'HTTP server shutdown failed');
        process.exitCode = 1;
      }

      void pool
        .end()
        .then(() => {
          clearTimeout(forceExit);
          process.exit();
        })
        .catch((poolError: unknown) => {
          logger.error({ err: poolError }, 'Database pool shutdown failed');
          process.exit(1);
        });
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start().catch((error: unknown) => {
  // eslint-disable-next-line no-console
  console.error('VaultX Pay failed to start.', error);
  process.exitCode = 1;
});
