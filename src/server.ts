/**
 * Entry point: loads settings, builds the app and starts the HTTP server.
 *
 * If configuration is missing or unsafe, it prints what is wrong (never the
 * secret values) and exits with an error instead of starting.
 */
import { existsSync } from 'node:fs';
import { createApp } from './app.js';
import { ConfigError, loadConfig, type Config } from './config/index.js';
import { createLogger } from './shared/logger.js';

// Load a local .env file if one exists (local development only).
// Existing environment variables are not overwritten.
if (process.env.NODE_ENV !== 'test' && existsSync('.env')) {
  process.loadEnvFile('.env');
}

function start(): void {
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

  const app = createApp({ config, logger });

  const server = app.listen(config.port, () => {
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

  // Finish in-flight requests before exiting when asked to stop.
  const shutdown = (signal: string) => {
    logger.info({ signal }, 'Shutting down');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start();
