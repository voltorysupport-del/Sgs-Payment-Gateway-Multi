import type { DestinationStream } from 'pino';
import { loadConfig, type Config } from '../src/config/index.js';
import { createLogger, type Logger } from '../src/shared/logger.js';

/** A minimal, valid set of settings for tests. No real secrets. */
export const VALID_ENV: Readonly<Record<string, string>> = Object.freeze({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://vaultx:test-only-password@localhost:5432/vaultx_pay_test',
});

export function testConfig(overrides: Record<string, string> = {}): Config {
  return loadConfig({ ...VALID_ENV, ...overrides });
}

/** A logger that writes into memory, so tests can inspect exactly what was logged. */
export function captureLogger(): { logger: Logger; output: () => string } {
  const lines: string[] = [];
  const destination: DestinationStream = {
    write: (line: string) => {
      lines.push(line);
    },
  };
  const logger = createLogger({ level: 'info', destination });
  return { logger, output: () => lines.join('') };
}
