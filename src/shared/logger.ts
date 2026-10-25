/**
 * Structured JSON logging with automatic redaction.
 *
 * Every log line is a JSON object, which makes logs easy to search later.
 * Anything that looks like a secret (API keys, passwords, tokens, the database
 * URL, Authorization/Cookie headers) is replaced with "[REDACTED]" before the
 * line is written, so secrets cannot leak into log files by accident.
 */
import { pino, type DestinationStream, type Logger } from 'pino';
import type { LogLevel } from '../config/index.js';

export const REDACTED = '[REDACTED]';

/** Field paths whose values are always hidden in logs. */
export const REDACT_PATHS: readonly string[] = [
  // HTTP headers that carry credentials
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-api-key"]',
  'req.headers["x-vaultx-read-proof"]',
  'res.headers["set-cookie"]',
  // Common secret field names, at the top level and one level deep
  'password',
  'secret',
  'token',
  'apiKey',
  'api_key',
  'authorization',
  'databaseUrl',
  'DATABASE_URL',
  'DASHBOARD_READ_ONLY_API_KEY',
  'dashboardReadOnlyApiKey',
  '*.password',
  '*.secret',
  '*.token',
  '*.apiKey',
  '*.api_key',
  '*.authorization',
  '*.databaseUrl',
  '*.DATABASE_URL',
  '*.DASHBOARD_READ_ONLY_API_KEY',
  '*.dashboardReadOnlyApiKey',
];

export interface LoggerOptions {
  level: LogLevel;
  /** Human-friendly coloured output for local development only. */
  pretty?: boolean;
  /** Where to write logs. Tests pass a stream to capture output. */
  destination?: DestinationStream;
}

export function createLogger(options: LoggerOptions): Logger {
  const baseOptions = {
    level: options.level,
    base: { service: 'vaultx-pay' },
    redact: { paths: [...REDACT_PATHS], censor: REDACTED },
    timestamp: pino.stdTimeFunctions.isoTime,
  };

  if (options.destination) {
    return pino(baseOptions, options.destination);
  }

  if (options.pretty) {
    // pino-pretty is a development-only dependency; never used in production.
    return pino({ ...baseOptions, transport: { target: 'pino-pretty' } });
  }

  return pino(baseOptions);
}

export type { Logger };
