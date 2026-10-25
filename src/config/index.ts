/**
 * Configuration loading and validation.
 *
 * Every setting the app uses is read from environment variables, checked here,
 * and turned into a typed, read-only `Config` object. If anything is missing or
 * unsafe, `loadConfig` throws a `ConfigError` and the app refuses to start.
 *
 * Error messages name the setting and the problem but NEVER echo the value,
 * because values such as DATABASE_URL contain passwords.
 */
import { z } from 'zod';
import { isIP } from 'node:net';

/** Payment providers this version of VaultX Pay is allowed to use. */
export const SUPPORTED_PROVIDERS = ['simulator'] as const;
export type ProviderName = (typeof SUPPORTED_PROVIDERS)[number];

export const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

/**
 * Strict "true"/"false" parser.
 * We deliberately do NOT use z.coerce.boolean(), because it treats the text
 * "false" as true (any non-empty string is truthy in JavaScript).
 */
const booleanFlag = (name: string) =>
  z
    .enum(['true', 'false'], { message: `${name} must be exactly "true" or "false"` })
    .default('false')
    .transform((value) => value === 'true');

const envSchema = z
  .object({
    DASHBOARD_ENABLED: booleanFlag('DASHBOARD_ENABLED'),
    DASHBOARD_BFF_ENABLED: booleanFlag('DASHBOARD_BFF_ENABLED'),
    DASHBOARD_OPERATOR_ID: z
      .uuid()
      .transform((value) => value.toLowerCase())
      .optional(),
    DASHBOARD_READ_ONLY_API_KEY: z
      .string()
      .optional()
      .refine((value) => value === undefined || /^vxp_[a-f0-9]{64}$/.test(value), {
        message: 'DASHBOARD_READ_ONLY_API_KEY must use the operator key format',
      }),
    DASHBOARD_PUBLIC_ORIGIN: z
      .string()
      .optional()
      .refine(
        (value) => {
          if (value === undefined) return true;
          try {
            const u = new URL(value);
            return u.protocol === 'https:' && u.origin === value && !u.username && !u.password;
          } catch {
            return false;
          }
        },
        { message: 'DASHBOARD_PUBLIC_ORIGIN must be an exact HTTPS origin' },
      ),
    DASHBOARD_TRUSTED_PROXIES: z
      .string()
      .default('')
      .transform((value) => (value ? value.split(',').map((v) => v.trim()) : []))
      .refine(
        (values) =>
          values.every((value) => {
            const [address, mask, extra] = value.split('/');
            const family = isIP(address ?? '');
            return (
              !extra &&
              family !== 0 &&
              (mask === undefined ||
                (/^[0-9]+$/.test(mask) &&
                  Number(mask) > 0 &&
                  Number(mask) <= (family === 4 ? 32 : 128)))
            );
          }),
        { message: 'DASHBOARD_TRUSTED_PROXIES must contain explicit IPs or CIDRs (no catch-all)' },
      ),
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),

    PORT: z.coerce.number().int().min(1).max(65535).default(3000),

    LOG_LEVEL: z.enum(LOG_LEVELS).default('info'),

    DATABASE_URL: z
      .string({ message: 'DATABASE_URL is required' })
      .min(1, { message: 'DATABASE_URL is required' })
      .refine((value) => /^postgres(ql)?:\/\//.test(value), {
        message: 'DATABASE_URL must start with postgres:// or postgresql://',
      }),

    // SAFETY LOCK: real payment processing is impossible in Version 1.
    // Any value other than "false" stops the app from starting.
    LIVE_MODE_ENABLED: z
      .enum(['true', 'false'], { message: 'LIVE_MODE_ENABLED must be exactly "false"' })
      .default('false')
      .refine((value) => value === 'false', {
        message:
          'LIVE_MODE_ENABLED must be "false". Real payment processing is disabled in Version 1.',
      })
      .transform(() => false as const),

    // SAFETY LOCK: only providers on the allowlist above may be configured.
    ALLOWED_PROVIDERS: z
      .string()
      .default('simulator')
      .transform((value) =>
        value
          .split(',')
          .map((name) => name.trim())
          .filter((name) => name.length > 0),
      )
      .pipe(
        z
          .array(
            z.enum(SUPPORTED_PROVIDERS, {
              message: `ALLOWED_PROVIDERS may only contain: ${SUPPORTED_PROVIDERS.join(', ')}`,
            }),
          )
          .min(1, { message: 'ALLOWED_PROVIDERS must list at least one provider' }),
      ),

    SIMULATOR_CONTROLS_ENABLED: booleanFlag('SIMULATOR_CONTROLS_ENABLED'),
  })
  .superRefine((env, ctx) => {
    if (env.DASHBOARD_BFF_ENABLED) {
      if (!env.DASHBOARD_ENABLED)
        ctx.addIssue({
          code: 'custom',
          path: ['DASHBOARD_BFF_ENABLED'],
          message: 'Requires DASHBOARD_ENABLED',
        });
      if (!env.DASHBOARD_OPERATOR_ID)
        ctx.addIssue({
          code: 'custom',
          path: ['DASHBOARD_OPERATOR_ID'],
          message: 'Required for dashboard BFF',
        });
      if (!env.DASHBOARD_READ_ONLY_API_KEY)
        ctx.addIssue({
          code: 'custom',
          path: ['DASHBOARD_READ_ONLY_API_KEY'],
          message: 'Required for dashboard BFF',
        });
    }
    if (env.DASHBOARD_ENABLED && !env.DASHBOARD_PUBLIC_ORIGIN)
      ctx.addIssue({
        code: 'custom',
        path: ['DASHBOARD_PUBLIC_ORIGIN'],
        message: 'Required when dashboard is enabled',
      });
    if (env.NODE_ENV === 'production' && env.SIMULATOR_CONTROLS_ENABLED) {
      ctx.addIssue({
        code: 'custom',
        path: ['SIMULATOR_CONTROLS_ENABLED'],
        message: 'SIMULATOR_CONTROLS_ENABLED must not be "true" when NODE_ENV is "production"',
      });
    }
  });

export interface Config {
  readonly dashboardBffEnabled: boolean;
  readonly dashboardOperatorId: string | undefined;
  readonly dashboardReadOnlyApiKey: string | undefined;
  readonly dashboardEnabled: boolean;
  readonly dashboardPublicOrigin: string | undefined;
  readonly dashboardTrustedProxies: readonly string[];
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly logLevel: LogLevel;
  readonly databaseUrl: string;
  /** Always false in Version 1. The type itself only allows `false`. */
  readonly liveModeEnabled: false;
  readonly allowedProviders: readonly ProviderName[];
  readonly simulatorControlsEnabled: boolean;
}

/** Thrown when configuration is missing or unsafe. Lists every problem found. */
export class ConfigError extends Error {
  readonly problems: readonly string[];

  constructor(problems: string[]) {
    super(`Invalid configuration:\n  - ${problems.join('\n  - ')}`);
    this.name = 'ConfigError';
    this.problems = Object.freeze([...problems]);
  }
}

type EnvSource = Readonly<Record<string, string | undefined>>;

/**
 * Reads and validates configuration.
 * Pass an object in tests; the app passes `process.env`.
 */
export function loadConfig(env: EnvSource = process.env): Config {
  const result = envSchema.safeParse(env);

  if (!result.success) {
    // Only the setting name and the rule are reported, never the value.
    const problems = result.error.issues.map((issue) => {
      const setting = issue.path[0] !== undefined ? String(issue.path[0]) : 'config';
      return `${setting}: ${issue.message}`;
    });
    throw new ConfigError(problems);
  }

  const parsed = result.data;

  return Object.freeze({
    dashboardEnabled: parsed.DASHBOARD_ENABLED,
    dashboardBffEnabled: parsed.DASHBOARD_BFF_ENABLED,
    dashboardOperatorId: parsed.DASHBOARD_OPERATOR_ID,
    dashboardReadOnlyApiKey: parsed.DASHBOARD_READ_ONLY_API_KEY,
    dashboardPublicOrigin: parsed.DASHBOARD_PUBLIC_ORIGIN,
    dashboardTrustedProxies: Object.freeze(parsed.DASHBOARD_TRUSTED_PROXIES),
    nodeEnv: parsed.NODE_ENV,
    port: parsed.PORT,
    logLevel: parsed.LOG_LEVEL,
    databaseUrl: parsed.DATABASE_URL,
    liveModeEnabled: parsed.LIVE_MODE_ENABLED,
    allowedProviders: Object.freeze([...new Set(parsed.ALLOWED_PROVIDERS)]),
    simulatorControlsEnabled: parsed.SIMULATOR_CONTROLS_ENABLED,
  });
}
