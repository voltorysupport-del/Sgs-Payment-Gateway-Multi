import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig, type Config } from '../../src/config/index.js';
import { UnsafeConfigurationError, assertRealPaymentsDisabled } from '../../src/config/safety.js';
import { VALID_ENV } from '../helpers.js';

function problemsFor(env: Record<string, string | undefined>): readonly string[] {
  try {
    loadConfig(env);
  } catch (error) {
    if (error instanceof ConfigError) return error.problems;
    throw error;
  }
  throw new Error('Expected loadConfig to reject this configuration');
}

describe('loadConfig', () => {
  it('accepts a minimal valid configuration and applies safe defaults', () => {
    const config = loadConfig(VALID_ENV);

    expect(config.nodeEnv).toBe('test');
    expect(config.port).toBe(3000);
    expect(config.logLevel).toBe('info');
    expect(config.liveModeEnabled).toBe(false);
    expect(config.allowedProviders).toEqual(['simulator']);
    expect(config.simulatorControlsEnabled).toBe(false);
  });

  it('returns a read-only configuration object', () => {
    const config = loadConfig(VALID_ENV);
    expect(Object.isFrozen(config)).toBe(true);
    expect(Object.isFrozen(config.allowedProviders)).toBe(true);
  });

  it('requires DATABASE_URL', () => {
    const problems = problemsFor({ NODE_ENV: 'test' });
    expect(problems.some((p) => p.startsWith('DATABASE_URL'))).toBe(true);
  });

  it('rejects a DATABASE_URL that is not a PostgreSQL URL', () => {
    const problems = problemsFor({ ...VALID_ENV, DATABASE_URL: 'mysql://user:pw@host/db' });
    expect(problems.some((p) => p.startsWith('DATABASE_URL'))).toBe(true);
  });

  it('never includes setting values (such as passwords) in error messages', () => {
    const secretUrl = 'mysql://user:SuperSecretPassword123@host/db';
    try {
      loadConfig({ ...VALID_ENV, DATABASE_URL: secretUrl, LIVE_MODE_ENABLED: 'true' });
      expect.unreachable('loadConfig should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      expect((error as Error).message).not.toContain('SuperSecretPassword123');
    }
  });

  it('reports every problem at once, not just the first', () => {
    const problems = problemsFor({ NODE_ENV: 'test', PORT: 'abc', LIVE_MODE_ENABLED: 'true' });
    expect(problems.length).toBeGreaterThanOrEqual(3);
  });

  it.each(['0', '70000', 'abc', '3000.5'])('rejects invalid PORT %s', (port) => {
    const problems = problemsFor({ ...VALID_ENV, PORT: port });
    expect(problems.some((p) => p.startsWith('PORT'))).toBe(true);
  });

  it('rejects an unknown NODE_ENV', () => {
    const problems = problemsFor({ ...VALID_ENV, NODE_ENV: 'staging' });
    expect(problems.some((p) => p.startsWith('NODE_ENV'))).toBe(true);
  });
});

describe('real payment processing is locked off', () => {
  it('refuses LIVE_MODE_ENABLED=true', () => {
    const problems = problemsFor({ ...VALID_ENV, LIVE_MODE_ENABLED: 'true' });
    expect(problems.join('\n')).toMatch(/LIVE_MODE_ENABLED.*disabled in Version 1/);
  });

  it.each(['TRUE', 'yes', '1', 'on', ' false'])(
    'refuses anything other than exactly "false" (got %j)',
    (value) => {
      const problems = problemsFor({ ...VALID_ENV, LIVE_MODE_ENABLED: value });
      expect(problems.some((p) => p.startsWith('LIVE_MODE_ENABLED'))).toBe(true);
    },
  );

  it('accepts LIVE_MODE_ENABLED=false', () => {
    expect(loadConfig({ ...VALID_ENV, LIVE_MODE_ENABLED: 'false' }).liveModeEnabled).toBe(false);
  });

  it.each(['voltory', 'simulator,voltory', 'stripe', ''])(
    'refuses ALLOWED_PROVIDERS=%j',
    (value) => {
      const problems = problemsFor({ ...VALID_ENV, ALLOWED_PROVIDERS: value });
      expect(problems.some((p) => p.startsWith('ALLOWED_PROVIDERS'))).toBe(true);
    },
  );

  it('refuses simulator controls in production', () => {
    const problems = problemsFor({
      ...VALID_ENV,
      NODE_ENV: 'production',
      SIMULATOR_CONTROLS_ENABLED: 'true',
    });
    expect(problems.some((p) => p.startsWith('SIMULATOR_CONTROLS_ENABLED'))).toBe(true);
  });

  it('allows simulator controls outside production', () => {
    const config = loadConfig({ ...VALID_ENV, SIMULATOR_CONTROLS_ENABLED: 'true' });
    expect(config.simulatorControlsEnabled).toBe(true);
  });

  it('treats the text "false" as false (a common JavaScript trap)', () => {
    const config = loadConfig({ ...VALID_ENV, SIMULATOR_CONTROLS_ENABLED: 'false' });
    expect(config.simulatorControlsEnabled).toBe(false);
  });
});

describe('assertRealPaymentsDisabled (second, independent safety check)', () => {
  const safe = (): Config => loadConfig(VALID_ENV);

  it('passes for a safe configuration', () => {
    expect(() => assertRealPaymentsDisabled(safe())).not.toThrow();
  });

  it('throws if a hand-built config enables live mode', () => {
    const unsafe = { ...safe(), liveModeEnabled: true } as unknown as Config;
    expect(() => assertRealPaymentsDisabled(unsafe)).toThrow(UnsafeConfigurationError);
  });

  it('throws if a hand-built config allows a non-simulator provider', () => {
    const unsafe = { ...safe(), allowedProviders: ['voltory'] } as unknown as Config;
    expect(() => assertRealPaymentsDisabled(unsafe)).toThrow(UnsafeConfigurationError);
  });

  it('throws if a hand-built production config enables simulator controls', () => {
    const unsafe = {
      ...safe(),
      nodeEnv: 'production',
      simulatorControlsEnabled: true,
    } as unknown as Config;
    expect(() => assertRealPaymentsDisabled(unsafe)).toThrow(UnsafeConfigurationError);
  });
});

describe('owner foundation configuration boundary', () => {
  const owner = {
    ...VALID_ENV,
    OWNER_ENABLED: 'true',
    OWNER_ORIGIN: 'https://owners.example.invalid',
    DASHBOARD_PUBLIC_ORIGIN: 'https://clients.example.invalid',
  };
  it('defaults owner authority off', () => {
    expect(loadConfig(VALID_ENV).ownerEnabled).toBe(false);
  });
  it('permits explicitly separated synthetic development/test realms only', () => {
    expect(loadConfig(owner).ownerEnabled).toBe(true);
  });
  it('rejects production enablement pending reviewed ceremonies and deployment controls', () => {
    expect(() => loadConfig({ ...owner, NODE_ENV: 'production' })).toThrow(ConfigError);
  });
  it('rejects missing origins and same-host cookie realms including different ports', () => {
    for (const env of [
      { ...owner, OWNER_ORIGIN: undefined },
      { ...owner, DASHBOARD_PUBLIC_ORIGIN: undefined },
      { ...owner, OWNER_ORIGIN: 'https://clients.example.invalid:444' },
      { ...owner, OWNER_ORIGIN: 'http://owners.example.invalid' },
      { ...owner, OWNER_ORIGIN: 'not a URL' },
    ])
      expect(() => loadConfig(env)).toThrow(ConfigError);
  });
});

describe('merchant management development gate', () => {
  it('defaults off and requires the existing dashboard authentication gate', () => {
    expect(loadConfig(VALID_ENV).merchantManagementEnabled).toBe(false);
    expect(
      problemsFor({ ...VALID_ENV, MERCHANT_MANAGEMENT_ENABLED: 'true' }).some((p) =>
        p.startsWith('MERCHANT_MANAGEMENT_ENABLED'),
      ),
    ).toBe(true);
    expect(
      loadConfig({
        ...VALID_ENV,
        MERCHANT_MANAGEMENT_ENABLED: 'true',
        DASHBOARD_ENABLED: 'true',
        DASHBOARD_PUBLIC_ORIGIN: 'https://client.example.invalid',
      }).merchantManagementEnabled,
    ).toBe(true);
  });
  it('refuses production activation and never echoes private configuration', () => {
    const problems = problemsFor({
      ...VALID_ENV,
      NODE_ENV: 'production',
      MERCHANT_MANAGEMENT_ENABLED: 'true',
      DASHBOARD_ENABLED: 'true',
      DASHBOARD_PUBLIC_ORIGIN: 'https://client.example.invalid',
    });
    expect(problems.some((p) => p.startsWith('MERCHANT_MANAGEMENT_ENABLED'))).toBe(true);
  });
});

describe('synthetic Phase 3 enrollment gate', () => {
  it('defaults off with existing dashboard/live gates off', () => {
    const config = loadConfig(VALID_ENV);
    expect(config.phase3EnrollmentEnabled).toBe(false);
    expect(config.dashboardEnabled).toBe(false);
    expect(config.dashboardBffEnabled).toBe(false);
    expect(config.liveModeEnabled).toBe(false);
  });
  it('requires development/test merchant authentication and refuses production', () => {
    expect(
      problemsFor({ ...VALID_ENV, PHASE3_ENROLLMENT_ENABLED: 'true' }).some((p) =>
        p.startsWith('PHASE3_ENROLLMENT_ENABLED'),
      ),
    ).toBe(true);
    expect(
      problemsFor({
        ...VALID_ENV,
        NODE_ENV: 'production',
        PHASE3_ENROLLMENT_ENABLED: 'true',
        DASHBOARD_ENABLED: 'true',
        MERCHANT_MANAGEMENT_ENABLED: 'true',
        DASHBOARD_PUBLIC_ORIGIN: 'https://dashboard.example.invalid',
      }).some((p) => p.startsWith('PHASE3_ENROLLMENT_ENABLED')),
    ).toBe(true);
    expect(
      loadConfig({
        ...VALID_ENV,
        PHASE3_ENROLLMENT_ENABLED: 'true',
        DASHBOARD_ENABLED: 'true',
        MERCHANT_MANAGEMENT_ENABLED: 'true',
        DASHBOARD_PUBLIC_ORIGIN: 'https://dashboard.example.invalid',
      }).phase3EnrollmentEnabled,
    ).toBe(true);
  });
});
