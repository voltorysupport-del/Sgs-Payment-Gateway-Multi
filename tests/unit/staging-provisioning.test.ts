import { mkdtemp, readFile, rm, stat, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { stagingPoolConfig } from '../../src/admin/staging-config.js';
import { parseProvisioningArgs, runStagingCli } from '../../src/admin/staging-cli.js';
import { deliverKeyFile } from '../../src/admin/key-delivery.js';
import { generateOperatorApiKey } from '../../src/db/operator-keys.js';

const valid = {
  NODE_ENV: 'production',
  DATABASE_URL: 'postgres://staging_user:synthetic@db.example:5432/vaultx_pay_staging',
  VAULTX_ENVIRONMENT: 'staging',
  ALLOW_STAGING_OPERATOR_PROVISIONING: 'true',
  STAGING_DATABASE_HOST: 'db.example',
  STAGING_DATABASE_USER: 'staging_user',
};

describe('staging authorization and target configuration', () => {
  it.each([
    { ALLOW_STAGING_OPERATOR_PROVISIONING: undefined },
    { ALLOW_STAGING_OPERATOR_PROVISIONING: 'TRUE' },
    { VAULTX_ENVIRONMENT: 'production' },
    { DATABASE_URL: undefined },
    { DATABASE_URL: 'invalid-synthetic-input' },
    { DATABASE_URL: 'postgres://staging_user:synthetic@db.example/vaultx_pay_test' },
    { DATABASE_URL: 'postgres://staging_user:synthetic@db.example/vaultx_pay_production' },
    { DATABASE_URL: 'postgres://staging_user:synthetic@db.example/vaultx_pay' },
    { STAGING_DATABASE_HOST: 'other.example' },
    { STAGING_DATABASE_USER: 'postgres' },
    { STAGING_DATABASE_HOST: undefined },
    { STAGING_DATABASE_USER: undefined },
    { LIVE_MODE_ENABLED: 'true' },
    { ALLOWED_PROVIDERS: 'stripe' },
    { SIMULATOR_CONTROLS_ENABLED: 'true' },
    { DATABASE_URL: valid.DATABASE_URL + '?sslmode=disable' },
    { DATABASE_URL: valid.DATABASE_URL + '?host=production.example' },
    { DATABASE_URL: valid.DATABASE_URL + '#synthetic' },
  ])('fails closed without exposing configuration: %j', (overrides) => {
    expect(() => stagingPoolConfig({ ...valid, ...overrides })).toThrow(
      'Staging provisioning refused (configuration).',
    );
  });

  it('verifies remote TLS and sets connection identity independently of ambient PG settings', () => {
    expect(
      stagingPoolConfig({
        ...valid,
        PGHOST: 'other.example',
        PGDATABASE: 'production',
        PGSSLMODE: 'disable',
      }),
    ).toMatchObject({
      host: 'db.example',
      user: 'staging_user',
      database: 'vaultx_pay_staging',
      ssl: { rejectUnauthorized: true, minVersion: 'TLSv1.2', servername: 'db.example' },
    });
  });

  it('rejects Render internal endpoints instead of disabling certificate verification', async () => {
    const internal = {
      ...valid,
      DATABASE_URL: 'postgres://staging_user:synthetic@dpg-synthetic-a/vaultx_pay_staging',
      STAGING_DATABASE_HOST: 'dpg-synthetic-a',
    };
    expect(() => stagingPoolConfig(internal)).toThrow('Render internal PostgreSQL endpoints');
    let errors = '';
    expect(
      await runStagingCli(
        ['status'],
        internal,
        () => undefined,
        (text) => {
          errors += text;
        },
      ),
    ).toBe(1);
    expect(errors.includes('dpg-synthetic-a')).toBe(false);
    expect(errors.includes('synthetic@')).toBe(false);
  });

  it('preserves the external hostname for SNI and accepts only verify-full URL options', () => {
    const host = 'dpg-synthetic-a.oregon-postgres.render.com';
    const config = stagingPoolConfig({
      ...valid,
      DATABASE_URL: `postgres://staging_user:synthetic@${host}/vaultx_pay_staging?sslmode=verify-full`,
      STAGING_DATABASE_HOST: host,
    });
    expect(config).toMatchObject({
      host,
      ssl: { servername: host, rejectUnauthorized: true, minVersion: 'TLSv1.2' },
    });
    expect(() =>
      stagingPoolConfig({ ...valid, DATABASE_URL: valid.DATABASE_URL + '?sslmode=require' }),
    ).toThrow('Staging provisioning refused (configuration).');
  });

  it.each(
    [
      [],
      ['ensure', '--print-key'],
      ['rotate'],
      ['revoke', '--key-id', 'not-a-uuid'],
      ['ensure', '--operator-code', 'production'],
      ['status', '--key-file', '/tmp/unused'],
      ['ensure', '--key-id', randomUUID()],
    ].map((args) => ({ args })),
  )('rejects unsafe CLI arguments %j', ({ args }) => {
    expect(() => parseProvisioningArgs(args)).toThrow(
      'Staging provisioning refused (configuration).',
    );
  });

  it('defaults to an identifiable staging operator', () => {
    expect(parseProvisioningArgs(['ensure'])).toMatchObject({
      operation: 'ensure',
      operatorCode: 'staging-e2e',
    });
  });

  it('prints help without configuration and never echoes rejected credential input', async () => {
    let output = '';
    let errors = '';
    expect(
      await runStagingCli(
        ['--help'],
        {},
        (s) => {
          output += s;
        },
        (s) => {
          errors += s;
        },
      ),
    ).toBe(0);
    expect(output.includes('Usage:')).toBe(true);
    output = '';
    expect(
      await runStagingCli(
        ['ensure'],
        { ...valid, DATABASE_URL: 'synthetic-sensitive-invalid-url' },
        (s) => {
          output += s;
        },
        (s) => {
          errors += s;
        },
      ),
    ).toBe(1);
    expect(output).toBe('');
    expect(errors.includes('synthetic-sensitive-invalid-url')).toBe(false);
  });
});

describe('explicit secret-file delivery', () => {
  it('writes once outside the repository with private permissions and refuses overwrite', async () => {
    const directory = await mkdtemp(path.join(tmpdir(), 'vaultx-delivery-'));
    const destination = path.join(directory, 'key.vaultx-key.json');
    const key = {
      operatorId: randomUUID(),
      keyId: randomUUID(),
      apiKey: generateOperatorApiKey().apiKey,
    };
    try {
      await deliverKeyFile(destination, key);
      if (process.platform !== 'win32') {
        expect((await stat(destination)).mode & 0o777).toBe(0o600);
        const saved = JSON.parse(await readFile(destination, 'utf8')) as { apiKey: string };
        expect(saved.apiKey === key.apiKey).toBe(true);
      }
      await expect(deliverKeyFile(destination, key)).rejects.toThrow(
        'Staging provisioning refused (delivery).',
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it('refuses repository paths, relative paths, and symlink destinations', async () => {
    const directory = await mkdtemp(path.join(tmpdir(), 'vaultx-delivery-'));
    const key = {
      operatorId: randomUUID(),
      keyId: randomUUID(),
      apiKey: generateOperatorApiKey().apiKey,
    };
    try {
      await expect(deliverKeyFile('relative-key', key)).rejects.toThrow(
        'Staging provisioning refused (delivery).',
      );
      await expect(deliverKeyFile(path.resolve('key.vaultx-key.json'), key)).rejects.toThrow(
        'Staging provisioning refused (delivery).',
      );
      if (process.platform !== 'win32') {
        const link = path.join(directory, 'link');
        await symlink(path.join(directory, 'target'), link);
        await expect(deliverKeyFile(link, key)).rejects.toThrow(
          'Staging provisioning refused (delivery).',
        );
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
