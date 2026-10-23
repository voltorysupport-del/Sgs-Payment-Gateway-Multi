import { beforeEach, describe, expect, it, vi } from 'vitest';
import { openTestDatabase, testDatabaseSettings } from '../test-database.js';

const mocks = vi.hoisted(() => ({
  query: vi.fn(),
  release: vi.fn(),
  connect: vi.fn(),
  end: vi.fn(),
  construct: vi.fn(),
}));
vi.mock('pg', () => ({
  Pool: class {
    constructor(config: unknown) {
      mocks.construct(config);
    }
    connect = mocks.connect;
    end = mocks.end;
  },
}));

const valid = {
  NODE_ENV: 'test',
  TEST_DATABASE_URL: 'postgres://vaultx_test:synthetic@127.0.0.1:15432/vaultx_pay_test',
  TEST_DATABASE_TOKEN: 'a'.repeat(64),
};

beforeEach(() => {
  vi.clearAllMocks();
  mocks.end.mockResolvedValue(undefined);
  mocks.query.mockResolvedValue({ rows: [] });
  mocks.connect.mockResolvedValue({ query: mocks.query, release: mocks.release });
});

describe('test database configuration boundary', () => {
  it.each([
    ['missing URL', { TEST_DATABASE_URL: undefined }],
    ['missing token', { TEST_DATABASE_TOKEN: undefined }],
    ['malformed token', { TEST_DATABASE_TOKEN: 'unsafe' }],
    ['non-test environment', { NODE_ENV: 'production' }],
    ['malformed URL', { TEST_DATABASE_URL: 'not-a-url' }],
    [
      'remote host',
      { TEST_DATABASE_URL: 'postgres://vaultx_test:x@production.invalid:5432/vaultx_pay_test' },
    ],
    [
      'development database',
      { TEST_DATABASE_URL: 'postgres://vaultx_test:x@127.0.0.1:5432/vaultx_pay' },
    ],
    [
      'staging database',
      { TEST_DATABASE_URL: 'postgres://vaultx_test:x@127.0.0.1:5432/vaultx_pay_staging' },
    ],
    [
      'production database',
      { TEST_DATABASE_URL: 'postgres://vaultx_test:x@127.0.0.1:5432/vaultx_pay_production' },
    ],
    [
      'administrator role',
      { TEST_DATABASE_URL: 'postgres://postgres:x@127.0.0.1:5432/vaultx_pay_test' },
    ],
    [
      'missing password',
      { TEST_DATABASE_URL: 'postgres://vaultx_test@127.0.0.1:5432/vaultx_pay_test' },
    ],
    [
      'missing explicit port',
      { TEST_DATABASE_URL: 'postgres://vaultx_test:x@127.0.0.1/vaultx_pay_test' },
    ],
    [
      'connection overrides',
      {
        TEST_DATABASE_URL:
          'postgres://vaultx_test:x@127.0.0.1:5432/vaultx_pay_test?host=production.invalid',
      },
    ],
    [
      'URL fragment',
      { TEST_DATABASE_URL: 'postgres://vaultx_test:x@127.0.0.1:5432/vaultx_pay_test#unsafe' },
    ],
  ])('rejects %s before constructing a pool', async (_name, overrides) => {
    await expect(openTestDatabase({ ...valid, ...overrides })).rejects.toThrow(
      'Unsafe test database',
    );
    expect(mocks.construct).not.toHaveBeenCalled();
  });

  it('never falls back to application or PostgreSQL environment settings', () => {
    const config = testDatabaseSettings({
      ...valid,
      DATABASE_URL: 'postgres://production.invalid/production',
      PGHOST: 'production.invalid',
      PGDATABASE: 'production',
      PGUSER: 'postgres',
      PGOPTIONS: '-c search_path=unsafe',
    }).poolConfig;
    expect(config).toMatchObject({
      host: '127.0.0.1',
      port: 15432,
      database: 'vaultx_pay_test',
      user: 'vaultx_test',
      ssl: false,
      options: '-c search_path=public -c statement_timeout=10000',
    });
    expect(() =>
      testDatabaseSettings({ NODE_ENV: 'test', DATABASE_URL: valid.TEST_DATABASE_URL }),
    ).toThrow('Unsafe test database');
  });
});

describe('server-side identity gate', () => {
  it('returns a pool only after a read-only identity check succeeds', async () => {
    mocks.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ safe: true }] })
      .mockResolvedValueOnce({ rows: [] });
    await expect(openTestDatabase(valid)).resolves.toBeDefined();
    expect(mocks.query.mock.calls[0]).toEqual(['BEGIN READ ONLY']);
    expect(mocks.query.mock.calls[1]?.[1]).toEqual([valid.TEST_DATABASE_TOKEN]);
    expect(mocks.query.mock.calls[2]).toEqual(['ROLLBACK']);
    expect(mocks.release).toHaveBeenCalledOnce();
    expect(mocks.end).not.toHaveBeenCalled();
  });

  it.each([false, null, undefined])('closes the pool when identity is %s', async (safe) => {
    mocks.query.mockResolvedValueOnce({ rows: [] }).mockResolvedValueOnce({ rows: [{ safe }] });
    await expect(openTestDatabase(valid)).rejects.toThrow('Unsafe test database');
    expect(mocks.end).toHaveBeenCalledOnce();
    expect(mocks.release).toHaveBeenCalledOnce();
    expect(mocks.query.mock.calls).toHaveLength(3);
  });

  it('fails closed and suppresses connection error credentials', async () => {
    mocks.connect.mockRejectedValueOnce(new Error(valid.TEST_DATABASE_URL));
    await expect(openTestDatabase(valid)).rejects.toThrow(
      'Unsafe test database configuration. See docs/testing.md.',
    );
    expect(mocks.end).toHaveBeenCalledOnce();
    expect(mocks.query).not.toHaveBeenCalled();
  });

  it('fails closed when the server marker cannot be read', async () => {
    mocks.query
      .mockResolvedValueOnce({ rows: [] })
      .mockRejectedValueOnce(new Error('missing marker'));
    await expect(openTestDatabase(valid)).rejects.toThrow('Unsafe test database');
    expect(mocks.release).toHaveBeenCalledOnce();
    expect(mocks.end).toHaveBeenCalledOnce();
    expect(mocks.query.mock.calls).toHaveLength(2);
  });
});
