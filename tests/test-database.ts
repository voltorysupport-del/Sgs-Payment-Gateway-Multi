import { Pool, type PoolConfig } from 'pg';

type Environment = Readonly<Record<string, string | undefined>>;

const refusal = () => new Error('Unsafe test database configuration. See docs/testing.md.');

/** Validate before constructing a pool: never fall back to DATABASE_URL or PG* settings. */
export function testDatabaseSettings(env: Environment): {
  poolConfig: PoolConfig;
  token: string;
} {
  if (env.NODE_ENV !== 'test' || !/^[a-f0-9]{64}$/.test(env.TEST_DATABASE_TOKEN ?? '')) {
    throw refusal();
  }

  let url: URL;
  try {
    url = new URL(env.TEST_DATABASE_URL ?? '');
  } catch {
    throw refusal();
  }

  if (
    !['postgres:', 'postgresql:'].includes(url.protocol) ||
    url.hostname !== '127.0.0.1' ||
    !url.port ||
    Number(url.port) < 1 ||
    Number(url.port) > 65535 ||
    url.pathname !== '/vaultx_pay_test' ||
    url.username !== 'vaultx_test' ||
    !url.password ||
    url.search ||
    url.hash
  ) {
    throw refusal();
  }

  let password: string;
  try {
    password = decodeURIComponent(url.password);
  } catch {
    throw refusal();
  }

  return {
    token: env.TEST_DATABASE_TOKEN!,
    poolConfig: {
      host: '127.0.0.1',
      port: Number(url.port),
      database: 'vaultx_pay_test',
      user: 'vaultx_test',
      password,
      ssl: false,
      options: '-c search_path=public -c statement_timeout=10000',
      application_name: 'vaultx-integration-tests',
      max: 5,
      connectionTimeoutMillis: 5_000,
    },
  };
}

/** Only read-only SQL is allowed until the server identity and provisioning token match. */
export async function openTestDatabase(env: Environment = process.env): Promise<Pool> {
  const { poolConfig, token } = testDatabaseSettings(env);
  const pool = new Pool(poolConfig);
  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN READ ONLY');
      const result = await client.query<{ safe: boolean }>(
        `SELECT current_database() = 'vaultx_pay_test'
           AND current_user = 'vaultx_test'
           AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole
           AND NOT r.rolreplication AND NOT r.rolbypassrls
           AND d.datdba = r.oid
           AND EXISTS (
             SELECT 1 FROM vaultx_test_guard.identity WHERE token = $1
           ) AS safe
         FROM pg_catalog.pg_roles r
         JOIN pg_catalog.pg_database d ON d.datname = current_database()
         WHERE r.rolname = current_user`,
        [token],
      );
      await client.query('ROLLBACK');
      if (result.rows.length !== 1 || result.rows[0]?.safe !== true) throw refusal();
    } finally {
      client.release();
    }
    return pool;
  } catch {
    await pool.end();
    // Never echo the URL, token, password, or PostgreSQL error details.
    throw refusal();
  }
}
