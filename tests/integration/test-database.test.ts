import { describe, expect, it } from 'vitest';
import { openTestDatabase, testDatabaseSettings } from '../test-database.js';

// A failed rejection assertion must never print a resolved Pool with credentials.
async function checkConnection(env: Record<string, string | undefined>): Promise<string> {
  const pool = await openTestDatabase(env);
  await pool.end();
  return 'unexpectedly connected';
}

describe('disposable PostgreSQL safety protections', () => {
  it('connects as the restricted test role to the designated database', async () => {
    const pool = await openTestDatabase();
    try {
      const result = await pool.query(
        `SELECT current_database() AS database, current_user AS role,
          rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
         FROM pg_catalog.pg_roles WHERE rolname = current_user`,
      );
      expect(result.rows).toEqual([
        {
          database: 'vaultx_pay_test',
          role: 'vaultx_test',
          rolsuper: false,
          rolcreatedb: false,
          rolcreaterole: false,
          rolreplication: false,
          rolbypassrls: false,
        },
      ]);
    } finally {
      await pool.end();
    }
  });

  it('rejects a mismatched provisioning token on the real server', async () => {
    const wrongToken =
      process.env.TEST_DATABASE_TOKEN === '0'.repeat(64) ? '1'.repeat(64) : '0'.repeat(64);
    await expect(
      checkConnection({ ...process.env, TEST_DATABASE_TOKEN: wrongToken }),
    ).rejects.toThrow('Unsafe test database');
  });

  it('requires the generated password for TCP connections', async () => {
    // Validate first so URL parser errors cannot echo malformed credential input.
    testDatabaseSettings(process.env);
    const url = new URL(process.env.TEST_DATABASE_URL!);
    url.password = 'deliberately-incorrect-test-password';
    await expect(
      checkConnection({ ...process.env, TEST_DATABASE_URL: url.toString() }),
    ).rejects.toThrow('Unsafe test database');
  });
});
