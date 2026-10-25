import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { expect, it } from 'vitest';
import { openTestDatabase } from '../test-database.js';
import { authenticateOperatorKey, generateOperatorApiKey } from '../../src/db/operator-keys.js';

it('upgrades populated schema 002 without changing verifiers, revocation or authentication', async () => {
  const pool = await openTestDatabase();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const schema = 'migration_' + randomUUID().replaceAll('-', '');
    await client.query(`CREATE SCHEMA ${schema}`);
    await client.query(`SET LOCAL search_path = ${schema}`);
    for (const name of ['001_initial_schema', '002_operator_api_keys']) {
      await client.query(
        await readFile(new URL('../../migrations/' + name + '.sql', import.meta.url), 'utf8'),
      );
    }
    const operator = randomUUID();
    const active = generateOperatorApiKey(),
      revoked = generateOperatorApiKey();
    await client.query('INSERT INTO operators (id, name, code) VALUES ($1, $2, $3)', [
      operator,
      'Upgrade test',
      schema,
    ]);
    await client.query(
      `INSERT INTO operator_api_keys (id, operator_id, name, key_hash, revoked_at)
      VALUES ($1, $2, 'Active', $3, NULL), ($4, $2, 'Revoked', $5, '2026-01-01T00:00:00Z')`,
      [randomUUID(), operator, active.keyHash, randomUUID(), revoked.keyHash],
    );
    const before = await client.query(
      'SELECT id, key_hash, revoked_at FROM operator_api_keys ORDER BY id',
    );
    await client.query(
      await readFile(
        new URL('../../migrations/003_api_key_permissions.sql', import.meta.url),
        'utf8',
      ),
    );
    const after = await client.query(
      'SELECT id, key_hash, revoked_at FROM operator_api_keys ORDER BY id',
    );
    expect(after.rows).toEqual(before.rows);
    expect((await client.query('SELECT permission FROM operator_api_keys')).rows).toEqual([
      { permission: 'read_write' },
      { permission: 'read_write' },
    ]);
    // Authentication only requires query(); use the same transactional connection.
    expect(
      (await authenticateOperatorKey(client as unknown as Pool, active.apiKey))?.permission,
    ).toBe('read_write');
    expect(await authenticateOperatorKey(client as unknown as Pool, revoked.apiKey)).toBeNull();
    await expect(
      client.query("UPDATE operator_api_keys SET permission = 'admin'"),
    ).rejects.toThrow();
  } finally {
    await client.query('ROLLBACK');
    client.release();
    await pool.end();
  }
});
