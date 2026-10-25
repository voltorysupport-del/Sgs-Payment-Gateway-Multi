import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { openTestDatabase, testDatabaseSettings } from '../test-database.js';
import { runMigrations } from '../../src/db/migrate.js';
import { authenticateOperatorKey, generateOperatorApiKey } from '../../src/db/operator-keys.js';

async function openUpgradeDatabase(): Promise<Pool> {
  // A third empty DB exists ONLY in the verified disposable cluster. This avoids
  // resetting public tables used concurrently by other suites or rewriting SQL.
  const verified = await openTestDatabase();
  await verified.end();
  const { poolConfig, token } = testDatabaseSettings(process.env);
  const pool = new Pool({ ...poolConfig, database: 'vaultx_pay_upgrade_test', max: 1 });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const identity = await client.query<{ safe: boolean }>(
      `SELECT current_database() = 'vaultx_pay_upgrade_test'
      AND session_user = 'vaultx_test' AND d.datdba = r.oid
      AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls
      AND pg_catalog.shobj_description(d.oid, 'pg_database') = $1 AS safe
      FROM pg_catalog.pg_database d JOIN pg_catalog.pg_roles r ON r.rolname = session_user WHERE d.datname = current_database()`,
      ['vaultx-test-upgrade:' + token],
    );
    await client.query('ROLLBACK');
    if (identity.rows[0]?.safe !== true)
      throw new Error('Disposable upgrade database identity refused.');
  } catch (error) {
    client.release(true);
    await pool.end();
    throw error;
  }
  client.release();
  return pool;
}

it('upgrades populated schema 003 and rolls back all 004 objects and its migration record after a failure', async () => {
  const pool = await openUpgradeDatabase();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'CREATE TABLE public.schema_migrations(name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())',
    );
    const existingMigrationNames = [
      '001_initial_schema',
      '002_operator_api_keys',
      '003_api_key_permissions',
    ];
    for (const name of existingMigrationNames) {
      await client.query(
        await readFile(new URL('../../migrations/' + name + '.sql', import.meta.url), 'utf8'),
      );
      await client.query('INSERT INTO public.schema_migrations(name) VALUES ($1)', [name + '.sql']);
    }
    const operator = randomUUID(),
      payment = randomUUID(),
      active = generateOperatorApiKey(),
      revoked = generateOperatorApiKey();
    await client.query('INSERT INTO public.operators(id, name, code) VALUES ($1, $2, $3)', [
      operator,
      'Upgrade fixture',
      'upgrade_' + operator,
    ]);
    await client.query(
      `INSERT INTO public.operator_api_keys(id, operator_id, name, key_hash, permission, revoked_at)
      VALUES ($1, $2, 'Active', $3, 'read_only', NULL), ($4, $2, 'Revoked', $5, 'read_write', NOW())`,
      [randomUUID(), operator, active.keyHash, randomUUID(), revoked.keyHash],
    );
    await client.query(
      "INSERT INTO public.payments(id, operator_id, amount_minor, currency, idempotency_key) VALUES ($1, $2, 100, 'EUR', $3)",
      [payment, operator, randomUUID()],
    );
    const before = await client.query(
      'SELECT id, key_hash, permission, revoked_at FROM public.operator_api_keys ORDER BY id',
    );
    const migration = await readFile(
      new URL('../../migrations/004_dashboard_auth.sql', import.meta.url),
      'utf8',
    );
    await client.query('SAVEPOINT before_004');
    await client.query(migration);
    await client.query(
      "INSERT INTO public.schema_migrations(name) VALUES ('004_dashboard_auth.sql')",
    );
    await expect(client.query('SELECT 1 / 0')).rejects.toThrow();
    await client.query('ROLLBACK TO SAVEPOINT before_004');
    expect(
      (await client.query("SELECT to_regclass('public.dashboard_users') AS object")).rows,
    ).toEqual([{ object: null }]);
    expect(
      (
        await client.query(
          "SELECT oid FROM pg_catalog.pg_proc WHERE pronamespace = 'public'::regnamespace AND proname IN ('invalidate_dashboard_user_sessions', 'invalidate_dashboard_membership_sessions', 'invalidate_suspended_operator_sessions')",
        )
      ).rowCount,
    ).toBe(0);
    expect(
      (
        await client.query(
          "SELECT oid FROM pg_catalog.pg_trigger WHERE tgname = 'dashboard_operator_invalidation'",
        )
      ).rowCount,
    ).toBe(0);
    expect(
      (
        await client.query(
          "SELECT name FROM public.schema_migrations WHERE name = '004_dashboard_auth.sql'",
        )
      ).rowCount,
    ).toBe(0);
    for (const name of [
      'dashboard_users',
      'dashboard_memberships',
      'dashboard_sessions',
      'dashboard_login_limits',
    ])
      expect(
        (await client.query('SELECT to_regclass($1) AS object', ['public.' + name])).rows,
      ).toEqual([{ object: null }]);
    await client.query(migration);
    expect(
      (
        await client.query(
          'SELECT id, key_hash, permission, revoked_at FROM public.operator_api_keys ORDER BY id',
        )
      ).rows,
    ).toEqual(before.rows);
    expect(
      (
        await client.query('SELECT status, amount_minor FROM public.payments WHERE id = $1', [
          payment,
        ])
      ).rows,
    ).toEqual([{ status: 'pending', amount_minor: '100' }]);
    expect(
      (await authenticateOperatorKey(client as unknown as Pool, active.apiKey))?.permission,
    ).toBe('read_only');
    expect(await authenticateOperatorKey(client as unknown as Pool, revoked.apiKey)).toBeNull();
    await client.query("UPDATE public.operators SET status = 'suspended' WHERE id = $1", [
      operator,
    ]);
    expect(await authenticateOperatorKey(client as unknown as Pool, active.apiKey)).toBeNull();
  } finally {
    await client.query('ROLLBACK');
    client.release();
    await pool.end();
  }
});

it(
  'serializes concurrent migration bootstrap, applies each file once and still propagates real SQL failures',
  { timeout: 20_000 },
  async () => {
    const pool = await openUpgradeDatabase();
    const peers = await Promise.all([
      openUpgradeDatabase(),
      openUpgradeDatabase(),
      openUpgradeDatabase(),
    ]);
    const blocker = await pool.connect();
    let runs: Promise<void[]> | undefined;
    try {
      // Hold the exact migration lock to prove independent sessions queue BEFORE DDL.
      await blocker.query('SELECT pg_advisory_lock(894318, 1)');
      runs = Promise.all(peers.map((peer) => runMigrations(peer)));
      // Attach rejection handling immediately, even when testing a broken migrator.
      void runs.catch(() => undefined);
      let queued = 0;
      for (let i = 0; i < 100; i++) {
        const locks = await blocker.query<{
          count: string;
        }>(`SELECT count(*) FROM pg_catalog.pg_locks
        WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())
          AND classid = 894318 AND objid = 1 AND NOT granted`);
        queued = Number(locks.rows[0]!.count);
        if (queued === 3) break;
        await new Promise((r) => setTimeout(r, 10));
      }
      expect(queued).toBe(3);
      expect(
        (await blocker.query("SELECT to_regclass('public.schema_migrations') AS object")).rows,
      ).toEqual([{ object: null }]);
      await blocker.query('SELECT pg_advisory_unlock(894318, 1)');
      await runs;
      const before = await blocker.query<{ name: string; applied_at: Date }>(
        'SELECT name, applied_at FROM public.schema_migrations ORDER BY name',
      );
      expect(before.rows.map((row) => row.name)).toEqual([
        '001_initial_schema.sql',
        '002_operator_api_keys.sql',
        '003_api_key_permissions.sql',
        '004_dashboard_auth.sql',
      ]);
      await Promise.all(peers.map((peer) => runMigrations(peer)));
      expect(
        (await blocker.query('SELECT name, applied_at FROM public.schema_migrations ORDER BY name'))
          .rows,
      ).toEqual(before.rows);
      // Deliberately inconsistent disposable history: the DDL MUST fail, not be ignored.
      const first = before.rows[0]!;
      await blocker.query('DELETE FROM public.schema_migrations WHERE name = $1', [first.name]);
      try {
        await expect(runMigrations(peers[0])).rejects.toMatchObject({ code: '42P07' });
        expect(
          (
            await blocker.query('SELECT name FROM public.schema_migrations WHERE name = $1', [
              first.name,
            ])
          ).rowCount,
        ).toBe(0);
        const locks = await blocker.query<{
          count: string;
        }>(`SELECT count(*) FROM pg_catalog.pg_locks
        WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())
          AND classid = 894318 AND objid = 1 AND granted`);
        expect(Number(locks.rows[0]!.count)).toBe(0);
      } finally {
        await blocker.query(
          'INSERT INTO public.schema_migrations(name, applied_at) VALUES ($1, $2)',
          [first.name, first.applied_at],
        );
      }
      await runMigrations(peers[0]);
    } finally {
      await blocker.query('SELECT pg_advisory_unlock_all()');
      await runs?.catch(() => undefined);
      blocker.release();
      await Promise.all([...peers, pool].map((peer) => peer.end()));
    }
  },
);
