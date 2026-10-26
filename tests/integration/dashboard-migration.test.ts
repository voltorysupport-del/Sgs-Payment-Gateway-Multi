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

it('upgrades populated 004 to 005 atomically, preserving verifiers and viewer identity without implicit rights for ineligible users', async () => {
  const pool = await openUpgradeDatabase(),
    client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'CREATE TABLE public.schema_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())',
    );
    for (const name of [
      '001_initial_schema',
      '002_operator_api_keys',
      '003_api_key_permissions',
      '004_dashboard_auth',
    ]) {
      await client.query(
        await readFile(new URL('../../migrations/' + name + '.sql', import.meta.url), 'utf8'),
      );
      await client.query('INSERT INTO schema_migrations(name) VALUES($1)', [name + '.sql']);
    }
    const op = randomUUID(),
      suspended = randomUUID(),
      users = [randomUUID(), randomUUID(), randomUUID()],
      members = [randomUUID(), randomUUID(), randomUUID()],
      key = generateOperatorApiKey(),
      revoked = generateOperatorApiKey();
    await client.query(
      "INSERT INTO operators(id,name,code,status) VALUES($1::uuid,'Active',$1::uuid::text,'active'),($2::uuid,'Suspended',$2::uuid::text,'suspended')",
      [op, suspended],
    );
    for (let i = 0; i < users.length; i++) {
      await client.query(
        'INSERT INTO dashboard_users(id,username,password_hash,status) VALUES($1::uuid,$1::uuid::text,$2,$3)',
        [users[i], 'synthetic-existing-verifier', i === 1 ? 'disabled' : 'active'],
      );
      await client.query(
        'INSERT INTO dashboard_memberships(id,user_id,operator_id) VALUES($1,$2,$3)',
        [members[i], users[i], i === 2 ? suspended : op],
      );
    }
    await client.query(
      "INSERT INTO operator_api_keys(id,operator_id,name,key_hash,permission,revoked_at) VALUES($1,$2,'Reader',$3,'read_only',NULL),($4,$2,'Revoked',$5,'read_write',NOW())",
      [randomUUID(), op, key.keyHash, randomUUID(), revoked.keyHash],
    );
    await client.query(
      "INSERT INTO payments(id,operator_id,amount_minor,currency,idempotency_key) VALUES($1::uuid,$2,100,'EUR',$1::uuid::text)",
      [randomUUID(), op],
    );
    await client.query(
      "INSERT INTO dashboard_sessions(token_hash,csrf_hash,user_id,membership_id,auth_version) VALUES(repeat('a',64),repeat('b',64),$1,$2,1)",
      [users[0], members[0]],
    );
    await client.query(
      "INSERT INTO dashboard_sessions(token_hash,csrf_hash) VALUES(repeat('c',64),repeat('d',64))",
    );
    const before = {
      users: (
        await client.query('SELECT id,password_hash,auth_version FROM dashboard_users ORDER BY id')
      ).rows,
      keys: (
        await client.query(
          'SELECT id,key_hash,permission,revoked_at FROM operator_api_keys ORDER BY id',
        )
      ).rows,
      payments: (await client.query('SELECT * FROM payments')).rows,
    };
    const migration = await readFile(
      new URL('../../migrations/005_viewer_permissions.sql', import.meta.url),
      'utf8',
    );
    for (const boundary of [
      migration.indexOf('INSERT INTO public.operator_access_policies'),
      migration.indexOf('DELETE FROM public.dashboard_sessions WHERE user_id'),
      migration.length,
    ]) {
      await client.query('SAVEPOINT before_005');
      await client.query(migration.slice(0, boundary));
      await client.query(
        "INSERT INTO schema_migrations(name) VALUES('005_viewer_permissions.sql')",
      );
      await expect(client.query('SELECT 1/0')).rejects.toThrow();
      await client.query('ROLLBACK TO SAVEPOINT before_005');
      expect(
        (await client.query("SELECT to_regclass('public.membership_permission_grants') AS object"))
          .rows,
      ).toEqual([{ object: null }]);
      expect(
        (await client.query('SELECT token_hash FROM dashboard_sessions ORDER BY token_hash'))
          .rowCount,
      ).toBe(2);
      expect(
        (
          await client.query(
            "SELECT name FROM schema_migrations WHERE name='005_viewer_permissions.sql'",
          )
        ).rowCount,
      ).toBe(0);
    }
    await client.query(migration);
    expect(
      (await client.query('SELECT id,password_hash,auth_version FROM dashboard_users ORDER BY id'))
        .rows,
    ).toEqual(before.users);
    expect(
      (
        await client.query(
          'SELECT id,key_hash,permission,revoked_at FROM operator_api_keys ORDER BY id',
        )
      ).rows,
    ).toEqual(before.keys);
    expect((await client.query('SELECT * FROM payments')).rows).toEqual(before.payments);
    expect((await client.query('SELECT code FROM access_permissions ORDER BY code')).rows).toEqual([
      { code: 'client.account.self' },
      { code: 'client.payments.read' },
      { code: 'client.status.read' },
    ]);
    expect(
      (
        await client.query(
          'SELECT id,user_id,operator_id,role FROM dashboard_memberships ORDER BY id',
        )
      ).rows,
    ).toHaveLength(3);
    for (let i = 0; i < members.length; i++) {
      const grants = await client.query(
        'SELECT revoked_at,source FROM membership_permission_grants WHERE membership_id=$1',
        [members[i]],
      );
      expect(grants.rows).toHaveLength(2);
      for (const grant of grants.rows) {
        expect(grant.source).toBe('legacy_viewer');
        expect(grant.revoked_at === null).toBe(i === 0);
      }
    }
    expect((await client.query('SELECT user_id FROM dashboard_sessions')).rows).toEqual([
      { user_id: null },
    ]);
    expect((await authenticateOperatorKey(client as unknown as Pool, key.apiKey))?.permission).toBe(
      'read_only',
    );
    expect(await authenticateOperatorKey(client as unknown as Pool, revoked.apiKey)).toBeNull();
    for (const sql of [
      "UPDATE dashboard_memberships SET role='client_admin'",
      "INSERT INTO dashboard_sessions(token_hash,csrf_hash,user_id,membership_id,auth_version) SELECT repeat('e',64),repeat('f',64),user_id,id,1 FROM dashboard_memberships LIMIT 1",
      'DELETE FROM dashboard_memberships',
    ]) {
      await client.query('SAVEPOINT invalid');
      await expect(client.query(sql)).rejects.toThrow();
      await client.query('ROLLBACK TO SAVEPOINT invalid');
    }
  } finally {
    await client.query('ROLLBACK');
    client.release();
    await pool.end();
  }
});

it('upgrades populated viewer schema 005 to management 006 without promoting identities and rolls back on failure', async () => {
  const pool = await openUpgradeDatabase();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const names = [
      '001_initial_schema',
      '002_operator_api_keys',
      '003_api_key_permissions',
      '004_dashboard_auth',
    ];
    await client.query(
      'CREATE TABLE public.schema_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())',
    );
    for (const name of names) {
      await client.query(
        await readFile(new URL('../../migrations/' + name + '.sql', import.meta.url), 'utf8'),
      );
      await client.query('INSERT INTO schema_migrations(name) VALUES($1)', [name + '.sql']);
    }
    const op = randomUUID(),
      user = randomUUID(),
      member = randomUUID(),
      payment = randomUUID(),
      key = generateOperatorApiKey();
    await client.query("INSERT INTO operators(id,name,code) VALUES($1,'Existing client',$2)", [
      op,
      'upgrade_' + op,
    ]);
    await client.query(
      "INSERT INTO dashboard_users(id,username,password_hash) VALUES($1,$2,'unchanged-synthetic-verifier')",
      [user, 'user_' + user],
    );
    await client.query(
      'INSERT INTO dashboard_memberships(id,user_id,operator_id) VALUES($1,$2,$3)',
      [member, user, op],
    );
    await client.query(
      "INSERT INTO operator_api_keys(id,operator_id,name,key_hash,permission) VALUES($1,$2,'Existing',$3,'read_only')",
      [randomUUID(), op, key.keyHash],
    );
    await client.query(
      "INSERT INTO payments(id,operator_id,amount_minor,currency,idempotency_key) VALUES($1,$2,100,'EUR',$3)",
      [payment, op, randomUUID()],
    );
    await client.query(
      await readFile(
        new URL('../../migrations/005_viewer_permissions.sql', import.meta.url),
        'utf8',
      ),
    );
    await client.query("INSERT INTO schema_migrations(name) VALUES('005_viewer_permissions.sql')");
    const snapshot = async () => ({
      users: (await client.query('SELECT * FROM dashboard_users ORDER BY id')).rows,
      members: (await client.query('SELECT * FROM dashboard_memberships ORDER BY id')).rows,
      grants: (await client.query('SELECT * FROM membership_permission_grants ORDER BY id')).rows,
      keys: (await client.query('SELECT * FROM operator_api_keys ORDER BY id')).rows,
      payments: (await client.query('SELECT * FROM payments ORDER BY id')).rows,
    });
    const before = await snapshot();
    const migration = await readFile(
      new URL('../../migrations/006_management_foundation.sql', import.meta.url),
      'utf8',
    );
    await client.query('SAVEPOINT before_management');
    await client.query(migration);
    await client.query(
      "INSERT INTO schema_migrations(name) VALUES('006_management_foundation.sql')",
    );
    await expect(client.query('SELECT 1/0')).rejects.toThrow();
    await client.query('ROLLBACK TO SAVEPOINT before_management');
    expect(
      (await client.query("SELECT to_regclass('public.owner_principals') AS name")).rows[0].name,
    ).toBeNull();
    expect(
      (
        await client.query(
          "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='operators' AND column_name='management_version'",
        )
      ).rowCount,
    ).toBe(0);
    expect(
      (
        await client.query(
          "SELECT name FROM schema_migrations WHERE name='006_management_foundation.sql'",
        )
      ).rowCount,
    ).toBe(0);
    expect(await snapshot()).toEqual(before);
    await client.query(migration);
    expect(await snapshot()).toEqual(before);
    expect(
      (await client.query('SELECT management_version FROM operators WHERE id=$1', [op])).rows[0]
        .management_version,
    ).toBe(1);
    for (const table of [
      'owner_principals',
      'owner_permission_grants',
      'owner_sessions',
      'management_audit',
    ])
      expect(
        (await client.query(`SELECT count(*)::int AS count FROM public.${table}`)).rows[0].count,
      ).toBe(0);
    expect(
      (
        await client.query<{ code: string }>(
          'SELECT code FROM owner_permission_catalog ORDER BY code',
        )
      ).rows.map((r) => r.code),
    ).toEqual(['platform.audit.read', 'platform.clients.manage', 'platform.clients.read']);
    expect((await client.query('SELECT role FROM dashboard_memberships')).rows).toEqual([
      { role: 'viewer' },
    ]);
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
        '005_viewer_permissions.sql',
        '006_management_foundation.sql',
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
