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
      grants: (
        await client.query<Record<string, unknown>>(
          'SELECT * FROM membership_permission_grants ORDER BY id',
        )
      ).rows,
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
    // The installed 006 trigger rejects unguarded legacy metadata writes.
    await client.query('SAVEPOINT ungated_revision');
    await expect(
      client.query("UPDATE operators SET name='Not authorized' WHERE id=$1", [op]),
    ).rejects.toMatchObject({ code: '42501' });
    await client.query('ROLLBACK TO SAVEPOINT ungated_revision');
    await client.query(
      "SELECT pg_advisory_xact_lock(hashtextextended('vaultx.viewer.policy:' || $1::uuid::text,0))",
      [op],
    );
    await client.query(
      'SELECT operator_id FROM operator_access_policies WHERE operator_id=$1 FOR UPDATE',
      [op],
    );
    await client.query('SELECT id FROM dashboard_users WHERE id=$1 FOR UPDATE', [user]);
    await client.query('SELECT id FROM dashboard_memberships WHERE id=$1 FOR UPDATE', [member]);
    await client.query('SELECT id FROM operators WHERE id=$1 FOR UPDATE', [op]);
    await client.query(
      'SELECT id FROM membership_permission_grants WHERE operator_id=$1 ORDER BY membership_id,permission_code,id FOR UPDATE',
      [op],
    );
    const updated = await client.query(
      "UPDATE operators SET name='Reviewed legacy update',management_version=management_version+1 WHERE id=$1 RETURNING management_version",
      [op],
    );
    expect(updated.rows[0].management_version).toBe(2); // Never 3 from competing increments.
    expect(
      (
        await client.query(
          'UPDATE operators SET name=name,management_version=management_version+1 WHERE id=$1 RETURNING management_version',
          [op],
        )
      ).rows[0].management_version,
    ).toBe(3);
  } finally {
    await client.query('ROLLBACK');
    client.release();
    await pool.end();
  }
});

it('upgrades populated schema 006 to merchant 007 atomically without creating authority or changing viewers', async () => {
  const pool = await openUpgradeDatabase();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'CREATE TABLE public.schema_migrations(name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())',
    );
    for (const name of [
      '001_initial_schema',
      '002_operator_api_keys',
      '003_api_key_permissions',
      '004_dashboard_auth',
      '005_viewer_permissions',
      '006_management_foundation',
    ]) {
      await client.query(
        await readFile(new URL('../../migrations/' + name + '.sql', import.meta.url), 'utf8'),
      );
      await client.query('INSERT INTO public.schema_migrations(name) VALUES($1)', [name + '.sql']);
    }
    const operator = randomUUID(),
      user = randomUUID(),
      membership = randomUUID(),
      key = generateOperatorApiKey();
    await client.query('INSERT INTO operators(id,code,name) VALUES($1,$2,$3)', [
      operator,
      'upgrade_' + operator,
      'Synthetic upgrade merchant',
    ]);
    await client.query('INSERT INTO operator_access_policies(operator_id) VALUES($1)', [operator]);
    await client.query(
      "INSERT INTO operator_permission_entitlements(operator_id,permission_code) VALUES($1,'client.payments.read'),($1,'client.status.read')",
      [operator],
    );
    await client.query('INSERT INTO dashboard_users(id,username,password_hash) VALUES($1,$2,$3)', [
      user,
      'upgrade_' + user,
      'SYNTHETIC_UNUSED_HASH',
    ]);
    await client.query(
      'INSERT INTO dashboard_memberships(id,user_id,operator_id) VALUES($1,$2,$3)',
      [membership, user, operator],
    );
    await client.query(
      "INSERT INTO membership_permission_grants(id,membership_id,operator_id,permission_code) VALUES($1,$2,$3,'client.payments.read')",
      [randomUUID(), membership, operator],
    );
    await client.query(
      "INSERT INTO operator_api_keys(id,operator_id,name,key_hash,permission) VALUES($1,$2,'Synthetic',$3,'read_only')",
      [randomUUID(), operator, key.keyHash],
    );
    const grants = (
      await client.query<Record<string, unknown>>(
        'SELECT * FROM membership_permission_grants ORDER BY id',
      )
    ).rows;
    const members = (await client.query('SELECT * FROM dashboard_memberships ORDER BY id')).rows;
    const keys = (await client.query('SELECT * FROM operator_api_keys ORDER BY id')).rows;
    const migration = await readFile(
      new URL('../../migrations/007_merchant_lifecycle.sql', import.meta.url),
      'utf8',
    );
    await client.query('SAVEPOINT before_007');
    await client.query(migration);
    await client.query("INSERT INTO schema_migrations(name) VALUES('007_merchant_lifecycle.sql')");
    await expect(client.query('SELECT 1/0')).rejects.toThrow();
    await client.query('ROLLBACK TO SAVEPOINT before_007');
    expect(
      (await client.query("SELECT to_regclass('public.merchant_member_profiles') AS value")).rows[0]
        .value,
    ).toBeNull();
    expect(
      (
        await client.query(
          "SELECT code FROM owner_permission_catalog WHERE code='platform.clients.bootstrap_admin'",
        )
      ).rowCount,
    ).toBe(0);
    expect(
      (
        await client.query<Record<string, unknown>>(
          'SELECT * FROM membership_permission_grants ORDER BY id',
        )
      ).rows,
    ).toEqual(grants);
    expect(
      (
        await client.query(
          "SELECT name FROM schema_migrations WHERE name='007_merchant_lifecycle.sql'",
        )
      ).rowCount,
    ).toBe(0);
    await client.query(migration);
    expect((await client.query('SELECT * FROM dashboard_memberships ORDER BY id')).rows).toEqual(
      members,
    );
    expect((await client.query('SELECT * FROM operator_api_keys ORDER BY id')).rows).toEqual(keys);
    const upgraded = (
      await client.query<Record<string, unknown>>(
        'SELECT * FROM membership_permission_grants ORDER BY id',
      )
    ).rows;
    expect(upgraded).toEqual(
      grants.map((g) => ({ ...g, issuer_owner_id: null, sponsor_grant_id: null })),
    );
    for (const table of [
      'merchant_member_profiles',
      'merchant_invitations',
      'merchant_terminals',
      'merchant_audit',
      'owner_principals',
    ])
      expect((await client.query('SELECT count(*) AS count FROM ' + table)).rows[0].count).toBe(
        '0',
      );
    expect(
      (
        await client.query(
          'SELECT permission_code FROM operator_permission_entitlements WHERE operator_id=$1 ORDER BY permission_code',
          [operator],
        )
      ).rows,
    ).toEqual([
      { permission_code: 'client.payments.read' },
      { permission_code: 'client.status.read' },
    ]);
    expect(
      (
        await client.query(
          'SELECT source,permission_code FROM membership_permission_grants WHERE membership_id=$1',
          [membership],
        )
      ).rows,
    ).toEqual([{ source: 'legacy_viewer', permission_code: 'client.payments.read' }]);
  } finally {
    await client.query('ROLLBACK');
    client.release();
    await pool.end();
  }
});

it('upgrades populated 007 to 008 without activating accounts, preserves credentials/intents, and rolls back atomically', async () => {
  const pool = await openUpgradeDatabase(),
    client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const name of [
      '001_initial_schema',
      '002_operator_api_keys',
      '003_api_key_permissions',
      '004_dashboard_auth',
      '005_viewer_permissions',
      '006_management_foundation',
      '007_merchant_lifecycle',
    ])
      await client.query(
        await readFile(new URL('../../migrations/' + name + '.sql', import.meta.url), 'utf8'),
      );
    const operator = randomUUID(),
      user = randomUUID(),
      membership = randomUUID(),
      owner = randomUUID(),
      invitation = randomUUID(),
      key = generateOperatorApiKey();
    await client.query('INSERT INTO operators(id,code,name) VALUES($1,$2,$3)', [
      operator,
      'upgrade_' + operator,
      'Synthetic pre-008',
    ]);
    await client.query('INSERT INTO operator_access_policies(operator_id) VALUES($1)', [operator]);
    await client.query(
      "SELECT pg_advisory_xact_lock(hashtextextended('vaultx.viewer.policy:' || $1::text,0))",
      [operator],
    );
    await client.query(
      "INSERT INTO operator_permission_entitlements(operator_id,permission_code) VALUES($1,'client.status.read')",
      [operator],
    );
    await client.query('INSERT INTO dashboard_users(id,username,password_hash) VALUES($1,$2,$3)', [
      user,
      'existing_' + user,
      'SYNTHETIC_UNUSABLE_HASH',
    ]);
    await client.query(
      'INSERT INTO dashboard_memberships(id,user_id,operator_id) VALUES($1,$2,$3)',
      [membership, user, operator],
    );
    await client.query(
      "INSERT INTO membership_permission_grants(id,membership_id,operator_id,permission_code) VALUES($1,$2,$3,'client.status.read')",
      [randomUUID(), membership, operator],
    );
    await client.query(
      "INSERT INTO operator_api_keys(id,operator_id,name,key_hash,permission) VALUES($1,$2,'Synthetic existing',$3,'read_only')",
      [randomUUID(), operator, key.keyHash],
    );
    await client.query('INSERT INTO owner_principals(id,username) VALUES($1,$2)', [
      owner,
      'existing_owner_' + owner,
    ]);
    await client.query(
      "INSERT INTO merchant_invitations(id,operator_id,username,kind,owner_issuer_id,permissions) VALUES($1,$2,$3,'merchant_admin',$4,ARRAY['client.status.read'])",
      [invitation, operator, 'pending_' + invitation, owner],
    );
    const tables = [
      'dashboard_users',
      'dashboard_memberships',
      'operator_api_keys',
      'membership_permission_grants',
      'merchant_invitations',
    ];
    const before = [];
    for (const table of tables)
      before.push(await client.query(`SELECT * FROM public.${table} ORDER BY 1`));
    const migration = await readFile(
      new URL('../../migrations/008_invitation_webauthn.sql', import.meta.url),
      'utf8',
    );
    await client.query('SAVEPOINT before_008');
    await client.query(migration);
    await expect(client.query('SELECT 1/0')).rejects.toThrow();
    await client.query('ROLLBACK TO SAVEPOINT before_008');
    expect(
      (await client.query("SELECT to_regclass('public.dashboard_passkeys') AS object")).rows[0]
        .object,
    ).toBeNull();
    expect(
      (
        await client.query(
          "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='dashboard_sessions' AND column_name='webauthn_verified_at'",
        )
      ).rowCount,
    ).toBe(0);
    await client.query(migration);
    for (let i = 0; i < tables.length; i++)
      expect((await client.query(`SELECT * FROM public.${tables[i]} ORDER BY 1`)).rows).toEqual(
        before[i]!.rows,
      );
    for (const table of [
      'dashboard_passkeys',
      'dashboard_webauthn_challenges',
      'merchant_invitation_tokens',
      'merchant_enrollment_audit',
    ])
      expect((await client.query(`SELECT * FROM public.${table}`)).rowCount).toBe(0);
  } finally {
    await client.query('ROLLBACK');
    client.release();
    await pool.end();
  }
});

it('upgrades populated 008 to 009 without attribution inference and rolls back all DDL atomically', async () => {
  const pool = await openUpgradeDatabase(),
    client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const name of [
      '001_initial_schema',
      '002_operator_api_keys',
      '003_api_key_permissions',
      '004_dashboard_auth',
      '005_viewer_permissions',
      '006_management_foundation',
      '007_merchant_lifecycle',
      '008_invitation_webauthn',
    ])
      await client.query(
        await readFile(new URL('../../migrations/' + name + '.sql', import.meta.url), 'utf8'),
      );
    const operator = randomUUID(),
      payment = randomUUID(),
      terminal = randomUUID();
    await client.query(
      "INSERT INTO public.operators(id,code,name) VALUES($1,$2,'Synthetic upgrade')",
      [operator, 'upgrade_' + operator],
    );
    await client.query(
      "INSERT INTO public.payments(id,operator_id,amount_minor,currency,idempotency_key) VALUES($1,$2,100,'EUR','old-payment')",
      [payment, operator],
    );
    await client.query(
      "INSERT INTO public.merchant_terminals(id,operator_id,code,name) VALUES($1,$2,'old-terminal','Synthetic terminal')",
      [terminal, operator],
    );
    const before = (await client.query('SELECT * FROM public.payments WHERE id=$1', [payment]))
      .rows[0];
    const sql = await readFile(
      new URL('../../migrations/009_payment_terminal_attribution.sql', import.meta.url),
      'utf8',
    );
    await client.query('SAVEPOINT before_009');
    await client.query(sql);
    await expect(client.query('SELECT 1/0')).rejects.toMatchObject({ code: '22012' });
    await client.query('ROLLBACK TO SAVEPOINT before_009');
    expect(
      (
        await client.query(
          "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='payments' AND column_name='terminal_id'",
        )
      ).rowCount,
    ).toBe(0);
    expect(
      (
        await client.query(
          "SELECT to_regclass('public.payments_terminal_created_idx') AS index, to_regprocedure('public.guard_payment_terminal()') AS guard",
        )
      ).rows[0],
    ).toEqual({ index: null, guard: null });
    expect(
      (await client.query('SELECT * FROM public.payments WHERE id=$1', [payment])).rows[0],
    ).toEqual(before);
    await client.query(sql);
    expect(
      (await client.query('SELECT * FROM public.payments WHERE id=$1', [payment])).rows[0],
    ).toEqual({ ...before, terminal_id: null });
    // Function keeps invoker rights and a deterministic, qualified table lookup.
    expect(
      (
        await client.query(
          "SELECT prosecdef,proconfig FROM pg_proc WHERE oid='public.guard_payment_terminal()'::regprocedure",
        )
      ).rows[0],
    ).toEqual({ prosecdef: false, proconfig: ['search_path=pg_catalog, public, pg_temp'] });
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
        '007_merchant_lifecycle.sql',
        '008_invitation_webauthn.sql',
        '009_payment_terminal_attribution.sql',
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
