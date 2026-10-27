import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import { beforeAll, beforeEach, afterEach, afterAll, expect, it } from 'vitest';
import { executeManagement } from '../../src/management/domain.js';
import { runMigrations } from '../../src/db/migrate.js';
import { createOperatorWithApiKey } from '../../src/db/operator-keys.js';
import { openTestDatabase } from '../test-database.js';
import { createOwnerFixture, cleanupOwnerFixture } from '../management-fixtures.js';
import {
  cleanupViewerFixture,
  seedViewerFixture,
  insertViewerSession,
  policyTransaction,
} from '../viewer-policy-fixtures.js';

let pool: Pool, actor: Awaited<ReturnType<typeof createOwnerFixture>>;
let operator: string,
  foreign: string,
  user: string,
  member: string,
  foreignUser: string,
  foreignMember: string;
const extraOwners: string[] = [];
beforeAll(async () => {
  pool = await openTestDatabase();
  await runMigrations(pool);
});
beforeEach(async () => {
  actor = await createOwnerFixture(pool);
  extraOwners.length = 0;
  const first = await createOperatorWithApiKey(
    pool,
    'Management fixture',
    'mgmt_' + randomUUID(),
    'Fixture',
    'read_only',
  );
  const second = await createOperatorWithApiKey(
    pool,
    'Foreign fixture',
    'mgmt_' + randomUUID(),
    'Fixture',
    'read_only',
  );
  operator = first.operatorId;
  foreign = second.operatorId;
  user = randomUUID();
  member = randomUUID();
  foreignUser = randomUUID();
  foreignMember = randomUUID();
  for (const [u, m, o] of [
    [user, member, operator],
    [foreignUser, foreignMember, foreign],
  ]) {
    await pool.query('INSERT INTO dashboard_users(id,username,password_hash) VALUES($1,$2,$3)', [
      u,
      'management_' + u,
      'SYNTHETIC_UNUSED_HASH',
    ]);
    await pool.query('INSERT INTO dashboard_memberships(id,user_id,operator_id) VALUES($1,$2,$3)', [
      m,
      u,
      o,
    ]);
    await seedViewerFixture(pool, u!);
  }
});
afterEach(async () => {
  for (const id of [actor.id, ...extraOwners]) await cleanupOwnerFixture(pool, id);
  for (const id of [user, foreignUser]) await cleanupViewerFixture(pool, id);
  for (const id of [operator, foreign]) {
    await pool.query('DELETE FROM operator_api_keys WHERE operator_id=$1', [id]);
    await pool.query('DELETE FROM operators WHERE id=$1', [id]);
  }
});
afterAll(async () => {
  await pool.end();
});
it('keeps owner realm separate and gives no authority to a viewer/session or machine verifier', async () => {
  const token = randomBytes(32).toString('hex');
  const hash = createHash('sha256').update(token).digest('hex');
  await insertViewerSession(pool, user, hash, randomBytes(32).toString('hex'));
  expect(
    await executeManagement(pool, hash, { action: 'operators.list', limit: 10, offset: 0 }),
  ).toEqual({ ok: false, error: 'unauthorized' });
  expect(
    await executeManagement(pool, randomBytes(32).toString('hex'), {
      action: 'operators.list',
      limit: 10,
      offset: 0,
    }),
  ).toEqual({ ok: false, error: 'unauthorized' });
  const owner = await executeManagement(pool, actor.tokenHash, { action: 'identity' });
  expect(owner).toMatchObject({
    ok: true,
    value: {
      owner: { id: actor.id },
      permissions: [
        'platform.clients.read',
        'platform.clients.manage',
        'platform.clients.bootstrap_admin',
        'platform.audit.read',
      ],
    },
  });
  await expect(
    pool.query("UPDATE dashboard_memberships SET role='client_admin' WHERE id=$1", [member]),
  ).rejects.toThrow();
  await expect(
    pool.query(
      "INSERT INTO owner_permission_grants(id,owner_id,permission) VALUES($1,$2,'client.payments.read')",
      [randomUUID(), actor.id],
    ),
  ).rejects.toThrow();
});
it('enforces exact owner permissions, scoped membership IDs, and redacted DTOs', async () => {
  const reader = await createOwnerFixture(pool, ['platform.clients.read']);
  extraOwners.push(reader.id);
  const directory = await executeManagement(pool, reader.tokenHash, {
    action: 'operators.list',
    limit: 1,
    offset: 0,
  });
  expect(directory).toMatchObject({
    ok: true,
    value: { operators: expect.any(Array), pagination: { limit: 1, offset: 0, hasMore: true } },
  });
  expect(
    await executeManagement(pool, reader.tokenHash, {
      action: 'members.detail',
      targetId: operator,
      membershipId: foreignMember,
    }),
  ).toEqual({ ok: false, error: 'not_found' });
  const members = await executeManagement(pool, reader.tokenHash, {
    action: 'members.list',
    targetId: operator,
    limit: 10,
    offset: 0,
  });
  expect(members).toMatchObject({
    ok: true,
    value: { operatorId: operator, members: [{ id: member, role: 'viewer' }] },
  });
  expect(JSON.stringify(members)).not.toMatch(/username|password|token_hash|key_hash|csrf|userId/);
  expect(
    await executeManagement(pool, reader.tokenHash, {
      action: 'operators.update',
      targetId: operator,
      expectedVersion: 1,
      csrfHash: reader.csrfHash,
      patch: { name: 'Denied' },
    }),
  ).toEqual({ ok: false, error: 'forbidden' });
  expect(
    await executeManagement(pool, reader.tokenHash, { action: 'audit.list', limit: 10, offset: 0 }),
  ).toEqual({ ok: false, error: 'forbidden' });
});
it('requires fresh MFA, CSRF and expected versions; atomically audits metadata updates', async () => {
  const command = {
    action: 'operators.update' as const,
    targetId: operator,
    expectedVersion: 1,
    csrfHash: actor.csrfHash,
    patch: { name: 'Updated fixture' },
  };
  expect(
    await executeManagement(pool, actor.tokenHash, { ...command, csrfHash: '0'.repeat(64) }),
  ).toEqual({ ok: false, error: 'forbidden' });
  await pool.query(
    "UPDATE owner_sessions SET mfa_verified_at=clock_timestamp()-interval '6 minutes',created_at=clock_timestamp()-interval '10 minutes' WHERE token_hash=$1",
    [actor.tokenHash],
  );
  expect(await executeManagement(pool, actor.tokenHash, command)).toEqual({
    ok: false,
    error: 'forbidden',
  });
  await pool.query(
    'UPDATE owner_sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1',
    [actor.tokenHash],
  );
  expect(await executeManagement(pool, actor.tokenHash, command)).toMatchObject({
    ok: true,
    value: { operator: { name: 'Updated fixture', version: 2 } },
  });
  expect(await executeManagement(pool, actor.tokenHash, command)).toEqual({
    ok: false,
    error: 'conflict',
  });
  const events = await pool.query(
    'SELECT action,summary,target_version FROM management_audit WHERE actor_id=$1',
    [actor.id],
  );
  const context = (
    await pool.query(
      'SELECT outcome,owner_policy_version,mfa_verified_at,request_id FROM management_audit WHERE actor_id=$1',
      [actor.id],
    )
  ).rows[0];
  expect(context).toMatchObject({
    outcome: 'success',
    owner_policy_version: 1,
    mfa_verified_at: expect.any(Date),
    request_id: expect.stringMatching(/^[A-Za-z0-9._:-]{1,80}$/),
  });
  expect(events.rows).toEqual([
    {
      action: 'operators.update',
      summary: { nameChanged: true, status: 'active', version: 2 },
      target_version: 2,
    },
  ]);
});
it('withdraws ceilings once, permanently revokes grants and invalidates viewer sessions', async () => {
  const token = randomBytes(32).toString('hex');
  await insertViewerSession(pool, user, token, randomBytes(32).toString('hex'));
  const command = {
    action: 'entitlements.withdraw' as const,
    targetId: operator,
    expectedVersion: 1,
    csrfHash: actor.csrfHash,
    permission: 'client.payments.read' as const,
  };
  expect(await executeManagement(pool, actor.tokenHash, command)).toMatchObject({
    ok: true,
    value: { operator: { version: 2 }, policyVersion: 2 },
  });
  expect(await executeManagement(pool, actor.tokenHash, command)).toEqual({
    ok: false,
    error: 'conflict',
  });
  expect(
    (await pool.query('SELECT token_hash FROM dashboard_sessions WHERE user_id=$1', [user]))
      .rowCount,
  ).toBe(0);
  const grants = await pool.query(
    'SELECT permission_code,revoked_at FROM membership_permission_grants WHERE membership_id=$1 ORDER BY permission_code',
    [member],
  );
  expect(grants.rows[0].revoked_at).toBeInstanceOf(Date);
  expect(grants.rows[1].revoked_at).toBeNull();
  expect(
    (
      await pool.query(
        'SELECT enabled FROM operator_permission_entitlements WHERE operator_id=$1 AND permission_code=$2',
        [foreign, 'client.payments.read'],
      )
    ).rows[0].enabled,
  ).toBe(true);
});
it('suspension and reactivation preserve revoked human history and machine scopes', async () => {
  const before = (
    await pool.query(
      'SELECT id,key_hash,permission,revoked_at FROM operator_api_keys WHERE operator_id=$1',
      [operator],
    )
  ).rows;
  expect(
    await executeManagement(pool, actor.tokenHash, {
      action: 'operators.update',
      targetId: operator,
      expectedVersion: 1,
      csrfHash: actor.csrfHash,
      patch: { status: 'suspended' },
    }),
  ).toMatchObject({ ok: true, value: { operator: { version: 2, status: 'suspended' } } });
  expect(
    await executeManagement(pool, actor.tokenHash, {
      action: 'operators.update',
      targetId: operator,
      expectedVersion: 2,
      csrfHash: actor.csrfHash,
      patch: { status: 'active' },
    }),
  ).toMatchObject({ ok: true, value: { operator: { version: 3, status: 'active' } } });
  expect(
    (
      await pool.query(
        'SELECT id FROM membership_permission_grants WHERE operator_id=$1 AND revoked_at IS NULL',
        [operator],
      )
    ).rowCount,
  ).toBe(0);
  expect(
    (
      await pool.query(
        'SELECT id,key_hash,permission,revoked_at FROM operator_api_keys WHERE operator_id=$1',
        [operator],
      )
    ).rows,
  ).toEqual(before);
});
it('serializes concurrent optimistic edits so exactly one version wins', async () => {
  const command = {
    action: 'operators.update' as const,
    targetId: operator,
    expectedVersion: 1,
    csrfHash: actor.csrfHash,
    patch: { name: 'First' },
  };
  const results = await Promise.all([
    executeManagement(pool, actor.tokenHash, command),
    executeManagement(pool, actor.tokenHash, { ...command, patch: { name: 'Second' } }),
  ]);
  expect(results.filter((result) => result.ok)).toHaveLength(1);
  expect(results.filter((result) => !result.ok)).toEqual([{ ok: false, error: 'conflict' }]);
  expect(
    (await pool.query('SELECT id FROM management_audit WHERE actor_id=$1', [actor.id])).rowCount,
  ).toBe(1);
});
it('fails closed and rolls back mutation when mandatory audit insertion fails', async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL lock_timeout='2000ms'");
    await client.query('LOCK TABLE management_audit IN ACCESS EXCLUSIVE MODE');
    const result = await executeManagement(pool, actor.tokenHash, {
      action: 'operators.update',
      targetId: operator,
      expectedVersion: 1,
      csrfHash: actor.csrfHash,
      patch: { name: 'Must roll back' },
    });
    expect(result).toEqual({ ok: false, error: 'unavailable' });
    await client.query('ROLLBACK');
    expect(
      (await pool.query('SELECT name,management_version FROM operators WHERE id=$1', [operator]))
        .rows[0],
    ).toEqual({ name: 'Management fixture', management_version: 1 });
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
});
it('rejects owner permission revocation resurrection and invalidates the old owner session', async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended('vaultx.owner.policy',0))");
    await client.query('SELECT id FROM owner_principals WHERE id=$1 FOR UPDATE', [actor.id]);
    await client.query(
      "UPDATE owner_permission_grants SET revoked_at=statement_timestamp() WHERE owner_id=$1 AND permission='platform.clients.read'",
      [actor.id],
    );
    await client.query('COMMIT');
    expect(await executeManagement(pool, actor.tokenHash, { action: 'identity' })).toEqual({
      ok: false,
      error: 'unauthorized',
    });
    await client.query('BEGIN');
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended('vaultx.owner.policy',0))");
    await expect(
      client.query(
        "UPDATE owner_permission_grants SET revoked_at=NULL WHERE owner_id=$1 AND permission='platform.clients.read'",
        [actor.id],
      ),
    ).rejects.toThrow();
    await client.query('ROLLBACK');
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
});
it('prevents audit UPDATE, DELETE, TRUNCATE and privilege-boundary DDL', async () => {
  await executeManagement(pool, actor.tokenHash, {
    action: 'operators.detail',
    targetId: operator,
  });
  for (const sql of [
    'UPDATE management_audit SET summary=summary',
    'DELETE FROM management_audit',
    'TRUNCATE management_audit',
  ])
    await expect(pool.query(sql)).rejects.toMatchObject({ code: '42501' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Role already exists only inside the isolated runner; role grants roll back.
    await client.query('GRANT SELECT,INSERT ON management_audit TO vaultx_viewer_runtime');
    await client.query('SET LOCAL ROLE vaultx_viewer_runtime');
    await expect(
      client.query('ALTER TABLE management_audit DISABLE TRIGGER management_audit_immutable'),
    ).rejects.toMatchObject({ code: '42501' });
    await client.query('ROLLBACK');
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
});
it('bounds pagination and preserves session expiry and logout/CSRF semantics', async () => {
  expect(
    await executeManagement(pool, actor.tokenHash, {
      action: 'operators.list',
      limit: 1000,
      offset: 0,
    }),
  ).toEqual({ ok: false, error: 'invalid_input' });
  const freshHash = randomBytes(32).toString('hex');
  expect(
    await executeManagement(pool, actor.tokenHash, {
      action: 'csrf.rotate',
      newCsrfHash: freshHash,
    }),
  ).toEqual({ ok: true, value: undefined });
  expect(
    await executeManagement(pool, actor.tokenHash, { action: 'logout', csrfHash: actor.csrfHash }),
  ).toEqual({ ok: false, error: 'forbidden' });
  expect(
    await executeManagement(pool, actor.tokenHash, { action: 'logout', csrfHash: freshHash }),
  ).toEqual({ ok: true, value: undefined });
  expect(await executeManagement(pool, actor.tokenHash, { action: 'identity' })).toEqual({
    ok: false,
    error: 'unauthorized',
  });
});

it('executes real owner reads as a restricted runtime role without policy, identity, audit rewrite or DDL rights', async () => {
  const role = 'vaultx_management_runtime';
  await pool.query(`GRANT USAGE ON SCHEMA public TO ${role}`);
  await pool.query(
    `GRANT SELECT ON management_policy,owner_permission_catalog,owner_principals,owner_permission_grants,owner_sessions,operators,operator_access_policies,dashboard_memberships,membership_permission_grants,management_audit TO ${role}`,
  );
  await pool.query(
    `GRANT UPDATE(id) ON management_policy,owner_principals,owner_permission_grants,operators TO ${role}`,
  );
  await pool.query(`GRANT UPDATE(operator_id) ON operator_access_policies TO ${role}`);
  await pool.query(`GRANT UPDATE(last_seen_at,csrf_hash),DELETE ON owner_sessions TO ${role}`);
  await pool.query(`GRANT INSERT ON management_audit TO ${role}`);
  const runtime = new Pool({
    ...pool.options,
    // pg intentionally makes password non-enumerable: object spread omits it.
    // Reuse only this already-verified disposable pool's credential, never PG env.
    password: pool.options.password,
    options: (pool.options.options ?? '') + ' -c role=' + role,
  });
  try {
    expect(await executeManagement(runtime, actor.tokenHash, { action: 'identity' })).toMatchObject(
      { ok: true, value: { owner: { id: actor.id } } },
    );
    expect(
      await executeManagement(runtime, actor.tokenHash, {
        action: 'operators.detail',
        targetId: operator,
      }),
    ).toMatchObject({ ok: true, value: { operator: { id: operator } } });
    expect(
      await executeManagement(runtime, actor.tokenHash, {
        action: 'members.list',
        targetId: operator,
        limit: 10,
        offset: 0,
      }),
    ).toMatchObject({ ok: true, value: { members: [{ id: member }] } });
    for (const sql of [
      'UPDATE management_audit SET summary=summary',
      'DELETE FROM management_audit',
      'TRUNCATE management_audit',
      'ALTER TABLE management_audit DISABLE TRIGGER management_audit_immutable',
      'CREATE TABLE public.management_forbidden(id int)',
      "UPDATE owner_principals SET status='active'",
      'UPDATE owner_principals SET id=id',
      'UPDATE owner_permission_grants SET revoked_at=statement_timestamp()',
      'UPDATE owner_permission_grants SET id=id',
      'UPDATE management_policy SET id=id',
      'UPDATE operator_access_policies SET authorization_version=authorization_version+1',
      'UPDATE operator_permission_entitlements SET enabled=true',
      'INSERT INTO owner_permission_grants(id,owner_id,permission) SELECT id,owner_id,permission FROM owner_permission_grants',
    ])
      await expect(runtime.query(sql)).rejects.toMatchObject({ code: '42501' });
    expect(
      await executeManagement(runtime, actor.tokenHash, {
        action: 'operators.update',
        targetId: operator,
        expectedVersion: 1,
        csrfHash: actor.csrfHash,
        patch: { name: 'Denied by SQL privilege' },
      }),
    ).toEqual({ ok: false, error: 'unavailable' });
  } finally {
    await runtime.end();
    await pool.query(
      `REVOKE ALL ON management_policy,owner_permission_catalog,owner_principals,owner_permission_grants,owner_sessions,operators,operator_access_policies,dashboard_memberships,membership_permission_grants,management_audit FROM ${role}`,
    );
    // Table-level REVOKE does not remove column privileges.
    await pool.query(
      `REVOKE UPDATE(id) ON management_policy,owner_principals,owner_permission_grants,operators FROM ${role}`,
    );
    await pool.query(`REVOKE UPDATE(operator_id) ON operator_access_policies FROM ${role}`);
    await pool.query(`REVOKE UPDATE(last_seen_at,csrf_hash) ON owner_sessions FROM ${role}`);
  }
});

it('consumes a metadata version even for no-op edits, preventing audit replay', async () => {
  const command = {
    action: 'operators.update' as const,
    targetId: operator,
    expectedVersion: 1,
    csrfHash: actor.csrfHash,
    patch: { name: 'Management fixture' },
  };
  expect(await executeManagement(pool, actor.tokenHash, command)).toMatchObject({
    ok: true,
    value: { operator: { version: 2 } },
  });
  expect(await executeManagement(pool, actor.tokenHash, command)).toEqual({
    ok: false,
    error: 'conflict',
  });
  expect(
    (await pool.query('SELECT id FROM management_audit WHERE actor_id=$1', [actor.id])).rowCount,
  ).toBe(1);
});

for (const boundary of ['idle', 'mfa'] as const) {
  it(`rechecks ${boundary} expiry after tenant locking rather than refreshing a stale authorization`, async () => {
    const holder = await pool.connect();
    try {
      await holder.query('BEGIN');
      await holder.query(
        "SELECT pg_advisory_xact_lock(hashtextextended('vaultx.viewer.policy:' || $1::uuid::text,0))",
        [operator],
      );
      const deadline = (
        await pool.query<{ deadline: Date }>(
          boundary === 'idle'
            ? "UPDATE owner_sessions SET last_seen_at=clock_timestamp()-interval '15 minutes'+interval '750 milliseconds' WHERE token_hash=$1 RETURNING last_seen_at+interval '15 minutes' AS deadline"
            : "UPDATE owner_sessions SET mfa_verified_at=clock_timestamp()-interval '5 minutes'+interval '750 milliseconds' WHERE token_hash=$1 RETURNING mfa_verified_at+interval '5 minutes' AS deadline",
          [actor.tokenHash],
        )
      ).rows[0]!.deadline;
      const result = executeManagement(pool, actor.tokenHash, {
        action: 'operators.update',
        targetId: operator,
        expectedVersion: 1,
        csrfHash: actor.csrfHash,
        patch: { name: 'Expired write must not commit' },
      });
      let queued = false;
      for (let i = 0; i < 200; i++) {
        const locks = await holder.query<{ waiting: boolean }>(
          "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())) AS waiting",
        );
        if (locks.rows[0]?.waiting) {
          queued = true;
          break;
        }
      }
      expect(queued).toBe(true);
      // Explicit database-clock barrier: release only after the authorization
      // deadline crossed, never an arbitrary sleep selecting an interleaving.
      for (const started = Date.now(); Date.now() - started < 1500;) {
        const clock = await holder.query<{ expired: boolean }>(
          'SELECT clock_timestamp()>=$1::timestamptz AS expired',
          [deadline],
        );
        if (clock.rows[0]?.expired) break;
      }
      expect(
        (
          await holder.query<{ expired: boolean }>(
            'SELECT clock_timestamp()>=$1::timestamptz AS expired',
            [deadline],
          )
        ).rows[0]?.expired,
      ).toBe(true);
      await holder.query('COMMIT');
      expect(await result).toEqual({
        ok: false,
        error: boundary === 'idle' ? 'unauthorized' : 'forbidden',
      });
      expect(
        (await pool.query('SELECT name,management_version FROM operators WHERE id=$1', [operator]))
          .rows[0],
      ).toEqual({ name: 'Management fixture', management_version: 1 });
      expect(
        (await pool.query('SELECT id FROM management_audit WHERE actor_id=$1', [actor.id]))
          .rowCount,
      ).toBe(0);
    } finally {
      await holder.query('ROLLBACK');
      holder.release();
    }
  });
}

it('rolls back mutation and its audit if the session expires while the mandatory audit waits', async () => {
  const holder = await pool.connect();
  try {
    await holder.query('BEGIN');
    await holder.query('LOCK TABLE management_audit IN ACCESS EXCLUSIVE MODE');
    const deadline = (
      await pool.query<{ deadline: Date }>(
        "UPDATE owner_sessions SET last_seen_at=clock_timestamp()-interval '15 minutes'+interval '750 milliseconds' WHERE token_hash=$1 RETURNING last_seen_at+interval '15 minutes' AS deadline",
        [actor.tokenHash],
      )
    ).rows[0]!.deadline;
    const result = executeManagement(pool, actor.tokenHash, {
      action: 'operators.update',
      targetId: operator,
      expectedVersion: 1,
      csrfHash: actor.csrfHash,
      patch: { name: 'Must roll back after audit' },
    });
    let queued = false;
    for (let i = 0; i < 200; i++) {
      const locks = await holder.query<{ waiting: boolean }>(
        "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='public.management_audit'::regclass AND NOT granted) AS waiting",
      );
      if (locks.rows[0]?.waiting) {
        queued = true;
        break;
      }
    }
    expect(queued).toBe(true);
    for (const started = Date.now(); Date.now() - started < 1500;) {
      if (
        (
          await holder.query<{ expired: boolean }>(
            'SELECT clock_timestamp()>=$1::timestamptz AS expired',
            [deadline],
          )
        ).rows[0]?.expired
      )
        break;
    }
    expect(
      (
        await holder.query<{ expired: boolean }>(
          'SELECT clock_timestamp()>=$1::timestamptz AS expired',
          [deadline],
        )
      ).rows[0]?.expired,
    ).toBe(true);
    await holder.query('COMMIT');
    expect(await result).toEqual({ ok: false, error: 'unavailable' });
    expect(
      (await pool.query('SELECT name,management_version FROM operators WHERE id=$1', [operator]))
        .rows[0],
    ).toEqual({ name: 'Management fixture', management_version: 1 });
    expect(
      (await pool.query('SELECT id FROM management_audit WHERE actor_id=$1', [actor.id])).rowCount,
    ).toBe(0);
  } finally {
    await holder.query('ROLLBACK');
    holder.release();
  }
});

it('fails closed when an existing target has no tenant policy row and never repairs it', async () => {
  const target = randomUUID();
  await pool.query("INSERT INTO operators(id,name,code) VALUES($1,'Uninitialized client',$2)", [
    target,
    'unknown_policy_' + target,
  ]);
  try {
    expect(
      await executeManagement(pool, actor.tokenHash, {
        action: 'operators.detail',
        targetId: target,
      }),
    ).toEqual({ ok: false, error: 'unavailable' });
    expect(
      await executeManagement(pool, actor.tokenHash, {
        action: 'operators.update',
        targetId: target,
        expectedVersion: 1,
        csrfHash: actor.csrfHash,
        patch: { status: 'suspended' },
      }),
    ).toEqual({ ok: false, error: 'unavailable' });
    expect(
      (await pool.query('SELECT status,management_version FROM operators WHERE id=$1', [target]))
        .rows[0],
    ).toEqual({ status: 'active', management_version: 1 });
    expect(
      (
        await pool.query('SELECT operator_id FROM operator_access_policies WHERE operator_id=$1', [
          target,
        ])
      ).rowCount,
    ).toBe(0);
    expect(
      await executeManagement(pool, actor.tokenHash, {
        action: 'operators.detail',
        targetId: randomUUID(),
      }),
    ).toEqual({ ok: false, error: 'not_found' });
  } finally {
    await pool.query('DELETE FROM operators WHERE id=$1', [target]);
  }
});

it('advances the canonical operator revision exactly once for a combined metadata/status edit and an API no-op', async () => {
  const combined = {
    action: 'operators.update' as const,
    targetId: operator,
    expectedVersion: 1,
    csrfHash: actor.csrfHash,
    patch: { name: 'Combined revision fixture', status: 'suspended' as const },
  };
  expect(await executeManagement(pool, actor.tokenHash, combined)).toMatchObject({
    ok: true,
    value: { operator: { name: combined.patch.name, status: 'suspended', version: 2 } },
  });
  expect(
    await executeManagement(pool, actor.tokenHash, { ...combined, expectedVersion: 2 }),
  ).toMatchObject({
    ok: true,
    value: { operator: { name: combined.patch.name, status: 'suspended', version: 3 } },
  });
  expect(
    await executeManagement(pool, actor.tokenHash, { ...combined, expectedVersion: 2 }),
  ).toEqual({
    ok: false,
    error: 'conflict',
  });
  expect(
    (await pool.query('SELECT management_version FROM operators WHERE id=$1', [operator])).rows[0]
      .management_version,
  ).toBe(3);
  const events = await pool.query(
    'SELECT target_version,summary FROM management_audit WHERE actor_id=$1 ORDER BY target_version',
    [actor.id],
  );
  expect(events.rows).toEqual([
    { target_version: 2, summary: { nameChanged: true, status: 'suspended', version: 2 } },
    { target_version: 3, summary: { nameChanged: true, status: 'suspended', version: 3 } },
  ]);
});

it('records distinct operator and policy revisions when withdrawing after multiple metadata and status edits', async () => {
  const patches = [
    { name: 'First revision fixture' },
    { name: 'Second revision fixture' },
    { status: 'suspended' as const },
    { status: 'active' as const },
    { name: 'Third revision fixture' },
  ];
  for (const [index, patch] of patches.entries()) {
    expect(
      await executeManagement(pool, actor.tokenHash, {
        action: 'operators.update',
        targetId: operator,
        expectedVersion: index + 1,
        csrfHash: actor.csrfHash,
        patch,
      }),
    ).toMatchObject({ ok: true, value: { operator: { version: index + 2 } } });
  }
  expect(
    (await pool.query('SELECT management_version FROM operators WHERE id=$1', [operator])).rows[0]
      .management_version,
  ).toBe(6);
  expect(
    (
      await pool.query(
        'SELECT authorization_version FROM operator_access_policies WHERE operator_id=$1',
        [operator],
      )
    ).rows[0].authorization_version,
  ).toBe(3);
  const command = {
    action: 'entitlements.withdraw' as const,
    targetId: operator,
    expectedVersion: 6,
    csrfHash: actor.csrfHash,
    permission: 'client.payments.read' as const,
  };
  expect(await executeManagement(pool, actor.tokenHash, command)).toMatchObject({
    ok: true,
    value: { operator: { version: 7 }, policyVersion: 4 },
  });
  expect(await executeManagement(pool, actor.tokenHash, command)).toEqual({
    ok: false,
    error: 'conflict',
  });
  const persisted = (
    await pool.query('SELECT management_version FROM operators WHERE id=$1', [operator])
  ).rows[0].management_version;
  const policy = (
    await pool.query(
      'SELECT authorization_version FROM operator_access_policies WHERE operator_id=$1',
      [operator],
    )
  ).rows[0].authorization_version;
  expect(persisted).toBe(7);
  expect(policy).toBe(4);
  const events = await pool.query(
    "SELECT target_version,summary FROM management_audit WHERE actor_id=$1 AND action='entitlements.withdraw'",
    [actor.id],
  );
  expect(events.rows).toEqual([
    {
      target_version: persisted,
      summary: { permission: 'client.payments.read', version: persisted, policyVersion: policy },
    },
  ]);
});

it('rejects revision jumps, reductions and null proposals even with metadata changes and a legitimate pre-gate', async () => {
  for (const proposal of ['management_version+2', 'management_version-1', 'NULL']) {
    await expect(
      policyTransaction(pool, operator, (client) =>
        client.query(
          `UPDATE operators SET name='Rejected revision fixture',status='suspended',management_version=${proposal} WHERE id=$1`,
          [operator],
        ),
      ),
    ).rejects.toMatchObject({ code: '42501' });
    expect(
      (
        await pool.query('SELECT name,status,management_version FROM operators WHERE id=$1', [
          operator,
        ])
      ).rows[0],
    ).toEqual({ name: 'Management fixture', status: 'active', management_version: 1 });
    expect(
      (
        await pool.query(
          'SELECT authorization_version FROM operator_access_policies WHERE operator_id=$1',
          [operator],
        )
      ).rows[0].authorization_version,
    ).toBe(1);
    expect(
      (
        await pool.query(
          'SELECT id FROM membership_permission_grants WHERE operator_id=$1 AND revoked_at IS NULL',
          [operator],
        )
      ).rowCount,
    ).toBe(2);
  }
  await expect(
    pool.query("UPDATE operators SET name='Missing gate' WHERE id=$1", [operator]),
  ).rejects.toMatchObject({ code: '42501' });
  await expect(
    pool.query('UPDATE operators SET management_version=management_version+1 WHERE id=$1', [
      operator,
    ]),
  ).rejects.toMatchObject({ code: '42501' });
  // An SQL no-op makes no policy/metadata change and does not consume a revision.
  expect(
    (
      await pool.query(
        'UPDATE operators SET name=name,management_version=management_version WHERE id=$1 RETURNING management_version',
        [operator],
      )
    ).rows[0].management_version,
  ).toBe(1);
  const implicit = await policyTransaction(pool, operator, (client) =>
    client.query(
      "UPDATE operators SET name='Implicit canonical revision' WHERE id=$1 RETURNING management_version",
      [operator],
    ),
  );
  expect(implicit.rows[0].management_version).toBe(2);
  const explicit = await policyTransaction(pool, operator, (client) =>
    client.query(
      "UPDATE operators SET name='Explicit canonical revision',status='suspended',management_version=management_version+1 WHERE id=$1 RETURNING management_version",
      [operator],
    ),
  );
  // The application proposes OLD+1; the trigger must not add a second increment.
  expect(explicit.rows[0].management_version).toBe(3);
  expect(
    (await pool.query('SELECT management_version FROM operators WHERE id=$1', [operator])).rows[0]
      .management_version,
  ).toBe(3);
});

it('counts a pre-gated maintenance withdrawal once and invalidates stale administrative forms', async () => {
  const viewer = randomBytes(32).toString('hex');
  await insertViewerSession(pool, user, viewer, randomBytes(32).toString('hex'));
  await policyTransaction(pool, operator, (client) =>
    client.query(
      "UPDATE operator_permission_entitlements SET enabled=false WHERE operator_id=$1 AND permission_code='client.payments.read'",
      [operator],
    ),
  );
  expect(
    (await pool.query('SELECT management_version FROM operators WHERE id=$1', [operator])).rows[0]
      .management_version,
  ).toBe(2);
  expect(
    (await pool.query('SELECT token_hash FROM dashboard_sessions WHERE user_id=$1', [user]))
      .rowCount,
  ).toBe(0);
  await policyTransaction(pool, operator, (client) =>
    client.query(
      "UPDATE operator_permission_entitlements SET enabled=false WHERE operator_id=$1 AND permission_code='client.payments.read'",
      [operator],
    ),
  );
  expect(
    (await pool.query('SELECT management_version FROM operators WHERE id=$1', [operator])).rows[0]
      .management_version,
  ).toBe(2);
  expect(
    await executeManagement(pool, actor.tokenHash, {
      action: 'operators.update',
      targetId: operator,
      expectedVersion: 1,
      csrfHash: actor.csrfHash,
      patch: { name: 'Stale after maintenance' },
    }),
  ).toEqual({ ok: false, error: 'conflict' });
  expect(
    await executeManagement(pool, actor.tokenHash, {
      action: 'entitlements.withdraw',
      targetId: operator,
      expectedVersion: 2,
      csrfHash: actor.csrfHash,
      permission: 'client.status.read',
    }),
  ).toMatchObject({ ok: true, value: { operator: { version: 3 }, policyVersion: 3 } });
  expect(
    (
      await pool.query('SELECT target_version,summary FROM management_audit WHERE actor_id=$1', [
        actor.id,
      ])
    ).rows,
  ).toEqual([
    {
      target_version: 3,
      summary: { permission: 'client.status.read', version: 3, policyVersion: 3 },
    },
  ]);
  expect(
    (
      await pool.query(
        'SELECT id FROM membership_permission_grants WHERE membership_id=$1 AND revoked_at IS NULL',
        [member],
      )
    ).rowCount,
  ).toBe(0);
});
