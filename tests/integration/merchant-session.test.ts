import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, expect, it } from 'vitest';
import { effectiveViewerPermissions } from '../../src/dashboard/permissions.js';
import { effectiveMerchantPermissions } from '../../src/management/merchant-domain.js';
import { runMigrations } from '../../src/db/migrate.js';
import { createMerchant, MERCHANT_PERMISSIONS } from '../../src/management/merchant-domain.js';
import { executeMerchantCommand } from '../../src/management/merchant-session.js';
import { openTestDatabase } from '../test-database.js';
import {
  createOwnerFixture,
  cleanupOwnerFixture,
  managementFixtureGuard,
} from '../management-fixtures.js';
import { insertViewerSession, policyTransaction } from '../viewer-policy-fixtures.js';
let pool: Pool, owner: Awaited<ReturnType<typeof createOwnerFixture>>;
let operator: string, foreign: string, admin: string, child: string, otherChild: string;
let adminUser: string, childUser: string, viewerUser: string;
let token: string, csrf: string;
beforeAll(async () => {
  pool = await openTestDatabase();
  await runMigrations(pool);
});
afterAll(async () => {
  await pool.end();
});
beforeEach(async () => {
  owner = await createOwnerFixture(pool);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    operator = (
      await createMerchant(client, {
        ownerId: owner.id,
        code: 'sessions_' + randomUUID(),
        name: 'Synthetic merchant session',
      })
    ).operator.id;
    foreign = (
      await createMerchant(client, {
        ownerId: owner.id,
        code: 'foreign_' + randomUUID(),
        name: 'Foreign synthetic merchant',
      })
    ).operator.id;
    [admin, adminUser] = await member(client, operator, 'merchant_admin');
    for (const permission of MERCHANT_PERMISSIONS)
      await rootGrant(client, admin, operator, permission);
    [child, childUser] = await member(client, operator, 'submerchant', admin);
    [, viewerUser] = await member(client, operator);
    const [foreignAdmin] = await member(client, foreign, 'merchant_admin');
    for (const permission of MERCHANT_PERMISSIONS)
      await rootGrant(client, foreignAdmin, foreign, permission);
    [otherChild] = await member(client, foreign, 'submerchant', foreignAdmin);
    const source = (
      await client.query(
        "SELECT id FROM membership_permission_grants WHERE membership_id=$1 AND permission_code='client.payments.read'",
        [admin],
      )
    ).rows[0].id;
    await client.query(
      "INSERT INTO membership_permission_grants(id,membership_id,operator_id,permission_code,source,sponsor_grant_id) VALUES($1,$2,$3,'client.payments.read','merchant_delegation',$4)",
      [randomUUID(), child, operator, source],
    );
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
  token = randomBytes(32).toString('hex');
  csrf = randomBytes(32).toString('hex');
  await insertViewerSession(pool, adminUser, token, csrf);
});
afterEach(async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await managementFixtureGuard(client);
    for (const [table, trigger] of [
      ['merchant_audit', 'merchant_audit_immutable'],
      ['merchant_invitations', 'merchant_invitation_history'],
      ['merchant_member_profiles', 'merchant_profile_history'],
    ])
      await client.query(`ALTER TABLE public.${table} DISABLE TRIGGER ${trigger}`);
    await client.query('DELETE FROM merchant_audit WHERE operator_id=ANY($1::uuid[])', [
      [operator, foreign],
    ]);
    await client.query('DELETE FROM merchant_invitations WHERE operator_id=ANY($1::uuid[])', [
      [operator, foreign],
    ]);
    await client.query(
      'DELETE FROM membership_permission_grants WHERE operator_id=ANY($1::uuid[])',
      [[operator, foreign]],
    );
    await client.query('DELETE FROM merchant_member_profiles WHERE operator_id=ANY($1::uuid[])', [
      [operator, foreign],
    ]);
    await client.query(
      'DELETE FROM dashboard_users WHERE id IN(SELECT user_id FROM dashboard_memberships WHERE operator_id=ANY($1::uuid[]))',
      [[operator, foreign]],
    );
    await client.query(
      'DELETE FROM operator_permission_entitlements WHERE operator_id=ANY($1::uuid[])',
      [[operator, foreign]],
    );
    await client.query('DELETE FROM operator_access_policies WHERE operator_id=ANY($1::uuid[])', [
      [operator, foreign],
    ]);
    await client.query('DELETE FROM operators WHERE id=ANY($1::uuid[])', [[operator, foreign]]);
    for (const [table, trigger] of [
      ['merchant_audit', 'merchant_audit_immutable'],
      ['merchant_invitations', 'merchant_invitation_history'],
      ['merchant_member_profiles', 'merchant_profile_history'],
    ])
      await client.query(`ALTER TABLE public.${table} ENABLE TRIGGER ${trigger}`);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
  await cleanupOwnerFixture(pool, owner.id);
});
async function member(
  client: PoolClient,
  tenant: string,
  kind?: 'merchant_admin' | 'submerchant',
  sponsor?: string,
): Promise<[string, string]> {
  const user = randomUUID(),
    id = randomUUID();
  await client.query('INSERT INTO dashboard_users(id,username,password_hash) VALUES($1,$2,$3)', [
    user,
    'synthetic_' + user,
    'SYNTHETIC_UNUSED_HASH',
  ]);
  await client.query('INSERT INTO dashboard_memberships(id,user_id,operator_id) VALUES($1,$2,$3)', [
    id,
    user,
    tenant,
  ]);
  if (kind)
    await client.query(
      'INSERT INTO merchant_member_profiles(membership_id,operator_id,kind,owner_issuer_id,sponsor_membership_id) VALUES($1,$2,$3,$4,$5)',
      [id, tenant, kind, kind === 'merchant_admin' ? owner.id : null, sponsor ?? null],
    );
  return [id, user];
}
async function rootGrant(
  client: PoolClient,
  membership: string,
  tenant: string,
  permission: string,
) {
  await client.query(
    "INSERT INTO membership_permission_grants(id,membership_id,operator_id,permission_code,source,issuer_owner_id) VALUES($1,$2,$3,$4,'owner_bootstrap',$5)",
    [randomUUID(), membership, tenant, permission, owner.id],
  );
}
async function version(id: string) {
  return Number(
    (await pool.query('SELECT authorization_version FROM dashboard_memberships WHERE id=$1', [id]))
      .rows[0].authorization_version,
  );
}
it('denies ordinary viewers, submerchant sessions and forged operator authority', async () => {
  const viewerToken = randomBytes(32).toString('hex'),
    childToken = randomBytes(32).toString('hex');
  await insertViewerSession(pool, viewerUser, viewerToken, csrf);
  await insertViewerSession(pool, childUser, childToken, csrf);
  for (const t of [
    viewerToken,
    childToken,
    createHash('sha256').update('not-a-session').digest('hex'),
  ])
    expect(
      await executeMerchantCommand(pool, t, { action: 'members.list', limit: 50, offset: 0 }),
    ).toEqual({ ok: false, error: 'unauthorized' });
  expect(
    await executeMerchantCommand(pool, token, {
      action: 'members.list',
      limit: 50,
      offset: 0,
      operatorId: foreign,
    } as never),
  ).toEqual({ ok: false, error: 'invalid_input' });
});
it('reads only current merchant members and persists sanitized mandatory read audit', async () => {
  const result = await executeMerchantCommand(pool, token, {
    action: 'members.list',
    limit: 50,
    offset: 0,
  });
  expect(result.ok).toBe(true);
  expect(JSON.stringify(result)).toContain(child);
  expect(JSON.stringify(result)).not.toContain(otherChild);
  const rows = await pool.query('SELECT summary,action FROM merchant_audit WHERE operator_id=$1', [
    operator,
  ]);
  expect(rows.rows).toHaveLength(1);
  expect(rows.rows[0]).toEqual({ summary: { limit: 50, offset: 0 }, action: 'members.list' });
});
it('requires CSRF and restricts mutations to own sponsored submerchant', async () => {
  const command = {
    action: 'members.disable' as const,
    membershipId: child,
    expectedVersion: await version(child),
  };
  expect(await executeMerchantCommand(pool, token, command)).toEqual({
    ok: false,
    error: 'forbidden',
  });
  expect(
    await executeMerchantCommand(pool, token, { ...command, membershipId: otherChild }, csrf),
  ).toEqual({ ok: false, error: 'not_found' });
  expect(
    await executeMerchantCommand(
      pool,
      token,
      { ...command, membershipId: admin, expectedVersion: await version(admin) },
      csrf,
    ),
  ).toEqual({ ok: false, error: 'not_found' });
  expect(
    (await pool.query('SELECT status FROM dashboard_memberships WHERE id=$1', [child])).rows[0]
      .status,
  ).toBe('active');
});
it('serializes two concurrent expected-version disables with exactly one committed audit', async () => {
  const expectedVersion = await version(child);
  const results = await Promise.all(
    [1, 2].map(() =>
      executeMerchantCommand(
        pool,
        token,
        { action: 'members.disable', membershipId: child, expectedVersion },
        csrf,
      ),
    ),
  );
  expect(results.filter((r) => r.ok)).toHaveLength(1);
  expect(results.filter((r) => !r.ok && r.error === 'conflict')).toHaveLength(1);
  expect(
    (
      await pool.query(
        "SELECT id FROM merchant_audit WHERE operator_id=$1 AND action='members.disable'",
        [operator],
      )
    ).rowCount,
  ).toBe(1);
  expect(
    (
      await pool.query(
        'SELECT revoked_at FROM membership_permission_grants WHERE membership_id=$1',
        [child],
      )
    ).rows[0].revoked_at,
  ).not.toBeNull();
});
it('withdrawal invalidates child sessions and stale versions cannot mutate again', async () => {
  const childToken = randomBytes(32).toString('hex');
  await insertViewerSession(pool, childUser, childToken, csrf);
  const expectedVersion = await version(child),
    command = {
      action: 'grants.withdraw' as const,
      membershipId: child,
      permission: 'client.payments.read' as const,
      expectedVersion,
    };
  expect((await executeMerchantCommand(pool, token, command, csrf)).ok).toBe(true);
  expect(
    (
      await pool.query('SELECT token_hash FROM dashboard_sessions WHERE token_hash=$1', [
        childToken,
      ])
    ).rowCount,
  ).toBe(0);
  expect(await executeMerchantCommand(pool, token, command, csrf)).toEqual({
    ok: false,
    error: 'conflict',
  });
});
it('disabled administrators cannot use previously valid sessions', async () => {
  await policyTransaction(pool, operator, (client) =>
    client.query("UPDATE dashboard_memberships SET status='disabled' WHERE id=$1", [admin]),
  );
  expect(
    await executeMerchantCommand(pool, token, { action: 'members.list', limit: 10, offset: 0 }),
  ).toEqual({ ok: false, error: 'unauthorized' });
});
it('rolls back a successful policy mutation if mandatory audit append fails', async () => {
  const before = await version(child);
  // Test-owner-only fault injection, scoped to this synthetic tenant. No runtime
  // bypass exists and the immutable audit trigger remains installed throughout.
  const client = await pool.connect();
  try {
    await managementFixtureGuard(client);
    await client.query(
      `CREATE FUNCTION public.merchant_audit_test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.operator_id='${operator}'::uuid THEN RAISE EXCEPTION 'Synthetic audit fault'; END IF; RETURN NEW; END; $$`,
    );
    await client.query(
      'CREATE TRIGGER merchant_audit_test_fault BEFORE INSERT ON public.merchant_audit FOR EACH ROW EXECUTE FUNCTION public.merchant_audit_test_failure()',
    );
    expect(
      await executeMerchantCommand(
        pool,
        token,
        {
          action: 'grants.withdraw',
          membershipId: child,
          permission: 'client.payments.read',
          expectedVersion: before,
        },
        csrf,
      ),
    ).toEqual({ ok: false, error: 'unavailable' });
    expect(await version(child)).toBe(before);
    expect(
      (
        await client.query(
          'SELECT revoked_at FROM membership_permission_grants WHERE membership_id=$1',
          [child],
        )
      ).rows[0].revoked_at,
    ).toBeNull();
    expect(
      (await client.query('SELECT id FROM merchant_audit WHERE operator_id=$1', [operator]))
        .rowCount,
    ).toBe(0);
  } finally {
    await client.query('DROP TRIGGER IF EXISTS merchant_audit_test_fault ON public.merchant_audit');
    await client.query('DROP FUNCTION IF EXISTS public.merchant_audit_test_failure()');
    client.release();
  }
});

it('never routes terminal-restricted submerchant grants into the operator-wide BFF', async () => {
  await policyTransaction(pool, operator, async (client) => {
    expect(await effectiveMerchantPermissions(client, child, operator)).toContain(
      'client.payments.read',
    );
    expect(await effectiveViewerPermissions(client, child, operator)).not.toContain(
      'client.payments.read',
    );
    expect(await effectiveViewerPermissions(client, admin, operator)).toContain(
      'client.payments.read',
    );
  });
});
it('returns subject-only merchant identity without directory authority', async () => {
  const result = await executeMerchantCommand(pool, token, { action: 'identity' });
  expect(result).toMatchObject({
    ok: true,
    value: {
      user: { id: adminUser },
      operator: { id: operator },
      membership: { id: admin },
      permissions: expect.arrayContaining(['client.users.read']),
    },
  });
  expect(JSON.stringify(result)).not.toMatch(/csrf_hash|password_hash|token_hash/);
});
