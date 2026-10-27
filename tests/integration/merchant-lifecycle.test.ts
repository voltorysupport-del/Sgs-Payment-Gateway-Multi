import { randomBytes, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, expect, it } from 'vitest';
import { runMigrations } from '../../src/db/migrate.js';
import {
  createMerchant,
  createMerchantInvitation,
  effectiveMerchantPermissions,
} from '../../src/management/merchant-domain.js';
import { openTestDatabase } from '../test-database.js';

let pool: Pool, client: PoolClient;
let owner: string, operator: string, admin: string, child: string;
const roots = [
  'client.payments.read',
  'client.status.read',
  'client.users.read',
  'client.users.manage_subaccounts',
  'client.permissions.delegate',
];
beforeAll(async () => {
  pool = await openTestDatabase();
  await runMigrations(pool);
});
afterAll(async () => {
  await pool.end();
});
beforeEach(async () => {
  client = await pool.connect();
  await client.query('BEGIN');
  owner = randomUUID();
  await client.query(
    "INSERT INTO owner_principals(id,username,status,enrollment_verified) VALUES($1,$2,'active',true)",
    [owner, 'lifecycle_' + owner],
  );
  await client.query(
    "INSERT INTO owner_permission_grants(id,owner_id,permission) VALUES($1,$2,'platform.clients.bootstrap_admin')",
    [randomUUID(), owner],
  );
  operator = (
    await createMerchant(client, {
      ownerId: owner,
      code: 'life_' + randomUUID(),
      name: 'Synthetic lifecycle merchant',
    })
  ).operator.id;
  admin = await member('merchant_admin');
  for (const permission of roots)
    await client.query(
      "INSERT INTO membership_permission_grants(id,membership_id,operator_id,permission_code,source,issuer_owner_id) VALUES($1,$2,$3,$4,'owner_bootstrap',$5)",
      [randomUUID(), admin, operator, permission, owner],
    );
  child = await member('submerchant', admin);
});
afterEach(async () => {
  await client.query('ROLLBACK');
  client.release();
});
async function member(kind: 'merchant_admin' | 'submerchant', sponsor?: string) {
  const user = randomUUID(),
    membership = randomUUID();
  await client.query('INSERT INTO dashboard_users(id,username,password_hash) VALUES($1,$2,$3)', [
    user,
    'synthetic_' + user,
    'SYNTHETIC_NOT_A_PASSWORD_VERIFIER',
  ]);
  await client.query('INSERT INTO dashboard_memberships(id,user_id,operator_id) VALUES($1,$2,$3)', [
    membership,
    user,
    operator,
  ]);
  await client.query(
    'INSERT INTO merchant_member_profiles(membership_id,operator_id,kind,owner_issuer_id,sponsor_membership_id) VALUES($1,$2,$3,$4,$5)',
    [membership, operator, kind, kind === 'merchant_admin' ? owner : null, sponsor ?? null],
  );
  return membership;
}
async function rejects(sql: string, values: unknown[]) {
  await client.query('SAVEPOINT rejected');
  await expect(client.query(sql, values)).rejects.toThrow();
  await client.query('ROLLBACK TO SAVEPOINT rejected');
}
async function delegate(permission = 'client.payments.read') {
  const source = (
    await client.query(
      'SELECT id FROM membership_permission_grants WHERE membership_id=$1 AND permission_code=$2',
      [admin, permission],
    )
  ).rows[0].id;
  const id = randomUUID();
  await client.query(
    "INSERT INTO membership_permission_grants(id,membership_id,operator_id,permission_code,source,sponsor_grant_id) VALUES($1,$2,$3,$4,'merchant_delegation',$5)",
    [id, child, operator, permission, source],
  );
  return { id, source };
}
it('creates a merchant without accounts, sessions or machine credentials and seeds only ceilings', async () => {
  expect(
    (await client.query('SELECT id FROM operator_api_keys WHERE operator_id=$1', [operator]))
      .rowCount,
  ).toBe(0);
  expect(
    (
      await client.query(
        'SELECT enabled FROM operator_permission_entitlements WHERE operator_id=$1',
        [operator],
      )
    ).rows,
  ).toHaveLength(7);
  expect(await effectiveMerchantPermissions(client, admin, operator)).toEqual(
    expect.arrayContaining(roots),
  );
});
it('does not infer authority from a profile, legacy source, or a different tenant', async () => {
  expect(await effectiveMerchantPermissions(client, child, operator)).toEqual([]);
  expect(await effectiveMerchantPermissions(client, admin, randomUUID())).toEqual([]);
  await rejects(
    'INSERT INTO membership_permission_grants(id,membership_id,operator_id,permission_code) VALUES($1,$2,$3,$4)',
    [randomUUID(), child, operator, 'client.users.manage_subaccounts'],
  );
  await rejects(
    "INSERT INTO membership_permission_grants(id,membership_id,operator_id,permission_code,source,issuer_owner_id) VALUES($1,$2,$3,$4,'owner_bootstrap',$5)",
    [randomUUID(), child, operator, 'client.users.manage_subaccounts', owner],
  );
});
it('enforces subordinate ceiling and prohibits delegating administration', async () => {
  await delegate();
  expect(await effectiveMerchantPermissions(client, child, operator)).toEqual([
    'client.payments.read',
  ]);
  const adminSource = (
    await client.query(
      "SELECT id FROM membership_permission_grants WHERE membership_id=$1 AND permission_code='client.users.manage_subaccounts'",
      [admin],
    )
  ).rows[0].id;
  await rejects(
    "INSERT INTO membership_permission_grants(id,membership_id,operator_id,permission_code,source,sponsor_grant_id) VALUES($1,$2,$3,'client.users.manage_subaccounts','merchant_delegation',$4)",
    [randomUUID(), child, operator, adminSource],
  );
});
it('permanently revokes child grants and invalidates sessions when sponsor grant is withdrawn', async () => {
  const { id, source } = await delegate();
  const hash = randomBytes(32).toString('hex');
  await client.query(
    `INSERT INTO dashboard_sessions(token_hash,csrf_hash,user_id,membership_id,auth_version,membership_authz_version,operator_authz_version)
 SELECT $2,$2,m.user_id,m.id,u.auth_version,m.authorization_version,p.authorization_version FROM dashboard_memberships m JOIN dashboard_users u ON u.id=m.user_id JOIN operator_access_policies p ON p.operator_id=m.operator_id WHERE m.id=$1`,
    [child, hash],
  );
  await client.query(
    "UPDATE membership_permission_grants SET revoked_at=statement_timestamp(),revocation_reason='withdrawn',revocation_policy_version=1 WHERE id=$1",
    [source],
  );
  expect(
    (await client.query('SELECT revoked_at FROM membership_permission_grants WHERE id=$1', [id]))
      .rows[0].revoked_at,
  ).not.toBeNull();
  expect(
    (await client.query('SELECT token_hash FROM dashboard_sessions WHERE token_hash=$1', [hash]))
      .rowCount,
  ).toBe(0);
  expect(await effectiveMerchantPermissions(client, child, operator)).toEqual([]);
  await rejects(
    'UPDATE membership_permission_grants SET revoked_at=NULL,revocation_reason=NULL,revocation_policy_version=NULL WHERE id=$1',
    [id],
  );
});
it('persists invitation intent without tokens, accounts or an activation bypass', async () => {
  const result = await createMerchantInvitation(client, {
    operatorId: operator,
    sponsorMembershipId: admin,
    username: 'synthetic_invitee',
    kind: 'submerchant',
    permissions: ['client.payments.read'],
    terminalIds: [],
  });
  expect(result).toMatchObject({ status: 'pending', activationEnabled: false });
  expect(Object.keys(result).sort()).toEqual([
    'activationEnabled',
    'expiresAt',
    'invitationId',
    'status',
  ]);
  expect(
    (await client.query("SELECT id FROM dashboard_users WHERE username='synthetic_invitee'"))
      .rowCount,
  ).toBe(0);
  await rejects("UPDATE merchant_invitations SET status='active' WHERE id=$1", [
    result.invitationId,
  ]);
});
it('rejects invitation escalation and foreign terminal scope', async () => {
  await expect(
    createMerchantInvitation(client, {
      operatorId: operator,
      sponsorMembershipId: admin,
      username: 'denied_invitee',
      kind: 'submerchant',
      permissions: ['client.permissions.delegate'],
      terminalIds: [],
    }),
  ).rejects.toThrow('Invitation authority unavailable.');
  await expect(
    createMerchantInvitation(client, {
      operatorId: operator,
      sponsorMembershipId: admin,
      username: 'terminal_invitee',
      kind: 'submerchant',
      permissions: ['client.payments.read'],
      terminalIds: [randomUUID()],
    }),
  ).rejects.toThrow('Terminal scope unavailable.');
});
it('cannot rewrite profile provenance or bypass the preowned policy gate', async () => {
  await rejects('UPDATE merchant_member_profiles SET owner_issuer_id=$2 WHERE membership_id=$1', [
    admin,
    randomUUID(),
  ]);
  await rejects('DELETE FROM merchant_member_profiles WHERE membership_id=$1', [child]);
  await rejects('SELECT public.require_viewer_policy_gate($1)', [randomUUID()]);
  const outsider = (
    await createMerchant(client, {
      ownerId: owner,
      code: 'other_' + randomUUID(),
      name: 'Foreign synthetic',
    })
  ).operator.id;
  await rejects(
    'INSERT INTO merchant_member_profiles(membership_id,operator_id,kind,owner_issuer_id) VALUES($1,$2,$3,$4)',
    [randomUUID(), outsider, 'merchant_admin', owner],
  );
});
