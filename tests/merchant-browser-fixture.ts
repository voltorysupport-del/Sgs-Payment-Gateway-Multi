import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { createMerchant, MERCHANT_PERMISSIONS } from '../src/management/merchant-domain.js';
import {
  createOwnerFixture,
  cleanupOwnerFixture,
  managementFixtureGuard,
} from './management-fixtures.js';
import {
  insertAssuredSession,
  cleanupPasskeyFixtures,
  cleanupEnrollmentFixtures,
} from './passkey-fixtures.js';
/** Synthetic schema-owner fixture, only after the disposable database guard.
 * Does NOT represent an approved production enrollment or activation ceremony.
 */
export async function createMerchantBrowserFixture(pool: Pool) {
  const owner = await createOwnerFixture(pool);
  const client = await pool.connect();
  const user = randomUUID(),
    member = randomUUID(),
    childUser = randomUUID(),
    child = randomUUID();
  let operator = '';
  const username = 'browser_merchant_' + user;
  try {
    await client.query('BEGIN');
    await managementFixtureGuard(client);
    operator = (
      await createMerchant(client, {
        ownerId: owner.id,
        code: 'browser_' + randomUUID(),
        name: 'Synthetic browser merchant',
      })
    ).operator.id;
    for (const [id, name, membership] of [
      [user, username, member],
      [childUser, 'browser_child_' + childUser, child],
    ]) {
      await client.query(
        'INSERT INTO public.dashboard_users(id,username,password_hash) VALUES($1,$2,$3)',
        [id, name, 'SYNTHETIC_UNUSED_VERIFIER'],
      );
      await client.query(
        'INSERT INTO public.dashboard_memberships(id,user_id,operator_id) VALUES($1,$2,$3)',
        [membership, id, operator],
      );
    }
    await client.query(
      "INSERT INTO public.merchant_member_profiles(membership_id,operator_id,kind,owner_issuer_id) VALUES($1,$2,'merchant_admin',$3)",
      [member, operator, owner.id],
    );
    for (const permission of MERCHANT_PERMISSIONS)
      await client.query(
        "INSERT INTO public.membership_permission_grants(id,membership_id,operator_id,permission_code,source,issuer_owner_id) VALUES($1,$2,$3,$4,'owner_bootstrap',$5)",
        [randomUUID(), member, operator, permission, owner.id],
      );
    await client.query(
      "INSERT INTO public.merchant_member_profiles(membership_id,operator_id,kind,sponsor_membership_id) VALUES($1,$2,'submerchant',$3)",
      [child, operator, member],
    );
    await client.query(
      'INSERT INTO public.merchant_terminals(id,operator_id,code,name) VALUES($1,$2,$3,$4)',
      [randomUUID(), operator, 'synthetic_browser_terminal', 'Synthetic browser terminal'],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
  const token = randomBytes(32).toString('hex'),
    csrf = randomBytes(32).toString('hex');
  await insertAssuredSession(
    pool,
    user,
    createHash('sha256').update(token).digest('hex'),
    createHash('sha256').update(csrf).digest('hex'),
  );
  return {
    owner,
    operator,
    member,
    child,
    username,
    childUsername: 'browser_child_' + childUser,
    token,
  };
}
/** Verified disposable schema-owner teardown; immutable history is not removable
 * by runtime roles. Trigger changes are transactional and restored before commit.
 */
export async function cleanupMerchantBrowserFixture(
  pool: Pool,
  fixture: Awaited<ReturnType<typeof createMerchantBrowserFixture>>,
) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await managementFixtureGuard(client);
    await cleanupEnrollmentFixtures(client, fixture.operator);
    await cleanupPasskeyFixtures(client, [fixture.operator]);
    for (const [table, trigger] of [
      ['merchant_audit', 'merchant_audit_immutable'],
      ['merchant_member_profiles', 'merchant_profile_history'],
    ])
      await client.query(`ALTER TABLE public.${table} DISABLE TRIGGER ${trigger}`);
    await client.query('DELETE FROM public.merchant_audit WHERE operator_id=$1', [
      fixture.operator,
    ]);
    await client.query('DELETE FROM public.membership_permission_grants WHERE operator_id=$1', [
      fixture.operator,
    ]);
    await client.query('DELETE FROM public.merchant_member_profiles WHERE operator_id=$1', [
      fixture.operator,
    ]);
    await client.query(
      'DELETE FROM public.dashboard_users WHERE id IN(SELECT user_id FROM public.dashboard_memberships WHERE operator_id=$1)',
      [fixture.operator],
    );
    await client.query('DELETE FROM public.merchant_terminals WHERE operator_id=$1', [
      fixture.operator,
    ]);
    await client.query('DELETE FROM public.operator_permission_entitlements WHERE operator_id=$1', [
      fixture.operator,
    ]);
    await client.query('DELETE FROM public.operator_access_policies WHERE operator_id=$1', [
      fixture.operator,
    ]);
    await client.query('DELETE FROM public.operators WHERE id=$1', [fixture.operator]);
    for (const [table, trigger] of [
      ['merchant_audit', 'merchant_audit_immutable'],
      ['merchant_member_profiles', 'merchant_profile_history'],
    ])
      await client.query(`ALTER TABLE public.${table} ENABLE TRIGGER ${trigger}`);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
  await cleanupOwnerFixture(pool, fixture.owner.id);
}
