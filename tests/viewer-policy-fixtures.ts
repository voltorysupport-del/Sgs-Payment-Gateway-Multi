import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';

/** Migration-owner fixtures ONLY, guarded by the disposable cluster's token.
 * Represents users present at 004→005 cutover; no production seeding helper.
 */
async function guard(client: PoolClient) {
  const result = await client.query<{ safe: boolean }>(
    `SELECT current_database()='vaultx_pay_test' AND session_user='vaultx_test'
 AND EXISTS(SELECT 1 FROM vaultx_test_guard.identity WHERE token=$1) AS safe`,
    [process.env.TEST_DATABASE_TOKEN],
  );
  if (process.env.NODE_ENV !== 'test' || result.rows[0]?.safe !== true)
    throw new Error('Disposable viewer fixture refused.');
}
export async function policyTransaction<T>(
  pool: Pool,
  operator: string,
  run: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='2000ms'");
    await guard(client);
    await lockPolicyRows(client, operator);
    const value = await run(client);
    await client.query('COMMIT');
    return value;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
export function policyQuery(pool: Pool, operator: string, sql: string, values: unknown[] = []) {
  return policyTransaction(pool, operator, (client) => client.query(sql, values));
}
export async function seedViewerFixture(pool: Pool, user: string) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await guard(client);
    const membership = await client.query<{ id: string; operator_id: string }>(
      'SELECT id,operator_id FROM public.dashboard_memberships WHERE user_id=$1',
      [user],
    );
    const m = membership.rows[0];
    if (!m) throw new Error('Missing fixture membership');
    if (
      (
        await client.query(
          'SELECT id FROM public.membership_permission_grants WHERE membership_id=$1',
          [m.id],
        )
      ).rowCount
    )
      throw new Error('Fixture already has cutover evidence');
    await client.query(
      'INSERT INTO public.operator_access_policies(operator_id) VALUES ($1) ON CONFLICT DO NOTHING',
      [m.operator_id],
    );
    await client.query(
      'INSERT INTO public.operator_permission_entitlements(operator_id,permission_code) SELECT $1,code FROM public.access_permissions WHERE NOT intrinsic ON CONFLICT DO NOTHING',
      [m.operator_id],
    );
    for (const permission of ['client.payments.read', 'client.status.read'])
      await client.query(
        'INSERT INTO public.membership_permission_grants(id,membership_id,operator_id,permission_code) VALUES($1,$2,$3,$4)',
        [randomUUID(), m.id, m.operator_id, permission],
      );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
export async function cleanupViewerFixture(pool: Pool, user: string) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await guard(client);
    const result = await client.query<{ operator_id: string }>(
      'SELECT operator_id FROM public.dashboard_memberships WHERE user_id=$1',
      [user],
    );
    await client.query(
      'DELETE FROM public.membership_permission_grants WHERE membership_id IN(SELECT id FROM public.dashboard_memberships WHERE user_id=$1)',
      [user],
    );
    await client.query('DELETE FROM public.dashboard_users WHERE id=$1', [user]);
    const op = result.rows[0]?.operator_id;
    if (op) {
      await client.query(
        'DELETE FROM public.operator_permission_entitlements WHERE operator_id=$1 AND NOT EXISTS(SELECT 1 FROM public.dashboard_memberships WHERE operator_id=$1)',
        [op],
      );
      await client.query(
        'DELETE FROM public.operator_access_policies WHERE operator_id=$1 AND NOT EXISTS(SELECT 1 FROM public.dashboard_memberships WHERE operator_id=$1)',
        [op],
      );
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
export async function insertViewerSession(pool: Pool, user: string, hash: string, csrf: string) {
  const client = await pool.connect();
  try {
    await guard(client);
    await client.query(
      `INSERT INTO public.dashboard_sessions(token_hash,csrf_hash,user_id,membership_id,auth_version,membership_authz_version,operator_authz_version)
 SELECT $2,$3,u.id,m.id,u.auth_version,m.authorization_version,p.authorization_version
 FROM public.dashboard_users u JOIN public.dashboard_memberships m ON m.user_id=u.id JOIN public.operator_access_policies p ON p.operator_id=m.operator_id WHERE u.id=$1`,
      [user, hash, csrf],
    );
  } finally {
    client.release();
  }
}

export async function lockPolicyRows(client: PoolClient, operator: string) {
  await guard(client);
  await client.query(
    "SELECT pg_advisory_xact_lock(hashtextextended('vaultx.viewer.policy:' || $1::uuid::text,0))",
    [operator],
  );
  await client.query(
    'SELECT operator_id FROM public.operator_access_policies WHERE operator_id=$1 FOR UPDATE',
    [operator],
  );
  await client.query(
    'SELECT u.id FROM public.dashboard_users u WHERE id IN(SELECT user_id FROM public.dashboard_memberships WHERE operator_id=$1) ORDER BY u.id FOR UPDATE',
    [operator],
  );
  await client.query(
    'SELECT id FROM public.dashboard_memberships WHERE operator_id=$1 ORDER BY id FOR UPDATE',
    [operator],
  );
  await client.query('SELECT id FROM public.operators WHERE id=$1 FOR UPDATE', [operator]);
  await client.query(
    'SELECT id FROM public.membership_permission_grants WHERE operator_id=$1 ORDER BY membership_id,permission_code,id FOR UPDATE',
    [operator],
  );
  await client.query(
    'SELECT token_hash FROM public.dashboard_sessions WHERE membership_id IN(SELECT id FROM public.dashboard_memberships WHERE operator_id=$1) ORDER BY token_hash FOR UPDATE',
    [operator],
  );
}
