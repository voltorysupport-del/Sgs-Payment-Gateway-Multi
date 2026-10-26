import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { OWNER_PERMISSIONS } from '../src/management/domain.js';

export async function managementFixtureGuard(client: PoolClient) {
  const identity = await client.query<{ safe: boolean }>(
    `SELECT current_database()='vaultx_pay_test' AND session_user='vaultx_test'
  AND EXISTS(SELECT 1 FROM vaultx_test_guard.identity WHERE token=$1) AS safe`,
    [process.env.TEST_DATABASE_TOKEN],
  );
  if (process.env.NODE_ENV !== 'test' || identity.rows[0]?.safe !== true)
    throw new Error('Disposable management fixture refused.');
}
/** Schema-owner synthetic assurance records, NOT an enrollment/bootstrap issuer. */
export async function createOwnerFixture(
  pool: Pool,
  permissions: readonly string[] = OWNER_PERMISSIONS,
) {
  const client = await pool.connect();
  const id = randomUUID(),
    token = randomBytes(32).toString('hex'),
    csrf = randomBytes(32).toString('hex');
  const tokenHash = createHash('sha256').update(token).digest('hex');
  const csrfHash = createHash('sha256').update(csrf).digest('hex');
  try {
    await client.query('BEGIN');
    await managementFixtureGuard(client);
    await client.query(
      "INSERT INTO public.owner_principals(id,username,status,enrollment_verified) VALUES($1,$2,'active',true)",
      [id, 'owner_' + id],
    );
    for (const permission of permissions)
      await client.query(
        'INSERT INTO public.owner_permission_grants(id,owner_id,permission) VALUES($1,$2,$3)',
        [randomUUID(), id, permission],
      );
    await client.query(
      `INSERT INTO public.owner_sessions(token_hash,csrf_hash,owner_id,assurance,authorization_version,policy_version,mfa_verified_at)
     VALUES($1,$2,$3,'mfa',1,(SELECT authorization_version FROM public.management_policy WHERE id='platform'),clock_timestamp())`,
      [tokenHash, csrfHash, id],
    );
    await client.query('COMMIT');
    return { id, token, tokenHash, csrf, csrfHash };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
/** Only the separately verified disposable schema owner may remove synthetic audit
 * evidence. Runtime cannot disable triggers; no production bypass exists. */
export async function cleanupOwnerFixture(pool: Pool, id: string) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await managementFixtureGuard(client);
    await client.query(
      'ALTER TABLE public.management_audit DISABLE TRIGGER management_audit_immutable',
    );
    await client.query('DELETE FROM public.management_audit WHERE actor_id=$1', [id]);
    await client.query(
      'ALTER TABLE public.management_audit ENABLE TRIGGER management_audit_immutable',
    );
    await client.query('DELETE FROM public.owner_sessions WHERE owner_id=$1', [id]);
    await client.query('DELETE FROM public.owner_permission_grants WHERE owner_id=$1', [id]);
    await client.query('DELETE FROM public.owner_principals WHERE id=$1', [id]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
