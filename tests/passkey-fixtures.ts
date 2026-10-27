import type { Pool, PoolClient } from 'pg';
import { syntheticAuthenticator } from './webauthn-authenticator.js';
import { managementFixtureGuard } from './management-fixtures.js';
import { insertViewerSession, policyTransaction } from './viewer-policy-fixtures.js';
/** Schema-owner assurance fixture for pre-existing management tests, NOT proof
 * of WebAuthn verification. New enrollment tests use real signed assertions. */
export async function insertAssuredSession(pool: Pool, user: string, hash: string, csrf: string) {
  const client = await pool.connect();
  let tenant: string;
  try {
    await managementFixtureGuard(client);
    tenant = (
      await client.query('SELECT operator_id FROM dashboard_memberships WHERE user_id=$1', [user])
    ).rows[0].operator_id;
  } finally {
    client.release();
  }
  const key = syntheticAuthenticator();
  await policyTransaction(pool, tenant, (c) =>
    c.query(
      'INSERT INTO public.dashboard_passkeys(credential_id,user_id,public_key,counter) VALUES($1,$2,$3,0)',
      [key.id, user, key.publicKey],
    ),
  );
  await insertViewerSession(pool, user, hash, csrf);
  await pool.query(
    'UPDATE public.dashboard_sessions SET webauthn_credential_id=$2,webauthn_verified_at=clock_timestamp() WHERE token_hash=$1',
    [hash, key.id],
  );
}
export async function cleanupPasskeyFixtures(client: PoolClient, operators: string[]) {
  await managementFixtureGuard(client);
  await client.query(
    'DELETE FROM public.dashboard_sessions WHERE membership_id IN(SELECT id FROM public.dashboard_memberships WHERE operator_id=ANY($1::uuid[]))',
    [operators],
  );
  await client.query(
    'ALTER TABLE public.dashboard_passkeys DISABLE TRIGGER dashboard_passkey_history',
  );
  await client.query(
    'DELETE FROM public.dashboard_passkeys WHERE user_id IN(SELECT user_id FROM public.dashboard_memberships WHERE operator_id=ANY($1::uuid[]))',
    [operators],
  );
  await client.query(
    'ALTER TABLE public.dashboard_passkeys ENABLE TRIGGER dashboard_passkey_history',
  );
}

export async function cleanupEnrollmentFixtures(client: PoolClient, operator: string) {
  await managementFixtureGuard(client);
  for (const [table, trigger] of [
    ['merchant_enrollment_audit', 'merchant_enrollment_audit_immutable'],
    ['merchant_invitation_tokens', 'invitation_token_history'],
    ['merchant_invitations', 'merchant_invitation_history'],
  ])
    await client.query(`ALTER TABLE public.${table} DISABLE TRIGGER ${trigger}`);
  await client.query('DELETE FROM public.merchant_enrollment_audit WHERE operator_id=$1', [
    operator,
  ]);
  await client.query(
    'DELETE FROM public.dashboard_sessions WHERE token_hash IN(SELECT session_hash FROM public.dashboard_webauthn_challenges WHERE invitation_token_hash IN(SELECT t.token_hash FROM public.merchant_invitation_tokens t JOIN public.merchant_invitations i ON i.id=t.invitation_id WHERE i.operator_id=$1))',
    [operator],
  );
  await client.query(
    'DELETE FROM public.merchant_invitation_tokens WHERE invitation_id IN(SELECT id FROM public.merchant_invitations WHERE operator_id=$1)',
    [operator],
  );
  await client.query('DELETE FROM public.merchant_invitations WHERE operator_id=$1', [operator]);
  for (const [table, trigger] of [
    ['merchant_enrollment_audit', 'merchant_enrollment_audit_immutable'],
    ['merchant_invitation_tokens', 'invitation_token_history'],
    ['merchant_invitations', 'merchant_invitation_history'],
  ])
    await client.query(`ALTER TABLE public.${table} ENABLE TRIGGER ${trigger}`);
}
