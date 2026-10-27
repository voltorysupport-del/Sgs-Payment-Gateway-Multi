import type { PoolClient } from 'pg';
import { effectiveMerchantPermissions } from '../management/merchant-domain.js';

export const unavailable = () => new Error('Enrollment unavailable.');
export interface Intent {
  id: string;
  operator_id: string;
  username: string;
  kind: 'merchant_admin' | 'submerchant';
  owner_issuer_id: string | null;
  sponsor_membership_id: string | null;
  permissions: string[];
  terminal_ids: string[];
}
/** Owner shared gate/rows FIRST, then exclusive tenant gate and ordered identity
 * rows. Same order as owner management. No network/browser wait holds these locks.
 * Versions are fail-closed fences; live authority is independently re-evaluated.
 */
export async function lockIntent(client: PoolClient, id: string) {
  const intent = (
    await client.query<Intent>('SELECT * FROM public.merchant_invitations WHERE id=$1', [id])
  ).rows[0];
  if (!intent) throw unavailable();
  let issuerVersion: number;
  let grantIds: string[] = [];
  if (intent.owner_issuer_id) {
    await client.query(
      "SELECT pg_advisory_xact_lock_shared(hashtextextended('vaultx.owner.policy',0))",
    );
    await client.query("SELECT id FROM public.management_policy WHERE id='platform' FOR SHARE");
    const owner = (
      await client.query<{ authorization_version: number }>(
        "SELECT authorization_version FROM public.owner_principals WHERE id=$1 AND status='active' AND enrollment_verified FOR SHARE",
        [intent.owner_issuer_id],
      )
    ).rows[0];
    if (!owner) throw unavailable();
    const authority = await client.query(
      "SELECT id FROM public.owner_permission_grants WHERE owner_id=$1 AND permission='platform.clients.bootstrap_admin' AND revoked_at IS NULL FOR SHARE",
      [intent.owner_issuer_id],
    );
    if (authority.rowCount !== 1) throw unavailable();
    issuerVersion = owner.authorization_version;
  } else issuerVersion = 0;
  const tenant = intent.operator_id;
  await client.query(
    "SELECT pg_advisory_xact_lock(hashtextextended('vaultx.viewer.policy:' || $1::text,0))",
    [tenant],
  );
  const policy = (
    await client.query<{ authorization_version: number }>(
      'SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=$1 FOR UPDATE',
      [tenant],
    )
  ).rows[0];
  if (!policy) throw unavailable();
  // Same bounded tenant protocol as merchant management; fail closed before locks
  // if a tenant exceeds this increment's supported management size.
  const count = (
    await client.query<{ count: string }>(
      'SELECT count(*) FROM public.dashboard_memberships WHERE operator_id=$1',
      [tenant],
    )
  ).rows[0];
  if (!count || Number(count.count) > 1000) throw unavailable();
  await client.query(
    'SELECT id FROM public.dashboard_users WHERE id IN(SELECT user_id FROM public.dashboard_memberships WHERE operator_id=$1) ORDER BY id FOR UPDATE',
    [tenant],
  );
  await client.query(
    'SELECT id FROM public.dashboard_memberships WHERE operator_id=$1 ORDER BY id FOR UPDATE',
    [tenant],
  );
  const operator = await client.query(
    "SELECT id FROM public.operators WHERE id=$1 AND status='active' FOR UPDATE",
    [tenant],
  );
  if (operator.rowCount !== 1) throw unavailable();
  await client.query(
    'SELECT id FROM public.membership_permission_grants WHERE operator_id=$1 ORDER BY membership_id,permission_code,id FOR UPDATE',
    [tenant],
  );
  await client.query(
    'SELECT token_hash FROM public.dashboard_sessions WHERE membership_id IN(SELECT id FROM public.dashboard_memberships WHERE operator_id=$1) ORDER BY token_hash FOR UPDATE',
    [tenant],
  );
  if (
    !(
      await client.query(
        'SELECT id FROM public.merchant_invitations WHERE id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()',
        [id],
      )
    ).rowCount
  )
    throw unavailable();
  const ceiling = await client.query(
    'SELECT permission_code FROM public.operator_permission_entitlements WHERE operator_id=$1 AND enabled AND permission_code=ANY($2::text[])',
    [tenant, intent.permissions],
  );
  if (ceiling.rowCount !== intent.permissions.length) throw unavailable();
  if (intent.terminal_ids.length) {
    const terminals = await client.query(
      "SELECT id FROM public.merchant_terminals WHERE operator_id=$1 AND id=ANY($2::uuid[]) AND status='active' ORDER BY id FOR SHARE",
      [tenant, intent.terminal_ids],
    );
    if (terminals.rowCount !== intent.terminal_ids.length) throw unavailable();
  }
  // Administrator terminal-restricted intent cannot become operator-wide authority.
  // Keep it unconsumable until a reviewed terminal-aware admin model exists.
  if (intent.kind === 'merchant_admin' && intent.terminal_ids.length) throw unavailable();
  if (intent.sponsor_membership_id) {
    const effective = await effectiveMerchantPermissions(
      client,
      intent.sponsor_membership_id,
      tenant,
    );
    const needed = [
      ...new Set([
        'client.users.manage_subaccounts',
        'client.permissions.delegate',
        ...intent.permissions,
      ]),
    ];
    if (needed.some((p) => !effective.includes(p))) throw unavailable();
    const sponsor = (
      await client.query<{ authorization_version: number }>(
        "SELECT m.authorization_version FROM public.dashboard_memberships m JOIN public.merchant_member_profiles p ON p.membership_id=m.id AND p.operator_id=m.operator_id AND p.kind='merchant_admin' WHERE m.id=$1 AND m.operator_id=$2 AND m.status='active'",
        [intent.sponsor_membership_id, tenant],
      )
    ).rows[0];
    if (!sponsor) throw unavailable();
    issuerVersion = sponsor.authorization_version;
    grantIds = (
      await client.query<{ id: string }>(
        'SELECT id FROM public.membership_permission_grants WHERE membership_id=$1 AND operator_id=$2 AND revoked_at IS NULL AND permission_code=ANY($3::text[]) ORDER BY id',
        [intent.sponsor_membership_id, tenant, needed],
      )
    ).rows.map((g) => g.id);
    if (grantIds.length !== needed.length) throw unavailable();
  }
  return { intent, policyVersion: policy.authorization_version, issuerVersion, grantIds };
}
