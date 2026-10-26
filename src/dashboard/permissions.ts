import type { PoolClient } from 'pg';
export const VIEWER_PERMISSIONS = ['client.payments.read', 'client.status.read'] as const;
export type ViewerPermission = (typeof VIEWER_PERMISSIONS)[number];

/** Admission's shared pre-gate and row gate are held only within its DB transaction. */
export async function lockViewerIdentity(
  client: PoolClient,
  userId: string,
  membershipId: string,
  operatorId: string,
) {
  await client.query(
    "SELECT pg_catalog.pg_advisory_xact_lock_shared(pg_catalog.hashtextextended('vaultx.viewer.policy:' || $1::text,0))",
    [operatorId],
  );
  const policy = await client.query<{ authorization_version: number }>(
    'SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=$1 FOR SHARE',
    [operatorId],
  );
  if (!policy.rows[0]) return undefined;
  const user = await client.query<{
    username: string;
    status: string;
    auth_version: number;
    password_hash: string;
  }>(
    'SELECT username,status,auth_version,password_hash FROM public.dashboard_users WHERE id=$1 FOR SHARE',
    [userId],
  );
  const membership = await client.query<{ status: string; authorization_version: number }>(
    "SELECT status,authorization_version FROM public.dashboard_memberships WHERE id=$1 AND user_id=$2 AND operator_id=$3 AND role='viewer' FOR SHARE",
    [membershipId, userId, operatorId],
  );
  const operator = await client.query<{ status: string }>(
    'SELECT status FROM public.operators WHERE id=$1 FOR SHARE',
    [operatorId],
  );
  if (
    user.rows[0]?.status !== 'active' ||
    membership.rows[0]?.status !== 'active' ||
    operator.rows[0]?.status !== 'active'
  )
    return undefined;
  return {
    user: user.rows[0],
    membershipVersion: membership.rows[0].authorization_version,
    operatorVersion: policy.rows[0].authorization_version,
  };
}
export async function effectiveViewerPermissions(
  client: PoolClient,
  membershipId: string,
  operatorId: string,
): Promise<ViewerPermission[]> {
  const result = await client.query<{ permission_code: string }>(
    `SELECT g.permission_code FROM public.membership_permission_grants g
 JOIN public.operator_permission_entitlements e ON e.operator_id=g.operator_id AND e.permission_code=g.permission_code AND e.enabled
 JOIN public.access_permissions p ON p.code=g.permission_code AND p.realm='client' AND NOT p.intrinsic
 WHERE g.membership_id=$1 AND g.operator_id=$2 AND g.revoked_at IS NULL ORDER BY g.membership_id,g.permission_code,g.id FOR SHARE OF g`,
    [membershipId, operatorId],
  );
  return VIEWER_PERMISSIONS.filter((permission) =>
    result.rows.some((row) => row.permission_code === permission),
  );
}
