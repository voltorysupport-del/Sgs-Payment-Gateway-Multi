import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';

export const MERCHANT_PERMISSIONS = [
  'client.users.read',
  'client.users.manage_subaccounts',
  'client.permissions.delegate',
  'client.audit.read',
  'client.terminals.read',
  'client.payments.read',
  'client.status.read',
] as const;
const DELEGABLE = ['client.payments.read', 'client.status.read'];

/** Internal transaction primitives, not authentication entry points. Call only
 * after the same transaction validates the appropriate owner/client session,
 * Origin/CSRF, permission, fresh MFA where required, and takes the tenant gate.
 */
export async function createMerchant(
  client: PoolClient,
  input: { ownerId: string; code: string; name: string },
) {
  if (
    !z.uuid().safeParse(input.ownerId).success ||
    !/^[a-z0-9][a-z0-9_-]{2,63}$/.test(input.code) ||
    !input.name.trim() ||
    input.name.length > 120 ||
    Array.from(input.name).some(
      (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    throw new Error('Merchant input unavailable.');
  const id = randomUUID();
  await client.query(
    "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('vaultx.viewer.policy:' || $1::text,0))",
    [id],
  );
  const result = await client.query<{
    id: string;
    code: string;
    name: string;
    status: string;
    version: number;
  }>(
    "INSERT INTO public.operators(id,code,name,status) VALUES($1,$2,$3,'active') RETURNING id,code,name,status,management_version AS version",
    [id, input.code, input.name],
  );
  await client.query('INSERT INTO public.operator_access_policies(operator_id) VALUES($1)', [id]);
  // Explicit ceilings, not human grants. Creation does not issue users/keys/sessions.
  await client.query(
    "INSERT INTO public.operator_permission_entitlements(operator_id,permission_code) SELECT $1,code FROM public.access_permissions WHERE realm='client' AND NOT intrinsic",
    [id],
  );
  return { operator: result.rows[0]! };
}

export async function effectiveMerchantPermissions(
  client: PoolClient,
  membershipId: string,
  operatorId: string,
): Promise<string[]> {
  const grants = await client.query<{ permission_code: string }>(
    `SELECT g.permission_code FROM public.membership_permission_grants g
 JOIN public.operator_permission_entitlements e ON e.operator_id=g.operator_id AND e.permission_code=g.permission_code AND e.enabled
 JOIN public.dashboard_memberships m ON m.id=g.membership_id AND m.operator_id=g.operator_id AND m.status='active'
 JOIN public.dashboard_users u ON u.id=m.user_id AND u.status='active'
 JOIN public.operators o ON o.id=g.operator_id AND o.status='active'
 JOIN public.merchant_member_profiles p ON p.membership_id=g.membership_id AND p.operator_id=g.operator_id
 WHERE g.membership_id=$1 AND g.operator_id=$2 AND g.revoked_at IS NULL
 AND ((p.kind='merchant_admin' AND g.source='owner_bootstrap' AND g.issuer_owner_id=p.owner_issuer_id) OR
 (p.kind='submerchant' AND g.source='merchant_delegation' AND EXISTS(
  SELECT 1 FROM public.membership_permission_grants sg
  JOIN public.dashboard_memberships sm ON sm.id=sg.membership_id AND sm.operator_id=sg.operator_id AND sm.status='active'
  JOIN public.dashboard_users su ON su.id=sm.user_id AND su.status='active'
  JOIN public.merchant_member_profiles sp ON sp.membership_id=sm.id AND sp.operator_id=sm.operator_id AND sp.kind='merchant_admin'
  WHERE sg.id=g.sponsor_grant_id AND sg.membership_id=p.sponsor_membership_id AND sg.operator_id=g.operator_id
   AND sg.permission_code=g.permission_code AND sg.revoked_at IS NULL AND sg.source='owner_bootstrap' AND sg.issuer_owner_id=sp.owner_issuer_id
   AND NOT EXISTS(SELECT 1 FROM (VALUES('client.permissions.delegate'),('client.users.manage_subaccounts')) needed(code)
    WHERE NOT EXISTS(SELECT 1 FROM public.membership_permission_grants ag
     JOIN public.operator_permission_entitlements ae ON ae.operator_id=ag.operator_id AND ae.permission_code=ag.permission_code AND ae.enabled
     WHERE ag.membership_id=sp.membership_id AND ag.operator_id=g.operator_id AND ag.permission_code=needed.code
      AND ag.source='owner_bootstrap' AND ag.issuer_owner_id=sp.owner_issuer_id AND ag.revoked_at IS NULL)))))
 ORDER BY g.permission_code,g.id`,
    [membershipId, operatorId],
  );
  return MERCHANT_PERMISSIONS.filter((permission) =>
    grants.rows.some((g) => g.permission_code === permission),
  );
}

export async function createMerchantInvitation(
  client: PoolClient,
  input: {
    operatorId: string;
    ownerId?: string;
    sponsorMembershipId?: string;
    username: string;
    kind: 'merchant_admin' | 'submerchant';
    permissions: string[];
    terminalIds: string[];
  },
) {
  if (
    !z.uuid().safeParse(input.operatorId).success ||
    !/^[a-z0-9][a-z0-9_.-]{2,79}$/.test(input.username) ||
    !input.permissions.length ||
    input.permissions.length > 7 ||
    new Set(input.permissions).size !== input.permissions.length ||
    input.permissions.some(
      (p) => !MERCHANT_PERMISSIONS.includes(p as (typeof MERCHANT_PERMISSIONS)[number]),
    ) ||
    input.terminalIds.length > 100 ||
    input.terminalIds.some((id) => !z.uuid().safeParse(id).success) ||
    new Set(input.terminalIds).size !== input.terminalIds.length
  )
    throw new Error('Invitation input unavailable.');
  await client.query('SELECT public.require_viewer_policy_gate($1)', [input.operatorId]);
  const ceilings = await client.query(
    "SELECT e.permission_code FROM public.operator_permission_entitlements e JOIN public.operators o ON o.id=e.operator_id AND o.status='active' WHERE e.operator_id=$1 AND e.enabled AND e.permission_code=ANY($2::text[])",
    [input.operatorId, input.permissions],
  );
  if (ceilings.rowCount !== input.permissions.length)
    throw new Error('Invitation ceiling unavailable.');
  if (input.kind === 'submerchant') {
    const effective = await effectiveMerchantPermissions(
      client,
      input.sponsorMembershipId ?? '',
      input.operatorId,
    );
    if (
      !effective.includes('client.users.manage_subaccounts') ||
      !effective.includes('client.permissions.delegate') ||
      input.permissions.some((p) => !DELEGABLE.includes(p) || !effective.includes(p))
    )
      throw new Error('Invitation authority unavailable.');
  }
  if (input.terminalIds.length) {
    const terminals = await client.query(
      "SELECT id FROM public.merchant_terminals WHERE operator_id=$1 AND id=ANY($2::uuid[]) AND status='active'",
      [input.operatorId, input.terminalIds],
    );
    if (terminals.rowCount !== new Set(input.terminalIds).size)
      throw new Error('Terminal scope unavailable.');
  }
  const result = await client.query<{ id: string; expires_at: Date }>(
    `INSERT INTO public.merchant_invitations(id,operator_id,username,kind,owner_issuer_id,sponsor_membership_id,permissions,terminal_ids)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,expires_at`,
    [
      randomUUID(),
      input.operatorId,
      input.username,
      input.kind,
      input.ownerId ?? null,
      input.sponsorMembershipId ?? null,
      [...new Set(input.permissions)],
      [...new Set(input.terminalIds)],
    ],
  );
  return {
    invitationId: result.rows[0]!.id,
    expiresAt: result.rows[0]!.expires_at.toISOString(),
    status: 'pending',
    activationEnabled: false,
  };
}

export async function listMerchantMembers(client: PoolClient, operatorId: string) {
  const result = await client.query(
    `SELECT m.id,m.status,p.kind,u.username,m.authorization_version AS version
 FROM public.dashboard_memberships m JOIN public.dashboard_users u ON u.id=m.user_id
 LEFT JOIN public.merchant_member_profiles p ON p.membership_id=m.id AND p.operator_id=m.operator_id
 WHERE m.operator_id=$1 ORDER BY m.id LIMIT 101`,
    [operatorId],
  );
  return { members: result.rows.slice(0, 100), hasMore: result.rows.length > 100 };
}
export async function listMerchantTerminals(client: PoolClient, operatorId: string) {
  const result = await client.query(
    'SELECT id,code,name,status FROM public.merchant_terminals WHERE operator_id=$1 ORDER BY id LIMIT 101',
    [operatorId],
  );
  return { terminals: result.rows.slice(0, 100), hasMore: result.rows.length > 100 };
}
export async function revokeMerchantProfile(
  client: PoolClient,
  input: { operatorId: string; membershipId: string },
) {
  await client.query('SELECT public.require_viewer_policy_gate($1)', [input.operatorId]);
  const result = await client.query(
    "UPDATE public.dashboard_memberships m SET status='disabled' FROM public.merchant_member_profiles p WHERE p.membership_id=m.id AND p.operator_id=m.operator_id AND m.operator_id=$1 AND m.id=$2 AND p.kind='submerchant' AND m.status='active' RETURNING m.id",
    [input.operatorId, input.membershipId],
  );
  return { revoked: result.rowCount === 1 };
}
export async function withdrawMerchantGrant(
  client: PoolClient,
  input: { operatorId: string; membershipId: string; permission: string },
) {
  await client.query('SELECT public.require_viewer_policy_gate($1)', [input.operatorId]);
  const result = await client.query(
    `UPDATE public.membership_permission_grants SET revoked_at=statement_timestamp(),revocation_reason='withdrawn',revocation_policy_version=(SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=$1) WHERE operator_id=$1 AND membership_id=$2 AND permission_code=$3 AND revoked_at IS NULL RETURNING id`,
    [input.operatorId, input.membershipId, input.permission],
  );
  return { revoked: result.rowCount === 1 };
}
