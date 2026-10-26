import { randomUUID, timingSafeEqual } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { withReadClient } from '../db/read-client.js';

export const OWNER_PERMISSIONS = [
  'platform.clients.read',
  'platform.clients.manage',
  'platform.audit.read',
] as const;
export type ManagementCommand =
  | { action: 'identity' }
  | { action: 'csrf.rotate'; newCsrfHash: string }
  | { action: 'logout'; csrfHash: string }
  | { action: 'operators.list'; limit: number; offset: number }
  | { action: 'operators.detail'; targetId: string }
  | { action: 'members.list'; targetId: string; limit: number; offset: number }
  | { action: 'members.detail'; targetId: string; membershipId: string }
  | { action: 'audit.list'; targetId?: string; limit: number; offset: number }
  | {
      action: 'operators.update';
      targetId: string;
      expectedVersion: number;
      csrfHash: string;
      patch: { name?: string; status?: 'active' | 'suspended' };
    }
  | {
      action: 'entitlements.withdraw';
      targetId: string;
      permission: 'client.payments.read' | 'client.status.read';
      expectedVersion: number;
      csrfHash: string;
    };
export type ManagementError =
  'unauthorized' | 'forbidden' | 'not_found' | 'conflict' | 'invalid_input' | 'unavailable';
export type ManagementResult = { ok: true; value: unknown } | { ok: false; error: ManagementError };
const denied = (error: ManagementError): ManagementResult => ({ ok: false, error });
const ok = (value: unknown): ManagementResult => ({ ok: true, value });
const digestPattern = /^[a-f0-9]{64}$/;
const matchesCsrf = (left: string, right: string) =>
  digestPattern.test(left) &&
  digestPattern.test(right) &&
  timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));

const uuid = z.uuid();
interface OwnerRow {
  id: string;
  username: string;
  authorization_version: number;
  status: string;
  enrollment_verified: boolean;
}
interface OperatorRow {
  id: string;
  code: string;
  name: string;
  status: string;
  management_version: number;
}
interface MemberRow {
  id: string;
  status: string;
  role: 'viewer';
  authorization_version: number;
}
const operatorDto = (row: OperatorRow) => ({
  id: row.id,
  code: row.code,
  name: row.name,
  status: row.status,
  version: row.management_version,
});
const memberDto = (row: MemberRow) => ({
  id: row.id,
  status: row.status,
  role: row.role,
  authorizationVersion: row.authorization_version,
});
const writes = (command: ManagementCommand) =>
  command.action === 'operators.update' || command.action === 'entitlements.withdraw';
function valid(command: ManagementCommand): boolean {
  if (
    'targetId' in command &&
    command.targetId !== undefined &&
    !uuid.safeParse(command.targetId).success
  )
    return false;
  if ('membershipId' in command && !uuid.safeParse(command.membershipId).success) return false;
  if (
    'limit' in command &&
    (!Number.isInteger(command.limit) ||
      command.limit < 1 ||
      command.limit > 100 ||
      !Number.isInteger(command.offset) ||
      command.offset < 0 ||
      command.offset > 10000)
  )
    return false;
  if (
    'expectedVersion' in command &&
    (!Number.isSafeInteger(command.expectedVersion) || command.expectedVersion < 1)
  )
    return false;
  if ('csrfHash' in command && !digestPattern.test(command.csrfHash)) return false;
  if (command.action === 'csrf.rotate' && !digestPattern.test(command.newCsrfHash)) return false;
  if (
    command.action === 'entitlements.withdraw' &&
    !['client.payments.read', 'client.status.read'].includes(command.permission)
  )
    return false;
  if (command.action === 'operators.update') {
    if (
      Object.keys(command.patch).some((key) => key !== 'name' && key !== 'status') ||
      !Object.keys(command.patch).length
    )
      return false;
    if (
      command.patch.name !== undefined &&
      (!command.patch.name.trim() ||
        command.patch.name.length > 120 ||
        Array.from(command.patch.name).some(
          (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
        ))
    )
      return false;
    if (
      command.patch.status !== undefined &&
      !['active', 'suspended'].includes(command.patch.status)
    )
      return false;
  }
  return true;
}
async function audit(
  client: PoolClient,
  actor: OwnerRow,
  action: string,
  operator: string | undefined,
  version: number | undefined,
  summary: Record<string, string | number | boolean>,
  context: { policyVersion: number; mfaVerifiedAt: Date; requestId: string },
) {
  await client.query(
    "INSERT INTO public.management_audit(id,actor_id,action,operator_id,actor_version,target_version,summary,owner_policy_version,mfa_verified_at,outcome,request_id) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,'success',$10)",
    [
      randomUUID(),
      actor.id,
      action,
      operator ?? null,
      actor.authorization_version,
      version ?? null,
      JSON.stringify(summary),
      context.policyVersion,
      context.mfaVerifiedAt,
      context.requestId,
    ],
  );
}
/** Owner policy gate always precedes a tenant gate. Existing client reducers never
 * acquire owner locks, so the two realms cannot invert each other's lock order.
 * No database lease spans HTTP, credential verification or browser interaction.
 */
async function lockTenant(
  client: PoolClient,
  operator: string,
  exclusive: boolean,
): Promise<true | 'unavailable' | 'not_found'> {
  await client.query(
    `SELECT pg_catalog.${exclusive ? 'pg_advisory_xact_lock' : 'pg_advisory_xact_lock_shared'}(pg_catalog.hashtextextended('vaultx.viewer.policy:' || $1::uuid::text,0))`,
    [operator],
  );
  const policy = await client.query(
    `SELECT operator_id FROM public.operator_access_policies WHERE operator_id=$1 FOR ${exclusive ? 'UPDATE' : 'SHARE'}`,
    [operator],
  );
  if (!policy.rowCount) {
    // An advisory pre-gate does not replace the required policy row gate.
    // This probe selects only a denial status; it can never authorize a read/write.
    const known = await client.query('SELECT id FROM public.operators WHERE id=$1', [operator]);
    return known.rowCount ? 'unavailable' : 'not_found';
  }
  if (exclusive) {
    const count = await client.query<{ count: string }>(
      'SELECT count(*) FROM public.dashboard_memberships WHERE operator_id=$1',
      [operator],
    );
    if (Number(count.rows[0]?.count) > 1000) return 'unavailable';
    await client.query(
      'SELECT id FROM public.dashboard_users WHERE id IN(SELECT user_id FROM public.dashboard_memberships WHERE operator_id=$1) ORDER BY id FOR UPDATE',
      [operator],
    );
    await client.query(
      'SELECT id FROM public.dashboard_memberships WHERE operator_id=$1 ORDER BY id FOR UPDATE',
      [operator],
    );
  }
  await client.query(
    `SELECT id FROM public.operators WHERE id=$1 FOR ${exclusive ? 'UPDATE' : 'SHARE'}`,
    [operator],
  );
  if (exclusive) {
    await client.query(
      'SELECT id FROM public.membership_permission_grants WHERE operator_id=$1 ORDER BY membership_id,permission_code,id FOR UPDATE',
      [operator],
    );
    await client.query(
      'SELECT token_hash FROM public.dashboard_sessions WHERE membership_id IN(SELECT id FROM public.dashboard_memberships WHERE operator_id=$1) ORDER BY token_hash FOR UPDATE',
      [operator],
    );
  }
  return true;
}

const ownerSessionEligibility = `token_hash=$1 AND owner_id=$2 AND authorization_version=$3 AND policy_version=$4 AND assurance='mfa'
 AND created_at<=clock_timestamp() AND last_seen_at<=clock_timestamp() AND mfa_verified_at<=clock_timestamp()
 AND mfa_verified_at>=created_at-interval '5 minutes'
 AND created_at>clock_timestamp()-interval '1 hour' AND last_seen_at>clock_timestamp()-interval '15 minutes'`;
async function currentOwnerSession(
  client: PoolClient,
  tokenHash: string,
  actor: OwnerRow,
  policyVersion: number,
) {
  return (
    await client.query<{ csrf_hash: string; fresh: boolean; mfa_verified_at: Date }>(
      `SELECT csrf_hash,mfa_verified_at,mfa_verified_at>clock_timestamp()-interval '5 minutes' AS fresh FROM public.owner_sessions WHERE ${ownerSessionEligibility}`,
      [tokenHash, actor.id, actor.authorization_version, policyVersion],
    )
  ).rows[0];
}
async function refreshOwnerSession(
  client: PoolClient,
  tokenHash: string,
  actor: OwnerRow,
  policyVersion: number,
  fresh: boolean,
  csrfHash?: string,
) {
  const refreshed = await client.query(
    `UPDATE public.owner_sessions SET last_seen_at=clock_timestamp(),csrf_hash=COALESCE($6,csrf_hash)
     WHERE ${ownerSessionEligibility} AND (NOT $5::boolean OR mfa_verified_at>clock_timestamp()-interval '5 minutes') RETURNING token_hash`,
    [tokenHash, actor.id, actor.authorization_version, policyVersion, fresh, csrfHash ?? null],
  );
  // This may follow a mutation/audit: throwing is mandatory to roll back ALL work.
  if (refreshed.rowCount !== 1) throw new Error('Owner session unavailable.');
}

/** Sole management application entry point. No caller-supplied actor/permissions.
 * No enrollment/session issuer, account creation, grant issuance or automatic retry.
 * Database assurance records are consumed only; their production issuer is deferred.
 */
export async function executeManagement(
  pool: Pool,
  tokenHash: string,
  command: ManagementCommand,
  requestId?: string,
): Promise<ManagementResult> {
  if (!digestPattern.test(tokenHash)) return denied('unauthorized');
  if (!valid(command)) return denied('invalid_input');
  const correlation =
    requestId && /^[A-Za-z0-9._:-]{1,80}$/.test(requestId) ? requestId : randomUUID();
  try {
    return await withReadClient(
      pool,
      async (client) => {
        await client.query(
          "SELECT pg_catalog.pg_advisory_xact_lock_shared(pg_catalog.hashtextextended('vaultx.owner.policy',0))",
        );
        const policy = await client.query<{ authorization_version: number }>(
          "SELECT authorization_version FROM public.management_policy WHERE id='platform' FOR SHARE",
        );
        if (!policy.rows[0]) return denied('unauthorized');
        const candidate = await client.query<{ owner_id: string }>(
          'SELECT owner_id FROM public.owner_sessions WHERE token_hash=$1',
          [tokenHash],
        );
        if (!candidate.rows[0]) return denied('unauthorized');
        const principal = await client.query<OwnerRow>(
          'SELECT id,username,status,enrollment_verified,authorization_version FROM public.owner_principals WHERE id=$1 FOR SHARE',
          [candidate.rows[0].owner_id],
        );
        const actor = principal.rows[0];
        if (!actor || actor.status !== 'active' || !actor.enrollment_verified)
          return denied('unauthorized');
        const grants = await client.query<{ permission: string }>(
          "SELECT g.permission FROM public.owner_permission_grants g JOIN public.owner_permission_catalog c ON c.code=g.permission AND c.realm='owner' WHERE g.owner_id=$1 AND g.revoked_at IS NULL ORDER BY g.permission,g.id FOR SHARE OF g",
          [actor.id],
        );
        const permissions = OWNER_PERMISSIONS.filter((permission) =>
          grants.rows.some((row) => row.permission === permission),
        );
        // Lock first, then use a fresh wall-clock statement. A clock predicate
        // evaluated before a row-lock wait must never revive an expired session.
        await client.query(
          'SELECT token_hash FROM public.owner_sessions WHERE token_hash=$1 FOR UPDATE',
          [tokenHash],
        );
        const policyVersion = policy.rows[0].authorization_version;
        let active = await currentOwnerSession(client, tokenHash, actor, policyVersion);
        if (!active) return denied('unauthorized');
        if (command.action === 'logout') {
          if (!matchesCsrf(command.csrfHash, active.csrf_hash)) return denied('forbidden');
          await refreshOwnerSession(client, tokenHash, actor, policyVersion, false);
          await client.query('DELETE FROM public.owner_sessions WHERE token_hash=$1', [tokenHash]);
          return ok(undefined);
        }
        if (command.action === 'csrf.rotate') {
          await refreshOwnerSession(
            client,
            tokenHash,
            actor,
            policyVersion,
            false,
            command.newCsrfHash,
          );
          return ok(undefined);
        }
        if (command.action === 'identity') {
          await refreshOwnerSession(client, tokenHash, actor, policyVersion, false);
          return ok({
            owner: { id: actor.id, username: actor.username },
            permissions,
            authorizationVersion: actor.authorization_version,
          });
        }
        const permission = writes(command)
          ? 'platform.clients.manage'
          : command.action === 'audit.list'
            ? 'platform.audit.read'
            : 'platform.clients.read';
        if (!permissions.includes(permission)) return denied('forbidden');
        if (
          writes(command) &&
          (!active.fresh ||
            !('csrfHash' in command) ||
            !matchesCsrf(command.csrfHash, active.csrf_hash))
        )
          return denied('forbidden');
        const targetId = 'targetId' in command ? command.targetId : undefined;
        let operator: OperatorRow | undefined;
        if (targetId) {
          const tenant = await lockTenant(client, targetId, writes(command));
          if (tenant !== true) return denied(tenant);
          operator = (
            await client.query<OperatorRow>(
              'SELECT id,code,name,status,management_version FROM public.operators WHERE id=$1',
              [targetId],
            )
          ).rows[0];
          if (!operator) return denied('not_found');
        }
        active = await currentOwnerSession(client, tokenHash, actor, policyVersion);
        if (!active) return denied('unauthorized');
        if (
          writes(command) &&
          (!active.fresh ||
            !('csrfHash' in command) ||
            !matchesCsrf(command.csrfHash, active.csrf_hash))
        )
          return denied('forbidden');
        let value: unknown;
        let summary: Record<string, string | number | boolean> = {};
        switch (command.action) {
          case 'operators.list': {
            const result = await client.query<OperatorRow>(
              'SELECT id,code,name,status,management_version FROM public.operators ORDER BY id LIMIT $1 OFFSET $2',
              [command.limit + 1, command.offset],
            );
            value = {
              operators: result.rows.slice(0, command.limit).map(operatorDto),
              pagination: {
                limit: command.limit,
                offset: command.offset,
                hasMore: result.rows.length > command.limit,
              },
            };
            summary = {
              limit: command.limit,
              offset: command.offset,
              returned: Math.min(command.limit, result.rows.length),
            };
            break;
          }
          case 'operators.detail':
            value = { operator: operatorDto(operator!) };
            break;
          case 'members.list':
          case 'members.detail': {
            const members =
              command.action === 'members.list'
                ? await client.query<MemberRow>(
                    'SELECT id,status,role,authorization_version FROM public.dashboard_memberships WHERE operator_id=$1 ORDER BY id LIMIT $2 OFFSET $3',
                    [targetId, command.limit + 1, command.offset],
                  )
                : await client.query<MemberRow>(
                    'SELECT id,status,role,authorization_version FROM public.dashboard_memberships WHERE operator_id=$1 AND id=$2',
                    [targetId, command.membershipId],
                  );
            if (command.action === 'members.detail' && !members.rows[0]) return denied('not_found');
            const selected =
              command.action === 'members.list'
                ? members.rows.slice(0, command.limit)
                : members.rows;
            const detailed = [];
            for (const member of selected) {
              const grants = await client.query<{
                id: string;
                permission_code: string;
                revoked_at: Date | null;
              }>(
                'SELECT id,permission_code,revoked_at FROM public.membership_permission_grants WHERE operator_id=$1 AND membership_id=$2 ORDER BY permission_code,id',
                [targetId, member.id],
              );
              detailed.push({
                ...memberDto(member),
                grants: grants.rows.map((grant) => ({
                  id: grant.id,
                  permission: grant.permission_code,
                  revokedAt: grant.revoked_at?.toISOString() ?? null,
                })),
              });
            }
            value =
              command.action === 'members.list'
                ? {
                    operatorId: targetId,
                    members: detailed,
                    pagination: {
                      limit: command.limit,
                      offset: command.offset,
                      hasMore: members.rows.length > command.limit,
                    },
                  }
                : { operatorId: targetId, member: detailed[0] };
            summary = { returned: detailed.length };
            break;
          }
          case 'operators.update': {
            if (operator!.management_version !== command.expectedVersion) return denied('conflict');
            const updated = await client.query<OperatorRow>(
              'UPDATE public.operators SET name=COALESCE($2,name),status=COALESCE($3,status),management_version=$4 WHERE id=$1 RETURNING id,code,name,status,management_version',
              [
                targetId,
                command.patch.name?.trim() ?? null,
                command.patch.status ?? null,
                command.expectedVersion + 1,
              ],
            );
            operator = updated.rows[0]!;
            value = { operator: operatorDto(operator) };
            summary = {
              nameChanged: command.patch.name !== undefined,
              status: operator.status,
              version: operator.management_version,
            };
            break;
          }
          case 'entitlements.withdraw': {
            if (operator!.management_version !== command.expectedVersion) return denied('conflict');
            const changed = await client.query(
              'UPDATE public.operator_permission_entitlements SET enabled=false WHERE operator_id=$1 AND permission_code=$2 AND enabled RETURNING permission_code',
              [targetId, command.permission],
            );
            if (!changed.rowCount) return denied('conflict');
            operator = (
              await client.query<OperatorRow>(
                'UPDATE public.operators SET management_version=$2 WHERE id=$1 RETURNING id,code,name,status,management_version',
                [targetId, command.expectedVersion + 1],
              )
            ).rows[0]!;
            const revision = await client.query<{ authorization_version: number }>(
              'SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=$1',
              [targetId],
            );
            value = {
              operator: operatorDto(operator),
              policyVersion: revision.rows[0]!.authorization_version,
            };
            summary = {
              permission: command.permission,
              version: operator.management_version,
              policyVersion: revision.rows[0]!.authorization_version,
            };
            break;
          }
          case 'audit.list': {
            const events = await client.query<{
              id: string;
              actor_id: string;
              action: string;
              operator_id: string | null;
              occurred_at: Date;
              summary: unknown;
            }>(
              'SELECT id,actor_id,action,operator_id,occurred_at,summary FROM public.management_audit WHERE ($1::uuid IS NULL OR operator_id=$1) ORDER BY occurred_at DESC,id DESC LIMIT $2 OFFSET $3',
              [targetId ?? null, command.limit + 1, command.offset],
            );
            value = {
              events: events.rows.slice(0, command.limit).map((event) => ({
                id: event.id,
                actorId: event.actor_id,
                action: event.action,
                operatorId: event.operator_id,
                occurredAt: event.occurred_at.toISOString(),
                summary: event.summary,
              })),
              pagination: {
                limit: command.limit,
                offset: command.offset,
                hasMore: events.rows.length > command.limit,
              },
            };
            summary = {
              limit: command.limit,
              offset: command.offset,
              returned: Math.min(command.limit, events.rows.length),
            };
            break;
          }
        }
        await audit(
          client,
          actor,
          command.action,
          targetId,
          operator?.management_version,
          summary,
          { policyVersion, mfaVerifiedAt: active.mfa_verified_at, requestId: correlation },
        );
        await refreshOwnerSession(client, tokenHash, actor, policyVersion, writes(command));
        return ok(value);
      },
      { readOnly: false, readCommitted: true, statementMs: 4000, lockMs: 1000, totalMs: 6000 },
    );
  } catch {
    return denied('unavailable');
  }
}
