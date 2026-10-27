import { randomUUID, timingSafeEqual } from 'node:crypto';
import type { Pool } from 'pg';
import { z } from 'zod';
import { withReadClient } from '../db/read-client.js';
import type { ManagementResult } from './domain.js';
import {
  createMerchantInvitation,
  effectiveMerchantPermissions,
  revokeMerchantProfile,
  withdrawMerchantGrant,
} from './merchant-domain.js';

const page = { limit: z.number().int().min(1).max(50), offset: z.number().int().min(0).max(10000) };
const revision = z.number().int().min(1).max(2147483647);
const readPermission = z.enum(['client.payments.read', 'client.status.read']);
const commandSchema = z.discriminatedUnion('action', [
  z.object({ action: z.literal('identity') }).strict(),
  z.object({ action: z.literal('members.list'), ...page }).strict(),
  z.object({ action: z.literal('terminals.list'), ...page }).strict(),
  z.object({ action: z.literal('audit.list'), ...page }).strict(),
  z
    .object({
      action: z.literal('invitations.create'),
      username: z.string().regex(/^[a-z0-9][a-z0-9_.-]{2,79}$/),
      permissions: z.array(readPermission).min(1).max(2),
      terminalIds: z.array(z.uuid()).max(50),
    })
    .strict(),
  z
    .object({
      action: z.literal('members.disable'),
      membershipId: z.uuid(),
      expectedVersion: revision,
    })
    .strict(),
  z
    .object({
      action: z.literal('grants.withdraw'),
      membershipId: z.uuid(),
      permission: readPermission,
      expectedVersion: revision,
    })
    .strict(),
]);
export type MerchantCommand = z.infer<typeof commandSchema>;
const required = {
  'members.list': 'client.users.read',
  'terminals.list': 'client.terminals.read',
  'audit.list': 'client.audit.read',
  'invitations.create': 'client.users.manage_subaccounts',
  'members.disable': 'client.users.manage_subaccounts',
  'grants.withdraw': 'client.permissions.delegate',
} as const;
const hash = /^[a-f0-9]{64}$/;
const deny = (
  error: 'unauthorized' | 'forbidden' | 'not_found' | 'conflict' | 'invalid_input',
): ManagementResult => ({ ok: false, error });

/** Single authorization + mutation transaction. Tenant comes only from the
 * authenticated session. The exclusive tenant gate serializes management with
 * existing shared admissions and reducers; identities/grants precede sessions.
 * No lock spans password hashing, HTTP, invitation delivery or browser activity.
 */
export async function executeMerchantCommand(
  pool: Pool,
  tokenHash: string,
  command: MerchantCommand,
  csrfHash?: string,
  requestId?: string,
): Promise<ManagementResult> {
  if (!hash.test(tokenHash)) return deny('unauthorized');
  const parsed = commandSchema.safeParse(command);
  if (!parsed.success) return deny('invalid_input');
  command = parsed.data;
  const writing = ['invitations.create', 'members.disable', 'grants.withdraw'].includes(
    command.action,
  );
  const correlation =
    requestId && /^[A-Za-z0-9._:-]{1,80}$/.test(requestId) ? requestId : randomUUID();
  try {
    return await withReadClient(
      pool,
      async (client) => {
        const candidate = (
          await client.query<{ user_id: string; membership_id: string; operator_id: string }>(
            `SELECT s.user_id,s.membership_id,m.operator_id FROM public.dashboard_sessions s
         JOIN public.dashboard_memberships m ON m.id=s.membership_id AND m.user_id=s.user_id WHERE s.token_hash=$1`,
            [tokenHash],
          )
        ).rows[0];
        if (!candidate) return deny('unauthorized');
        const tenant = candidate.operator_id;
        await client.query(
          "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('vaultx.viewer.policy:' || $1::uuid::text,0))",
          [tenant],
        );
        if (
          !(
            await client.query(
              'SELECT operator_id FROM public.operator_access_policies WHERE operator_id=$1 FOR UPDATE',
              [tenant],
            )
          ).rowCount
        )
          return deny('unauthorized');
        const count = (
          await client.query<{ count: string }>(
            'SELECT count(*) FROM public.dashboard_memberships WHERE operator_id=$1',
            [tenant],
          )
        ).rows[0];
        if (!count || Number(count.count) > 1000) return { ok: false, error: 'unavailable' };
        await client.query(
          'SELECT id FROM public.dashboard_users WHERE id IN(SELECT user_id FROM public.dashboard_memberships WHERE operator_id=$1) ORDER BY id FOR UPDATE',
          [tenant],
        );
        await client.query(
          'SELECT id FROM public.dashboard_memberships WHERE operator_id=$1 ORDER BY id FOR UPDATE',
          [tenant],
        );
        await client.query('SELECT id FROM public.operators WHERE id=$1 FOR UPDATE', [tenant]);
        await client.query(
          'SELECT id FROM public.membership_permission_grants WHERE operator_id=$1 ORDER BY membership_id,permission_code,id FOR UPDATE',
          [tenant],
        );
        await client.query(
          'SELECT token_hash FROM public.dashboard_sessions WHERE membership_id IN(SELECT id FROM public.dashboard_memberships WHERE operator_id=$1) ORDER BY token_hash FOR UPDATE',
          [tenant],
        );
        // Wall-clock predicates run AFTER all lock waits. Never revive expired
        // sessions or follow changed identity/tenant fields from the initial probe.
        const actor = (
          await client.query<{
            csrf_hash: string;
            authorization_version: number;
            username: string;
          }>(
            `SELECT s.csrf_hash,m.authorization_version,u.username FROM public.dashboard_sessions s
         JOIN public.dashboard_users u ON u.id=s.user_id AND u.status='active'
         JOIN public.dashboard_memberships m ON m.id=s.membership_id AND m.user_id=u.id AND m.status='active' AND m.role='viewer'
         JOIN public.operators o ON o.id=m.operator_id AND o.status='active'
         JOIN public.operator_access_policies p ON p.operator_id=o.id
         JOIN public.merchant_member_profiles mp ON mp.membership_id=m.id AND mp.operator_id=o.id AND mp.kind='merchant_admin'
         WHERE s.token_hash=$1 AND s.user_id=$2 AND s.membership_id=$3 AND o.id=$4
         AND public.dashboard_session_has_webauthn(s)
         AND s.auth_version=u.auth_version AND s.membership_authz_version=m.authorization_version AND s.operator_authz_version=p.authorization_version
         AND s.created_at<=clock_timestamp() AND s.last_seen_at<=clock_timestamp()
         AND s.created_at>clock_timestamp()-interval '8 hours' AND s.last_seen_at>clock_timestamp()-interval '30 minutes'
         AND (NOT $5::boolean OR s.webauthn_verified_at>clock_timestamp()-interval '5 minutes')`,
            [tokenHash, candidate.user_id, candidate.membership_id, tenant, writing],
          )
        ).rows[0];
        if (!actor) return deny('unauthorized');
        const permissions = await effectiveMerchantPermissions(
          client,
          candidate.membership_id,
          tenant,
        );
        if (command.action === 'identity') {
          const refreshed = await client.query(
            `UPDATE public.dashboard_sessions SET last_seen_at=clock_timestamp() WHERE token_hash=$1
            AND created_at>clock_timestamp()-interval '8 hours' AND last_seen_at>clock_timestamp()-interval '30 minutes' RETURNING token_hash`,
            [tokenHash],
          );
          if (refreshed.rowCount !== 1) throw new Error('Merchant session unavailable.');
          return {
            ok: true,
            value: {
              user: { id: candidate.user_id, username: actor.username },
              operator: { id: tenant },
              membership: { id: candidate.membership_id, version: actor.authorization_version },
              permissions,
            },
          };
        }
        if (!permissions.includes(required[command.action])) return deny('forbidden');
        if (
          writing &&
          (!csrfHash ||
            !hash.test(csrfHash) ||
            !timingSafeEqual(Buffer.from(csrfHash, 'hex'), Buffer.from(actor.csrf_hash, 'hex')))
        )
          return deny('forbidden');
        let value: unknown;
        let targetVersion: number | null = null;
        const target = 'membershipId' in command ? command.membershipId : null;
        if (target) {
          // Administrator cannot edit another administrator, self, legacy viewer,
          // or another sponsor's restricted account, even inside this tenant.
          const member = (
            await client.query<{ authorization_version: number; status: string }>(
              `SELECT m.authorization_version,m.status FROM public.dashboard_memberships m JOIN public.merchant_member_profiles p
           ON p.membership_id=m.id AND p.operator_id=m.operator_id WHERE m.id=$1 AND m.operator_id=$2 AND p.kind='submerchant' AND p.sponsor_membership_id=$3`,
              [target, tenant, candidate.membership_id],
            )
          ).rows[0];
          if (!member) return deny('not_found');
          if (
            !('expectedVersion' in command) ||
            member.authorization_version !== command.expectedVersion ||
            member.status !== 'active'
          )
            return deny('conflict');
        }
        if (command.action === 'invitations.create') {
          if (
            !permissions.includes('client.permissions.delegate') ||
            command.permissions.some((p) => !permissions.includes(p)) ||
            new Set(command.permissions).size !== command.permissions.length ||
            new Set(command.terminalIds).size !== command.terminalIds.length
          )
            return deny('forbidden');
          value = await createMerchantInvitation(client, {
            operatorId: tenant,
            sponsorMembershipId: candidate.membership_id,
            kind: 'submerchant',
            username: command.username,
            permissions: command.permissions,
            terminalIds: command.terminalIds,
          });
        } else if (command.action === 'members.disable' || command.action === 'grants.withdraw') {
          const changed =
            command.action === 'members.disable'
              ? await revokeMerchantProfile(client, {
                  operatorId: tenant,
                  membershipId: command.membershipId,
                })
              : await withdrawMerchantGrant(client, {
                  operatorId: tenant,
                  membershipId: command.membershipId,
                  permission: command.permission,
                });
          if (!changed.revoked) return deny('conflict');
          targetVersion = (
            await client.query<{ authorization_version: number }>(
              'SELECT authorization_version FROM public.dashboard_memberships WHERE id=$1 AND operator_id=$2',
              [target, tenant],
            )
          ).rows[0]!.authorization_version;
          value = { revoked: true, version: targetVersion };
        } else if (command.action === 'members.list') {
          const rows = await client.query(
            `SELECT m.id,m.status,u.username,p.kind,p.sponsor_membership_id AS "sponsorMembershipId",m.authorization_version AS version FROM public.dashboard_memberships m
          JOIN public.dashboard_users u ON u.id=m.user_id LEFT JOIN public.merchant_member_profiles p ON p.membership_id=m.id AND p.operator_id=m.operator_id
          WHERE m.operator_id=$1 ORDER BY m.id LIMIT $2 OFFSET $3`,
            [tenant, command.limit + 1, command.offset],
          );
          value = {
            members: rows.rows.slice(0, command.limit),
            pagination: {
              limit: command.limit,
              offset: command.offset,
              hasMore: rows.rows.length > command.limit,
            },
          };
        } else if (command.action === 'terminals.list') {
          const rows = await client.query(
            'SELECT id,code,name,status FROM public.merchant_terminals WHERE operator_id=$1 ORDER BY id LIMIT $2 OFFSET $3',
            [tenant, command.limit + 1, command.offset],
          );
          value = {
            terminals: rows.rows.slice(0, command.limit),
            pagination: {
              limit: command.limit,
              offset: command.offset,
              hasMore: rows.rows.length > command.limit,
            },
          };
        } else if (command.action === 'audit.list') {
          const rows = await client.query(
            'SELECT id,actor_membership_id,action,target_membership_id,target_version,occurred_at,summary FROM public.merchant_audit WHERE operator_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT $2 OFFSET $3',
            [tenant, command.limit + 1, command.offset],
          );
          value = {
            events: rows.rows.slice(0, command.limit),
            pagination: {
              limit: command.limit,
              offset: command.offset,
              hasMore: rows.rows.length > command.limit,
            },
          };
        }
        await client.query(
          `INSERT INTO public.merchant_audit(id,actor_membership_id,operator_id,action,actor_version,request_id,target_membership_id,target_version,summary)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`,
          [
            randomUUID(),
            candidate.membership_id,
            tenant,
            command.action,
            actor.authorization_version,
            correlation,
            target,
            targetVersion,
            JSON.stringify(
              command.action === 'grants.withdraw'
                ? { permission: command.permission, revoked: true, version: targetVersion }
                : command.action === 'members.disable'
                  ? { revoked: true, version: targetVersion }
                  : command.action === 'invitations.create'
                    ? {
                        invitationId: (value as { invitationId: string }).invitationId,
                        kind: 'submerchant',
                      }
                    : { limit: command.limit, offset: command.offset },
            ),
          ],
        );
        const refreshed = await client.query(
          `UPDATE public.dashboard_sessions SET last_seen_at=clock_timestamp() WHERE token_hash=$1
        AND created_at>clock_timestamp()-interval '8 hours' AND last_seen_at>clock_timestamp()-interval '30 minutes' RETURNING token_hash`,
          [tokenHash],
        );
        if (refreshed.rowCount !== 1) throw new Error('Merchant session unavailable.');
        return { ok: true, value };
      },
      { readOnly: false, readCommitted: true, statementMs: 4000, lockMs: 1000, totalMs: 6000 },
    );
  } catch {
    return { ok: false, error: 'unavailable' };
  }
}
