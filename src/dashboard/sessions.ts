import type { TerminalReadScope } from '../payments/internal-read.js';
import type { Request } from 'express';
import { withReadClient } from '../db/read-client.js';
import {
  lockViewerIdentity,
  effectiveViewerPermissions,
  type ViewerPermission,
} from './permissions.js';
import type { Pool } from 'pg';

export const DASHBOARD_SESSION_COOKIE = '__Host-vaultx_session';
export function dashboardSessionToken(req: Request): string | undefined {
  const values = (req.headers.cookie ?? '')
    .split(';')
    .map((v) => v.trim())
    .filter((v) => v.startsWith(DASHBOARD_SESSION_COOKIE + '='));
  if (values.length !== 1) return undefined;
  const value = values[0]!.slice(DASHBOARD_SESSION_COOKIE.length + 1);
  return /^[a-f0-9]{64}$/.test(value) ? value : undefined;
}

export interface DashboardIdentity {
  user_id: string;
  username: string;
  operator_id: string;
  permissions: ViewerPermission[];
  permissionAllowed: boolean;
  terminalScope?: TerminalReadScope;
  passkeyRequired: boolean;
  passkeyVerified: boolean;
  passkeyFresh: boolean;
}
/** Shared pre-gate → policy row → ordered identities/grants → session.
 * Recheck wall-clock expiry AFTER acquiring the session lock, not at transaction start.
 */
export async function touchDashboardSession(
  pool: Pool,
  tokenHash: string,
  required?: ViewerPermission,
  allowTerminalReads = false,
): Promise<DashboardIdentity | undefined> {
  try {
    return await withReadClient(
      pool,
      async (client) => {
        const candidate = await client.query<{
          user_id: string;
          membership_id: string;
          operator_id: string;
        }>(
          `SELECT s.user_id,s.membership_id,m.operator_id FROM public.dashboard_sessions s JOIN public.dashboard_memberships m ON m.id=s.membership_id AND m.user_id=s.user_id WHERE s.token_hash=$1`,
          [tokenHash],
        );
        const row = candidate.rows[0];
        if (!row) return undefined;
        const identity = await lockViewerIdentity(
          client,
          row.user_id,
          row.membership_id,
          row.operator_id,
        );
        if (!identity) return undefined;
        const permissions = await effectiveViewerPermissions(
          client,
          row.membership_id,
          row.operator_id,
          allowTerminalReads,
        );
        const assurance = await client.query<{
          required: boolean;
          verified: boolean;
          fresh: boolean;
        }>(
          `SELECT EXISTS(SELECT 1 FROM public.merchant_member_profiles WHERE membership_id=s.membership_id) AS required,
           public.dashboard_session_has_webauthn(s) AS verified,
           COALESCE(s.webauthn_verified_at>clock_timestamp()-interval '5 minutes',false) AS fresh
           FROM public.dashboard_sessions s WHERE s.token_hash=$1`,
          [tokenHash],
        );
        const proof = assurance.rows[0];
        const effective = proof && (!proof.required || proof.verified) ? permissions : [];
        let terminalScope: TerminalReadScope | undefined;
        let scopeAllowed = true;
        if (
          allowTerminalReads &&
          (
            await client.query(
              "SELECT 1 FROM public.merchant_member_profiles WHERE membership_id=$1 AND kind='submerchant'",
              [row.membership_id],
            )
          ).rowCount
        ) {
          const terminals = await client.query<{ terminal_id: string }>(
            `SELECT a.terminal_id FROM public.merchant_terminal_assignments a JOIN public.merchant_terminals t ON t.id=a.terminal_id AND t.operator_id=a.operator_id AND t.status='active'
            WHERE a.membership_id=$1 AND a.operator_id=$2 AND a.revoked_at IS NULL ORDER BY a.terminal_id`,
            [row.membership_id, row.operator_id],
          );
          scopeAllowed =
            terminals.rows.length > 0 && terminals.rows.length <= 100 && proof?.verified === true;
          terminalScope = {
            userId: row.user_id,
            membershipId: row.membership_id,
            sessionHash: tokenHash,
            membershipVersion: identity.membershipVersion,
            operatorVersion: identity.operatorVersion,
            terminalIds: terminals.rows.map((t) => t.terminal_id),
          };
        }
        const permissionAllowed =
          (required === undefined || effective.includes(required)) && scopeAllowed;
        await client.query(
          'SELECT token_hash FROM public.dashboard_sessions WHERE token_hash = $1 FOR UPDATE /* dashboard-touch-lock */',
          [tokenHash],
        );
        const updated = await client.query(
          `UPDATE public.dashboard_sessions s SET last_seen_at = clock_timestamp()
        FROM public.dashboard_users u, public.dashboard_memberships m, public.operators o
        WHERE s.token_hash = $1 AND u.id = s.user_id AND m.id = s.membership_id AND m.user_id = u.id
          AND o.id = m.operator_id AND u.status = 'active' AND o.status = 'active' AND s.auth_version = u.auth_version
          AND m.status='active' AND m.role='viewer'
          AND s.membership_authz_version=m.authorization_version
          AND s.operator_authz_version=(SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=m.operator_id)
          AND s.created_at > clock_timestamp() - INTERVAL '8 hours'
          AND s.last_seen_at > clock_timestamp() - INTERVAL '30 minutes'
        RETURNING s.token_hash`,
          [tokenHash],
        );
        return updated.rowCount === 1
          ? {
              user_id: row.user_id,
              username: identity.user.username,
              operator_id: row.operator_id,
              permissions: effective,
              ...(terminalScope ? { terminalScope } : {}),
              permissionAllowed,
              passkeyRequired: proof?.required === true,
              passkeyVerified: proof?.verified === true,
              passkeyFresh: proof?.verified === true && proof.fresh,
            }
          : undefined;
      },
      { readOnly: false, readCommitted: true, statementMs: 5000, lockMs: 2000, totalMs: 6000 },
    );
  } catch {
    throw new Error('Dashboard session unavailable.');
  }
}
