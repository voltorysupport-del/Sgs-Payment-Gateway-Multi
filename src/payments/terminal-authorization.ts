import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { withReadClient } from '../db/read-client.js';
import { lockViewerIdentity } from '../dashboard/permissions.js';
import { effectiveMerchantPermissions } from '../management/merchant-domain.js';
import { InvalidReadRestriction, type TerminalReadScope } from './internal-read.js';

/** Final authorization and materialization share one bounded transaction. Never
 * hold a connection while waiting on the loopback HTTP request. Mutation paths
 * must own the exclusive tenant pre-gate before locking any policy/identity row.
 */
export function withTerminalAuthorization<T>(
  pool: Pool,
  apiKey: string,
  operatorId: string,
  scope: TerminalReadScope,
  permission: 'client.payments.read' | 'client.status.read',
  read: (client: PoolClient, terminals: string[]) => Promise<T>,
): Promise<T> {
  return withReadClient(
    pool,
    async (client) => {
      const identity = await lockViewerIdentity(
        client,
        scope.userId,
        scope.membershipId,
        operatorId,
      );
      if (
        !identity ||
        identity.membershipVersion !== scope.membershipVersion ||
        identity.operatorVersion !== scope.operatorVersion
      )
        throw new InvalidReadRestriction();
      const profile = await client.query(
        "SELECT membership_id FROM public.merchant_member_profiles WHERE membership_id=$1 AND operator_id=$2 AND kind='submerchant'",
        [scope.membershipId, operatorId],
      );
      if (
        !profile.rowCount ||
        !(await effectiveMerchantPermissions(client, scope.membershipId, operatorId)).includes(
          permission,
        )
      )
        throw new InvalidReadRestriction();
      // Acquire each row class explicitly; do not depend on join row-mark order.
      await client.query(
        'SELECT id FROM public.merchant_terminals WHERE operator_id=$1 AND id=ANY($2::uuid[]) ORDER BY id FOR SHARE',
        [operatorId, scope.terminalIds],
      );
      const assigned = await client.query<{ terminal_id: string }>(
        `SELECT a.terminal_id FROM public.merchant_terminal_assignments a
      JOIN public.merchant_terminals t ON t.id=a.terminal_id AND t.operator_id=a.operator_id AND t.status='active'
      WHERE a.operator_id=$1 AND a.membership_id=$2 AND a.revoked_at IS NULL ORDER BY a.terminal_id FOR SHARE OF a`,
        [operatorId, scope.membershipId],
      );
      const terminals = assigned.rows.map((r) => r.terminal_id);
      if (
        !terminals.length ||
        terminals.length > 100 ||
        JSON.stringify(terminals) !== JSON.stringify(scope.terminalIds)
      )
        throw new InvalidReadRestriction();
      // Lock session after identities/assignments, then evaluate wall-clock expiry.
      await client.query(
        'SELECT token_hash FROM public.dashboard_sessions WHERE token_hash=$1 FOR SHARE',
        [scope.sessionHash],
      );
      const key = await client.query(
        `SELECT id FROM public.operator_api_keys WHERE operator_id=$1 AND key_hash=$2
      AND permission='read_only' AND revoked_at IS NULL FOR SHARE`,
        [operatorId, createHash('sha256').update(apiKey).digest('hex')],
      );
      if (!key.rowCount) throw new InvalidReadRestriction();
      const session = await client.query(
        `SELECT s.token_hash FROM public.dashboard_sessions s
      WHERE s.token_hash=$1 AND s.user_id=$2 AND s.membership_id=$3 AND s.auth_version=$4
      AND s.membership_authz_version=$5 AND s.operator_authz_version=$6
      AND s.created_at<=clock_timestamp() AND s.last_seen_at<=clock_timestamp()
      AND s.created_at>clock_timestamp()-interval '8 hours' AND s.last_seen_at>clock_timestamp()-interval '30 minutes'
      AND public.dashboard_session_has_webauthn(s)`,
        [
          scope.sessionHash,
          scope.userId,
          scope.membershipId,
          identity.user.auth_version,
          scope.membershipVersion,
          scope.operatorVersion,
        ],
      );
      if (!session.rowCount) throw new InvalidReadRestriction();
      return read(client, terminals);
    },
    { readOnly: false, readCommitted: true, totalMs: 3500, lockMs: 500, statementMs: 1500 },
  );
}
