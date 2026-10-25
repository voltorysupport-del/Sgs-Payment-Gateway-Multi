import type { Pool } from 'pg';

export interface DashboardIdentity {
  user_id: string;
  username: string;
  operator_id: string;
}
/** Lock identities before the session (same direction as invalidation triggers).
 * Recheck wall-clock expiry AFTER acquiring the session lock, not at transaction start.
 */
export async function touchDashboardSession(
  pool: Pool,
  tokenHash: string,
): Promise<DashboardIdentity | undefined> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL statement_timeout = '5000ms'; SET LOCAL lock_timeout = '2000ms'");
    const identity = await client.query<DashboardIdentity>(
      `SELECT u.id AS user_id, u.username, m.operator_id
      FROM public.dashboard_sessions s
      JOIN public.dashboard_users u ON u.id = s.user_id
      JOIN public.dashboard_memberships m ON m.id = s.membership_id AND m.user_id = u.id
      JOIN public.operators o ON o.id = m.operator_id
      WHERE s.token_hash = $1 AND u.status = 'active' AND o.status = 'active' AND s.auth_version = u.auth_version
      FOR SHARE OF u, m, o`,
      [tokenHash],
    );
    let valid = false;
    if (identity.rowCount) {
      await client.query(
        'SELECT token_hash FROM public.dashboard_sessions WHERE token_hash = $1 FOR UPDATE /* dashboard-touch-lock */',
        [tokenHash],
      );
      const updated = await client.query(
        `UPDATE public.dashboard_sessions s SET last_seen_at = clock_timestamp()
        FROM public.dashboard_users u, public.dashboard_memberships m, public.operators o
        WHERE s.token_hash = $1 AND u.id = s.user_id AND m.id = s.membership_id AND m.user_id = u.id
          AND o.id = m.operator_id AND u.status = 'active' AND o.status = 'active' AND s.auth_version = u.auth_version
          AND s.created_at > clock_timestamp() - INTERVAL '8 hours'
          AND s.last_seen_at > clock_timestamp() - INTERVAL '30 minutes'
        RETURNING s.token_hash`,
        [tokenHash],
      );
      valid = updated.rowCount === 1;
    }
    await client.query('COMMIT');
    return valid ? identity.rows[0] : undefined;
  } catch {
    await client.query('ROLLBACK').catch(() => undefined);
    throw new Error('Dashboard session unavailable.');
  } finally {
    client.release();
  }
}
