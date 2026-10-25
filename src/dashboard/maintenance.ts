import type { Pool } from 'pg';

/** One small batch per table. Never chase an unbounded backlog in a request. */
export async function cleanupDashboardAuth(pool: Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL statement_timeout = '2000ms'; SET LOCAL lock_timeout = '500ms'");
    await client.query(`WITH expired AS (
      SELECT token_hash FROM public.dashboard_sessions
      WHERE (user_id IS NULL AND created_at <= clock_timestamp() - INTERVAL '10 minutes')
         OR (user_id IS NOT NULL AND (created_at <= clock_timestamp() - INTERVAL '8 hours'
           OR last_seen_at <= clock_timestamp() - INTERVAL '30 minutes'))
      ORDER BY created_at LIMIT 100 FOR UPDATE SKIP LOCKED
    ) DELETE FROM public.dashboard_sessions s USING expired e WHERE s.token_hash = e.token_hash`);
    await client.query(`WITH expired AS (
      SELECT bucket_hash FROM public.dashboard_login_limits WHERE expires_at <= clock_timestamp()
      ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED
    ) DELETE FROM public.dashboard_login_limits l USING expired e WHERE l.bucket_hash = e.bucket_hash`);
    await client.query('COMMIT');
  } catch {
    await client.query('ROLLBACK').catch(() => undefined);
    throw new Error('Dashboard maintenance unavailable.');
  } finally {
    client.release();
  }
}

// Shared across routers using the same pool; no timers, worker or external scheduler.
const states = new WeakMap<Pool, { next: number; running?: Promise<void> }>();
export async function maintainDashboardAuth(pool: Pool): Promise<void> {
  let state = states.get(pool);
  if (!state) {
    state = { next: 0 };
    states.set(pool, state);
  }
  if (state.running) return state.running;
  if (Date.now() < state.next) return;
  state.next = Date.now() + 60_000;
  const running = cleanupDashboardAuth(pool);
  state.running = running;
  try {
    await running;
  } finally {
    state.running = undefined;
  }
}
