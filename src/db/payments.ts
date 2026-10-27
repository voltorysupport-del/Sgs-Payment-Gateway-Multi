import { withReadClient } from './read-client.js';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';

export type SimulationOutcome = 'succeeded' | 'failed';

interface PaymentRow {
  id: string;
  amount_minor: string;
  currency: string;
  status: 'pending' | SimulationOutcome | 'cancelled';
  provider: 'simulator';
  created_at: Date;
  updated_at: Date;
}

const columns = 'id, amount_minor, currency, status, provider, created_at, updated_at';

function serialize(row: PaymentRow) {
  return {
    id: row.id,
    amountMinor: Number(row.amount_minor),
    currency: row.currency.trim(),
    status: row.status,
    provider: row.provider,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

export class TerminalUnavailable extends Error {
  constructor() {
    super('The requested terminal is unavailable.');
  }
}

export class PaymentConflict extends Error {
  constructor(
    readonly code: 'idempotency_conflict' | 'invalid_payment_transition',
    message: string,
  ) {
    super(message);
    this.name = 'PaymentConflict';
  }
}

export async function createPayment(
  pool: Pool,
  operatorId: string,
  idempotencyKey: string,
  amountMinor: number,
  currency: string,
  terminalId?: string,
) {
  const client = await pool.connect();
  let discard = false;
  try {
    await client.query('BEGIN');
    // Serialize same-operator request identities before checking terminal state.
    // This also permits exact retries after a terminal is suspended.
    await client.query(
      "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('vaultx.payment.create:' || $1 || ':' || $2, 0))",
      [operatorId, idempotencyKey],
    );
    let row = (
      await client.query<PaymentRow & { terminal_id: string | null }>(
        `SELECT ${columns}, terminal_id FROM public.payments WHERE operator_id=$1 AND idempotency_key=$2`,
        [operatorId, idempotencyKey],
      )
    ).rows[0];
    let created = false;
    if (!row) {
      // The INSERT trigger checks eligibility and locks the same-tenant terminal
      // FOR SHARE through COMMIT, serializing suspension/deletion/reassignment.
      row = (
        await client.query<PaymentRow & { terminal_id: string | null }>(
          `INSERT INTO public.payments
          (id, operator_id, provider, amount_minor, currency, status, idempotency_key, terminal_id)
         VALUES ($1,$2,'simulator',$3,$4,'pending',$5,$6)
         ON CONFLICT (operator_id,idempotency_key) DO NOTHING
         RETURNING ${columns}, terminal_id`,
          [randomUUID(), operatorId, amountMinor, currency, idempotencyKey, terminalId ?? null],
        )
      ).rows[0];
      created = Boolean(row);
      // Keep the unique-constraint fallback for independent/older writers that
      // do not participate in the application advisory-lock protocol.
      if (!row)
        row = (
          await client.query<PaymentRow & { terminal_id: string | null }>(
            `SELECT ${columns}, terminal_id FROM public.payments WHERE operator_id=$1 AND idempotency_key=$2`,
            [operatorId, idempotencyKey],
          )
        ).rows[0];
    }
    if (!row) throw new Error('Could not resolve the persisted payment.');
    if (
      Number(row.amount_minor) !== amountMinor ||
      row.currency.trim() !== currency ||
      row.terminal_id !== (terminalId ?? null)
    ) {
      throw new PaymentConflict(
        'idempotency_conflict',
        'This idempotency key was already used with a different request.',
      );
    }
    await client.query('COMMIT');
    return { created, payment: serialize(row) };
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      discard = true;
    }
    if (error instanceof Error && 'code' in error && error.code === 'VX001')
      throw new TerminalUnavailable();
    throw error;
  } finally {
    client.release(discard);
  }
}

export async function getPayment(pool: Pool, operatorId: string, paymentId: string) {
  const result = await withReadClient(pool, (client) =>
    client.query<PaymentRow>(`SELECT ${columns} FROM payments WHERE operator_id = $1 AND id = $2`, [
      operatorId,
      paymentId,
    ]),
  );
  return result.rows[0] ? serialize(result.rows[0]) : undefined;
}

export async function simulatePayment(
  pool: Pool,
  operatorId: string,
  paymentId: string,
  outcome: SimulationOutcome,
) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serialize competing outcomes and scope the lock to the authenticated
    // operator. Final states are immutable; identical retries do not write.
    const result = await client.query<PaymentRow>(
      `SELECT ${columns} FROM payments
       WHERE operator_id = $1 AND id = $2 AND provider = 'simulator'
       FOR UPDATE`,
      [operatorId, paymentId],
    );
    let row = result.rows[0];
    if (row && row.status !== outcome) {
      if (row.status !== 'pending') {
        throw new PaymentConflict(
          'invalid_payment_transition',
          'A completed payment cannot be changed to another outcome.',
        );
      }
      const updated = await client.query<PaymentRow>(
        `UPDATE payments SET status = $3, updated_at = clock_timestamp()
         WHERE operator_id = $1 AND id = $2 AND provider = 'simulator' AND status = 'pending'
         RETURNING ${columns}`,
        [operatorId, paymentId, outcome],
      );
      row = updated.rows[0];
      if (!row) throw new Error('Could not persist the simulated outcome.');
    }
    await client.query('COMMIT');
    return row ? serialize(row) : undefined;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/** Bounded, deterministic history; offset pagination is not a snapshot. */
export async function listPayments(
  pool: Pool,
  operatorId: string,
  options: {
    limit: number;
    offset: number;
    status?: string;
    currency?: string;
  },
) {
  const result = await withReadClient(pool, (client) =>
    client.query<PaymentRow>(
      `SELECT ${columns} FROM payments
     WHERE operator_id = $1 AND ($2::text IS NULL OR status = $2)
       AND ($3::text IS NULL OR currency = $3)
     ORDER BY created_at DESC, id DESC LIMIT $4 OFFSET $5`,
      [
        operatorId,
        options.status ?? null,
        options.currency ?? null,
        options.limit + 1,
        options.offset,
      ],
    ),
  );
  return {
    payments: result.rows.slice(0, options.limit).map(serialize),
    pagination: {
      limit: options.limit,
      offset: options.offset,
      hasMore: result.rows.length > options.limit,
    },
  };
}
