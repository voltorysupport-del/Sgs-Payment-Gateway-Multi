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
) {
  // The unique constraint resolves concurrent creation; never update an existing
  // payment on an idempotency collision (including one already completed).
  const inserted = await pool.query<PaymentRow>(
    `INSERT INTO payments
       (id, operator_id, provider, amount_minor, currency, status, idempotency_key)
     VALUES ($1, $2, 'simulator', $3, $4, 'pending', $5)
     ON CONFLICT (operator_id, idempotency_key) DO NOTHING
     RETURNING ${columns}`,
    [randomUUID(), operatorId, amountMinor, currency, idempotencyKey],
  );
  let row = inserted.rows[0];
  if (!row) {
    const existing = await pool.query<PaymentRow>(
      `SELECT ${columns} FROM payments WHERE operator_id = $1 AND idempotency_key = $2`,
      [operatorId, idempotencyKey],
    );
    row = existing.rows[0];
  }
  if (!row) throw new Error('Could not resolve the persisted payment.');
  if (Number(row.amount_minor) !== amountMinor || row.currency.trim() !== currency) {
    throw new PaymentConflict(
      'idempotency_conflict',
      'This idempotency key was already used with a different request.',
    );
  }
  return { created: inserted.rows.length > 0, payment: serialize(row) };
}

export async function getPayment(pool: Pool, operatorId: string, paymentId: string) {
  const result = await pool.query<PaymentRow>(
    `SELECT ${columns} FROM payments WHERE operator_id = $1 AND id = $2`,
    [operatorId, paymentId],
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
