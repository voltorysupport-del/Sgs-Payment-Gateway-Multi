import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, beforeEach, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { runMigrations } from '../../src/db/migrate.js';
import { createOperatorWithApiKey } from '../../src/db/operator-keys.js';
import { createPayment, TerminalUnavailable } from '../../src/db/payments.js';
import { openTestDatabase } from '../test-database.js';
import { captureLogger, testConfig } from '../helpers.js';

let pool: Pool;
let owner: Awaited<ReturnType<typeof createOperatorWithApiKey>>;
let other: typeof owner;
let readonly: typeof owner;
let terminal: string;
let foreign: string;
let suspended: string;
const { logger, output } = captureLogger();
const app = () => createApp({ pool, config: testConfig(), logger });
const post = (key: string, terminalId?: string, credential = owner.apiKey) =>
  request(app())
    .post('/payments')
    .set('Authorization', `Bearer ${credential}`)
    .set('Idempotency-Key', key)
    .send({ amountMinor: 100, currency: 'EUR', ...(terminalId ? { terminalId } : {}) });

beforeAll(async () => {
  pool = await openTestDatabase();
  await runMigrations(pool);
});
beforeEach(async () => {
  owner = await createOperatorWithApiKey(
    pool,
    'Synthetic attribution',
    'attribution_' + randomUUID(),
  );
  other = await createOperatorWithApiKey(pool, 'Synthetic other', 'other_' + randomUUID());
  readonly = await createOperatorWithApiKey(
    pool,
    'Synthetic readonly',
    'read_' + randomUUID(),
    'Read',
    'read_only',
  );
  terminal = randomUUID();
  foreign = randomUUID();
  suspended = randomUUID();
  await pool.query(
    `INSERT INTO public.merchant_terminals(id,operator_id,code,name,status)
    VALUES($1,$2,'terminal-a','Synthetic A','active'),($3,$4,'terminal-b','Synthetic B','active'),
    ($5,$2,'terminal-disabled','Synthetic disabled','suspended')`,
    [terminal, owner.operatorId, foreign, other.operatorId, suspended],
  );
});
afterEach(async () => {
  for (const id of [owner, other, readonly].map((o) => o.operatorId)) {
    await pool.query('DELETE FROM public.payments WHERE operator_id=$1', [id]);
    await pool.query('DELETE FROM public.merchant_terminals WHERE operator_id=$1', [id]);
    await pool.query('DELETE FROM public.operator_api_keys WHERE operator_id=$1', [id]);
    await pool.query('DELETE FROM public.operators WHERE id=$1', [id]);
  }
});
afterAll(async () => {
  await pool?.end();
});

it('preserves legacy JSON and unattributed payments; persists canonical terminal under authenticated operator', async () => {
  const legacy = await post('legacy-payment');
  expect(legacy.status).toBe(201);
  expect(legacy.body).not.toHaveProperty('terminalId');
  const attributed = await post('terminal-payment', terminal.toUpperCase());
  expect(attributed.status).toBe(201);
  expect(
    (await pool.query('SELECT terminal_id FROM public.payments WHERE id=$1', [legacy.body.id]))
      .rows[0].terminal_id,
  ).toBeNull();
  expect(
    (
      await pool.query('SELECT terminal_id,operator_id FROM public.payments WHERE id=$1', [
        attributed.body.id,
      ])
    ).rows[0],
  ).toEqual({ terminal_id: terminal, operator_id: owner.operatorId });
  expect(
    (
      await request(app())
        .get('/payments/' + attributed.body.id)
        .set('Authorization', `Bearer ${other.apiKey}`)
    ).status,
  ).toBe(404);
});

it('rejects missing, foreign, disabled and malformed terminals generically, and rejects operator overrides and read-only keys', async () => {
  const responses = await Promise.all(
    [foreign, suspended, randomUUID()].map((id) => post(randomUUID(), id)),
  );
  expect(responses.map((r) => r.status)).toEqual([400, 400, 400]);
  for (const response of responses)
    expect(response.body).toMatchObject({
      error: { code: 'invalid_terminal', message: 'The requested terminal is unavailable.' },
    });
  expect((await post('malformed-id', 'not-a-uuid')).status).toBe(400);
  expect((await post('readonly-key', terminal, readonly.apiKey)).status).toBe(403);
  expect(
    (
      await request(app())
        .post('/payments')
        .set('Authorization', `Bearer ${owner.apiKey}`)
        .set('Idempotency-Key', 'operator-override')
        .send({
          amountMinor: 100,
          currency: 'EUR',
          terminalId: foreign,
          operatorId: other.operatorId,
        })
    ).status,
  ).toBe(400);
  expect(
    (
      await pool.query('SELECT count(*) FROM public.payments WHERE operator_id=$1', [
        owner.operatorId,
      ])
    ).rows[0].count,
  ).toBe('0');
  expect(output()).not.toContain(owner.apiKey);
});

it('includes terminal attribution in idempotency, serializes duplicates, and permits exact retries after suspension', async () => {
  const results = await Promise.all([
    post('same-terminal-key', terminal),
    post('same-terminal-key', terminal),
  ]);
  expect(results.map((r) => r.status).sort()).toEqual([200, 201]);
  expect(results[0].body.id).toBe(results[1].body.id);
  expect((await post('same-terminal-key')).status).toBe(409);
  expect((await post('same-terminal-key', foreign)).status).toBe(409);
  await post('unattributed-key');
  expect((await post('unattributed-key', terminal)).status).toBe(409);
  const contenders = await Promise.all([post('competing-key', terminal), post('competing-key')]);
  expect(contenders.map((r) => r.status).sort()).toEqual([201, 409]);
  await pool.query("UPDATE public.merchant_terminals SET status='suspended' WHERE id=$1", [
    terminal,
  ]);
  expect((await post('same-terminal-key', terminal)).status).toBe(200);
  expect((await post('new-after-suspend', terminal)).status).toBe(400);
});

it('database enforces immutable attribution and composite tenant integrity without relying on HTTP checks', async () => {
  const created = await post('immutable-payment', terminal);
  for (const sql of [
    'UPDATE public.payments SET terminal_id=NULL WHERE id=$1',
    'UPDATE public.payments SET terminal_id=$2 WHERE id=$1',
    'UPDATE public.payments SET operator_id=$2 WHERE id=$1',
  ]) {
    const values = sql.includes('operator_id=')
      ? [created.body.id, other.operatorId]
      : sql.includes('$2')
        ? [created.body.id, foreign]
        : [created.body.id];
    // A separate failed statement leaves the pool connection usable.
    await expect(pool.query(sql, values)).rejects.toMatchObject({ code: '42501' });
  }
  await expect(
    pool.query('DELETE FROM public.merchant_terminals WHERE id=$1', [terminal]),
  ).rejects.toMatchObject({ code: '23503' });
  await expect(
    pool.query('UPDATE public.merchant_terminals SET operator_id=$2 WHERE id=$1', [
      terminal,
      other.operatorId,
    ]),
  ).rejects.toMatchObject({ code: '23503' });
  const unassigned = await post('no-backfill-key');
  await expect(
    pool.query('UPDATE public.payments SET terminal_id=$2 WHERE id=$1', [
      unassigned.body.id,
      terminal,
    ]),
  ).rejects.toMatchObject({ code: '42501' });
});

async function blocked(client: PoolClient, pid: number) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const result = await client.query('SELECT cardinality(pg_blocking_pids($1))>0 AS blocked', [
      pid,
    ]);
    if (result.rows[0].blocked) return;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error('Expected PostgreSQL lock wait was not observed');
}

it('suspension winning the row lock rejects waiting creation, without committing a payment', async () => {
  const blocker = await pool.connect(),
    writer = await pool.connect();
  const pid = (await writer.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
  let pending: Promise<unknown> | undefined;
  try {
    await blocker.query('BEGIN');
    await blocker.query("UPDATE public.merchant_terminals SET status='suspended' WHERE id=$1", [
      terminal,
    ]);
    pending = createPayment(
      { connect: () => Promise.resolve(writer) } as unknown as Pool,
      owner.operatorId,
      'blocked-creation',
      100,
      'EUR',
      terminal,
    );
    const outcome = pending.then(
      () => null,
      (error: unknown) => error,
    );
    await blocked(blocker, pid);
    await blocker.query('COMMIT');
    expect(await outcome).toBeInstanceOf(TerminalUnavailable);
    expect(
      (
        await pool.query('SELECT count(*) FROM public.payments WHERE operator_id=$1', [
          owner.operatorId,
        ])
      ).rows[0].count,
    ).toBe('0');
  } finally {
    await blocker.query('ROLLBACK');
    await pending?.catch(() => undefined);
    blocker.release();
  }
});

it('creation winning the terminal lock commits history before suspension can complete', async () => {
  const creator = await pool.connect(),
    disabler = await pool.connect();
  const pid = (await disabler.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
  let pending: Promise<unknown> | undefined;
  const payment = randomUUID();
  try {
    await creator.query('BEGIN');
    await creator.query(
      `INSERT INTO public.payments(id,operator_id,amount_minor,currency,idempotency_key,terminal_id)
      VALUES($1,$2,100,'EUR','creation-wins',$3)`,
      [payment, owner.operatorId, terminal],
    );
    pending = disabler.query(
      "UPDATE public.merchant_terminals SET status='suspended' WHERE id=$1",
      [terminal],
    );
    await blocked(creator, pid);
    await creator.query('COMMIT');
    await pending;
    expect(
      (await pool.query('SELECT terminal_id FROM public.payments WHERE id=$1', [payment])).rows[0]
        .terminal_id,
    ).toBe(terminal);
  } finally {
    await creator.query('ROLLBACK');
    await pending?.catch(() => undefined);
    creator.release();
    disabler.release();
  }
});

it('retains unique-constraint idempotency compatibility with a writer outside the advisory-lock protocol', async () => {
  const first = await pool.connect(),
    follower = await pool.connect();
  const pid = (await follower.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
  let pending: ReturnType<typeof createPayment> | undefined;
  const payment = randomUUID();
  try {
    await first.query('BEGIN');
    await first.query(
      `INSERT INTO public.payments(id,operator_id,amount_minor,currency,idempotency_key,terminal_id)
      VALUES($1,$2,100,'EUR','outside-protocol',$3)`,
      [payment, owner.operatorId, terminal],
    );
    pending = createPayment(
      { connect: () => Promise.resolve(follower) } as unknown as Pool,
      owner.operatorId,
      'outside-protocol',
      100,
      'EUR',
      terminal,
    );
    await blocked(first, pid);
    await first.query('COMMIT');
    expect(await pending).toMatchObject({ created: false, payment: { id: payment } });
  } finally {
    await first.query('ROLLBACK');
    await pending?.catch(() => undefined);
    first.release();
  }
});

it('fails closed for insufficient runtime privileges and needs no elevated trigger rights', async () => {
  const client = await pool.connect();
  const role = 'vaultx_terminal_runtime';
  const insert = `INSERT INTO public.payments(id,operator_id,amount_minor,currency,idempotency_key,terminal_id)
    VALUES($1,$2,100,'EUR','runtime-privilege',$3)`;
  const values = [randomUUID(), owner.operatorId, terminal];
  try {
    await client.query('BEGIN');
    await client.query(`GRANT USAGE ON SCHEMA public TO ${role}`);
    await client.query(`GRANT INSERT,SELECT ON public.payments TO ${role}`);
    await client.query(`GRANT SELECT ON public.merchant_terminals TO ${role}`);
    await client.query(`SET LOCAL ROLE ${role}`);
    await client.query('SAVEPOINT insufficient');
    await expect(client.query(insert, values)).rejects.toMatchObject({ code: '42501' });
    await client.query('ROLLBACK TO SAVEPOINT insufficient');
    await client.query('RESET ROLE');
    // PostgreSQL row locks require UPDATE on at least one column. This fixture
    // proves that requirement without granting terminal identity/status writes.
    await client.query(`GRANT UPDATE(name) ON public.merchant_terminals TO ${role}`);
    await client.query(`SET LOCAL ROLE ${role}`);
    await client.query(insert, values);
    await client.query('SAVEPOINT no_identity_write');
    await expect(
      client.query('UPDATE public.merchant_terminals SET operator_id=$2 WHERE id=$1', [
        terminal,
        other.operatorId,
      ]),
    ).rejects.toMatchObject({ code: '42501' });
    await client.query('ROLLBACK TO SAVEPOINT no_identity_write');
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
});
