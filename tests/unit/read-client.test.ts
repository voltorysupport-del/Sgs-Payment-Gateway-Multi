import type { Pool, PoolClient } from 'pg';
import { afterEach, expect, it, vi } from 'vitest';
import { withReadClient, ReadUnavailable } from '../../src/db/read-client.js';
afterEach(() => vi.useRealTimers());
it('discards a stalled read connection at its total deadline and prevents late commit', async () => {
  vi.useFakeTimers();
  let finish!: () => void;
  const gate = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const query = vi.fn(() => Promise.resolve({ rows: [] })),
    release = vi.fn();
  const client = { query, release } as unknown as PoolClient;
  const pool = { connect: () => Promise.resolve(client) } as unknown as Pool;
  const pending = withReadClient(pool, () => gate);
  const assertion = expect(pending).rejects.toBeInstanceOf(ReadUnavailable);
  await vi.advanceTimersByTimeAsync(2501);
  await assertion;
  expect(release).toHaveBeenCalledWith(true);
  expect(release).toHaveBeenCalledTimes(1);
  finish();
  await vi.advanceTimersByTimeAsync(0);
  expect(query.mock.calls.some((args) => (args as unknown[])[0] === 'COMMIT')).toBe(false);
  expect(release).toHaveBeenCalledTimes(1);
});
