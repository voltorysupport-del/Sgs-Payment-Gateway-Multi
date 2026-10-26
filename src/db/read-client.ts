import type { Pool, PoolClient } from 'pg';

export class ReadUnavailable extends Error {
  constructor() {
    super('Read capacity temporarily unavailable.');
  }
}
const admitted = new WeakMap<Pool, number>();
/** Bound active AND timed-out queued acquisitions. Late connections are released
 * without executing SQL; a timed-out acquisition cannot accumulate replacements.
 */
export async function withReadClient<T>(
  pool: Pool,
  run: (client: PoolClient) => Promise<T>,
  options: {
    readOnly?: boolean;
    statementMs?: number;
    lockMs?: number;
    totalMs?: number;
    readCommitted?: boolean;
  } = {},
): Promise<T> {
  const count = admitted.get(pool) ?? 0;
  if (count >= 4) throw new ReadUnavailable();
  admitted.set(pool, count + 1);
  let left = false;
  const leave = () => {
    if (!left) {
      left = true;
      admitted.set(pool, (admitted.get(pool) ?? 1) - 1);
    }
  };
  let client: PoolClient;
  try {
    client = await new Promise<PoolClient>((resolve, reject) => {
      let expired = false;
      const timer = setTimeout(() => {
        expired = true;
        reject(new ReadUnavailable());
      }, 750);
      let connecting: Promise<PoolClient>;
      try {
        connecting = pool.connect();
      } catch {
        clearTimeout(timer);
        leave();
        reject(new ReadUnavailable());
        return;
      }
      void connecting.then(
        (value) => {
          clearTimeout(timer);
          if (expired) {
            value.release();
            leave();
          } else resolve(value);
        },
        () => {
          clearTimeout(timer);
          leave();
          reject(new ReadUnavailable());
        },
      );
    });
  } catch {
    throw new ReadUnavailable();
  }
  let discard = false,
    expired = false,
    released = false;
  const release = (destroy: boolean) => {
    if (!released) {
      released = true;
      client.release(destroy);
      leave();
    }
  };
  let timer!: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      expired = true;
      release(true); // Also bound a stalled driver/network, not just server SQL time.
      reject(new ReadUnavailable());
    }, options.totalMs ?? 2500);
  });
  const transaction = async () => {
    try {
      await client.query(
        options.readOnly === false
          ? options.readCommitted
            ? 'BEGIN ISOLATION LEVEL READ COMMITTED'
            : 'BEGIN'
          : 'BEGIN READ ONLY',
      );
      if (expired) throw new ReadUnavailable();
      // Values are private numeric policy constants, never browser/config input.
      await client.query(
        `SET LOCAL statement_timeout = '${options.statementMs ?? 1500}ms'; SET LOCAL lock_timeout = '${options.lockMs ?? 500}ms'`,
      );
      if (expired) throw new ReadUnavailable();
      const value = await run(client);
      if (expired) throw new ReadUnavailable();
      await client.query('COMMIT');
      return value;
    } catch {
      if (!expired) {
        try {
          await client.query('ROLLBACK');
        } catch {
          discard = true;
        }
      }
      throw new ReadUnavailable();
    }
  };
  try {
    return await Promise.race([transaction(), deadline]);
  } finally {
    clearTimeout(timer);
    release(discard || expired);
  }
}
