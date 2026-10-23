import { Pool } from 'pg';
import type { Config } from '../config/index.js';

export function createPool(config: Config): Pool {
  return new Pool({
    connectionString: config.databaseUrl,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });
}

export async function checkDatabase(pool: Pool): Promise<void> {
  await pool.query('SELECT 1');
}
