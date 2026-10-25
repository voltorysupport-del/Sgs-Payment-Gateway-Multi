import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Pool } from 'pg';

const migrationsDirectory = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../migrations',
);

export async function runMigrations(pool: Pool): Promise<void> {
  const files = (await readdir(migrationsDirectory))
    .filter((file) => /^\d+_[a-z0-9_-]+\.sql$/.test(file))
    .sort();
  // All callers in this database use one dedicated session, including bootstrap
  // and the history check. Locking only the DDL leaves a check-then-create race.
  // This namespace is distinct from staging provisioning's operator locks.
  const client = await pool.connect();
  let locked = false;
  let failed = false;
  let failure: unknown;
  let discard = false;
  try {
    await client.query('SELECT pg_advisory_lock(894318, 1)');
    locked = true;
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    for (const name of files) {
      const alreadyApplied = await client.query('SELECT 1 FROM schema_migrations WHERE name = $1', [
        name,
      ]);
      if (alreadyApplied.rowCount) continue;
      const sql = await readFile(path.join(migrationsDirectory, name), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [name]);
        await client.query('COMMIT');
      } catch (error) {
        try {
          await client.query('ROLLBACK');
        } catch {
          discard = true;
        }
        // Preserve the actual SQL error; never treat duplicate objects as success.
        throw error;
      }
    }
  } catch (error) {
    failed = true;
    failure = error;
  } finally {
    if (locked) {
      try {
        const result = await client.query<{ unlocked: boolean }>(
          'SELECT pg_advisory_unlock(894318, 1) AS unlocked',
        );
        if (result.rows[0]?.unlocked !== true) {
          discard = true;
          if (!failed) {
            failed = true;
            failure = new Error('Migration lock release failed.');
          }
        }
      } catch (error) {
        discard = true;
        if (!failed) {
          failed = true;
          failure = error;
        }
      }
    } else {
      // A failed acquisition has uncertain session state; never pool that session.
      discard = true;
    }
    client.release(discard);
  }
  // Preserve the original SQL error, including its PostgreSQL code.
  if (failed) {
    if (failure instanceof Error) throw failure;
    throw new Error('Migration failed.', { cause: failure });
  }
}
