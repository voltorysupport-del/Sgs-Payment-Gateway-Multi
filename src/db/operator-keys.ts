import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import type { Pool } from 'pg';

const API_KEY_PREFIX = 'vxp_';

function hashApiKey(apiKey: string): string {
  return createHash('sha256').update(apiKey, 'utf8').digest('hex');
}

/** Shared issuance format/verifier for HTTP authentication and administrative tools. */
export function generateOperatorApiKey(): { apiKey: string; keyHash: string } {
  const apiKey = `${API_KEY_PREFIX}${randomBytes(32).toString('hex')}`;
  return { apiKey, keyHash: hashApiKey(apiKey) };
}

export interface IssuedOperatorKey {
  operatorId: string;
  keyId: string;
  apiKey: string;
}

export async function createOperatorWithApiKey(
  pool: Pool,
  name: string,
  code: string,
  keyName = 'Initial API key',
): Promise<IssuedOperatorKey> {
  const operatorId = randomUUID();
  const keyId = randomUUID();
  const { apiKey, keyHash } = generateOperatorApiKey();

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query(
      `INSERT INTO operators (id, name, code)
       VALUES ($1, $2, $3)`,
      [operatorId, name, code],
    );

    await client.query(
      `INSERT INTO operator_api_keys
         (id, operator_id, name, key_hash)
       VALUES ($1, $2, $3, $4)`,
      [keyId, operatorId, keyName, keyHash],
    );

    await client.query('COMMIT');

    // The raw key is returned once. Callers must not log or persist it.
    return { operatorId, keyId, apiKey };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export interface AuthenticatedOperator {
  id: string;
  code: string;
}

export async function authenticateOperatorKey(
  pool: Pool,
  apiKey: string,
): Promise<AuthenticatedOperator | null> {
  if (!/^vxp_[a-f0-9]{64}$/.test(apiKey)) {
    return null;
  }

  const suppliedHash = hashApiKey(apiKey);

  const result = await pool.query<{
    id: string;
    code: string;
    key_hash: string;
  }>(
    `SELECT o.id, o.code, k.key_hash
     FROM operator_api_keys k
     JOIN operators o ON o.id = k.operator_id
     WHERE k.key_hash = $1
       AND k.revoked_at IS NULL
       AND o.status = 'active'
     LIMIT 1`,
    [suppliedHash],
  );

  const row = result.rows[0];

  if (!row) {
    // Perform a fixed-length comparison even for unknown keys.
    timingSafeEqual(Buffer.from(suppliedHash), Buffer.alloc(64));
    return null;
  }

  const expectedHash = Buffer.from(row.key_hash, 'hex');
  const actualHash = Buffer.from(suppliedHash, 'hex');

  if (expectedHash.length !== actualHash.length || !timingSafeEqual(expectedHash, actualHash)) {
    return null;
  }

  return { id: row.id, code: row.code };
}

export async function revokeOperatorKey(
  pool: Pool,
  keyId: string,
  operatorId: string,
): Promise<boolean> {
  const result = await pool.query(
    `UPDATE operator_api_keys
     SET revoked_at = NOW()
     WHERE id = $1
       AND operator_id = $2
       AND revoked_at IS NULL`,
    [keyId, operatorId],
  );

  return result.rowCount === 1;
}
