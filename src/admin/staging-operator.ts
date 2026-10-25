import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { generateOperatorApiKey, type IssuedOperatorKey } from '../db/operator-keys.js';
import { ProvisioningError } from './staging-config.js';

export const STAGING_OPERATOR_NAME = 'VaultX Pay Staging Test Operator';
export type StagingOperation = 'ensure' | 'status' | 'rotate' | 'revoke';
export interface ProvisioningRequest {
  operation: StagingOperation;
  operatorCode: string;
  keyId?: string;
}
export interface KeyMetadata {
  id: string;
  name: string;
  revoked_at: Date | null;
}

export async function verifyStagingTarget(client: PoolClient, expectedUser: string): Promise<void> {
  // session_user identifies the authenticated login; SET ROLE changes current_user.
  await client.query('BEGIN READ ONLY');
  const result = await client.query<{ safe: boolean }>(
    `SELECT current_database() = 'vaultx_pay_staging' AND session_user = $1
       AND pg_catalog.shobj_description(d.oid, 'pg_database') = 'vaultx-pay:staging' AS safe
     FROM pg_catalog.pg_database d WHERE d.datname = current_database()`,
    [expectedUser],
  );
  await client.query('ROLLBACK');
  if (result.rows.length !== 1 || result.rows[0]?.safe !== true)
    throw new ProvisioningError('target');
}

/** Delivery happens once, before commit; only metadata is returned to callers/loggers. */
export async function provisionStagingOperator(
  pool: Pool,
  expectedUser: string,
  request: ProvisioningRequest,
  deliver?: (key: IssuedOperatorKey) => Promise<void>,
) {
  const client = await pool.connect();
  try {
    await verifyStagingTarget(client, expectedUser);
    await client.query('BEGIN');
    // Covers the initially absent operator, then row locks protect existing keys.
    await client.query('SELECT pg_advisory_xact_lock(894317, hashtext($1))', [
      request.operatorCode,
    ]);
    if (request.operation === 'ensure') {
      await client.query(
        `INSERT INTO operators (id, name, code) VALUES ($1, $2, $3)
         ON CONFLICT (code) DO NOTHING`,
        [randomUUID(), STAGING_OPERATOR_NAME, request.operatorCode],
      );
    }
    const operators = await client.query<{ id: string; name: string; status: string }>(
      'SELECT id, name, status FROM operators WHERE code = $1 FOR UPDATE',
      [request.operatorCode],
    );
    const operator = operators.rows[0];
    if (
      !operator ||
      operator.name !== STAGING_OPERATOR_NAME ||
      (operator.status !== 'active' &&
        (request.operation === 'ensure' || request.operation === 'rotate'))
    ) {
      throw new ProvisioningError('operator');
    }
    const keys = await client.query<KeyMetadata>(
      'SELECT id, name, revoked_at FROM operator_api_keys WHERE operator_id = $1 ORDER BY created_at, id FOR UPDATE',
      [operator.id],
    );
    let action: 'unchanged' | 'issued' | 'revoked' = 'unchanged';
    let keyId = request.keyId;
    let shouldIssue = false;
    const active = keys.rows.filter((key) => !key.revoked_at);
    if (request.operation === 'ensure') {
      if (active.length) keyId = active[0]!.id;
      else if (keys.rows.length) throw new ProvisioningError('key');
      else shouldIssue = true;
    }
    if (request.operation === 'rotate' || request.operation === 'revoke') {
      const old = keys.rows.find((key) => key.id === request.keyId);
      if (!old) throw new ProvisioningError('key');
      if (request.operation === 'rotate') {
        const previous = keys.rows.find((key) => key.name === `Staging rotation from ${old.id}`);
        if (previous) keyId = previous.id;
        else {
          if (active.some((key) => key.id !== old.id)) throw new ProvisioningError('key');
          shouldIssue = true;
        }
      }
      if ((request.operation === 'revoke' || shouldIssue) && !old.revoked_at) {
        await client.query(
          'UPDATE operator_api_keys SET revoked_at = NOW() WHERE id = $1 AND operator_id = $2',
          [old.id, operator.id],
        );
        action = 'revoked';
      }
    }
    if (shouldIssue) {
      if (!deliver) throw new ProvisioningError('delivery');
      const generated = generateOperatorApiKey();
      keyId = randomUUID();
      await client.query(
        'INSERT INTO operator_api_keys (id, operator_id, name, key_hash) VALUES ($1, $2, $3, $4)',
        [
          keyId,
          operator.id,
          request.operation === 'rotate'
            ? `Staging rotation from ${request.keyId!}`
            : 'Staging initial API key',
          generated.keyHash,
        ],
      );
      await deliver({ operatorId: operator.id, keyId, apiKey: generated.apiKey });
      action = 'issued';
    }
    const metadata = await client.query<KeyMetadata>(
      'SELECT id, name, revoked_at FROM operator_api_keys WHERE operator_id = $1 ORDER BY created_at, id',
      [operator.id],
    );
    await client.query('COMMIT');
    return {
      action,
      operatorId: operator.id,
      operatorCode: request.operatorCode,
      keyId,
      // Existing free-form key names are not trusted log content. Return only
      // public identifiers and revocation dates, never names or verifiers.
      keys: metadata.rows.map((key) => ({ keyId: key.id, revokedAt: key.revoked_at })),
    };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
