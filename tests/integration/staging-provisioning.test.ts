import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Pool } from 'pg';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { runStagingCli } from '../../src/admin/staging-cli.js';
import {
  provisionStagingOperator,
  STAGING_OPERATOR_NAME,
  verifyStagingTarget,
} from '../../src/admin/staging-operator.js';
import {
  authenticateOperatorKey,
  createOperatorWithApiKey,
  type IssuedOperatorKey,
} from '../../src/db/operator-keys.js';
import { runMigrations } from '../../src/db/migrate.js';
import { createApp } from '../../src/app.js';
import { captureLogger, testConfig } from '../helpers.js';
import { openTestDatabase, testDatabaseSettings } from '../test-database.js';
import { readIssuedKey } from '../support/issued-key.js';

let pool: Pool;
let code: string;
let directory: string;
let env: Record<string, string | undefined>;

beforeAll(async () => {
  // The only source of connection settings is the independently verified
  // disposable test cluster. No application DATABASE_URL is consulted here.
  const verified = await openTestDatabase();
  await verified.end();
  const config = testDatabaseSettings(process.env).poolConfig;
  pool = new Pool({ ...config, database: 'vaultx_pay_staging' });
  const client = await pool.connect();
  try {
    await verifyStagingTarget(client, String(config.user));
  } finally {
    client.release();
  }
  await runMigrations(pool);
  const url = new URL(process.env.TEST_DATABASE_URL!);
  url.pathname = '/vaultx_pay_staging';
  env = {
    NODE_ENV: 'production',
    DATABASE_URL: url.toString(),
    VAULTX_ENVIRONMENT: 'staging',
    ALLOW_STAGING_OPERATOR_PROVISIONING: 'true',
    STAGING_DATABASE_HOST: '127.0.0.1',
    STAGING_DATABASE_USER: String(config.user),
    LIVE_MODE_ENABLED: 'false',
    ALLOWED_PROVIDERS: 'simulator',
  };
});

beforeEach(async () => {
  code = `staging-${randomUUID()}`;
  directory = await realpath(await mkdtemp(path.join(tmpdir(), 'vaultx-provisioning-')));
});
afterEach(async () => {
  if (code) {
    await pool.query(
      'DELETE FROM payments WHERE operator_id IN (SELECT id FROM operators WHERE code = $1)',
      [code],
    );
    await pool.query(
      'DELETE FROM operator_api_keys WHERE operator_id IN (SELECT id FROM operators WHERE code = $1)',
      [code],
    );
    await pool.query('DELETE FROM operators WHERE code = $1', [code]);
  }
  if (directory) await rm(directory, { recursive: true, force: true });
});
afterAll(async () => {
  await pool?.end();
});

async function cli(operation: string, extra: string[] = [], settings = env) {
  let output = '';
  let errors = '';
  const status = await runStagingCli(
    [operation, '--operator-code', code, ...extra],
    settings,
    (s) => {
      output += s;
    },
    (s) => {
      errors += s;
    },
  );
  return { status, output, errors };
}
async function issue() {
  const destination = path.join(directory, 'initial.vaultx-key.json');
  const result = await cli('ensure', ['--key-file', destination]);
  expect(result.status).toBe(0);
  const key = await readIssuedKey(destination);
  expect(result.output.includes(key.apiKey)).toBe(false);
  return key;
}

// Native Windows key delivery starts PowerShell; keep every assertion and allow
// bounded startup overhead for tests performing several deliveries.
describe('staging provisioning on disposable PostgreSQL only', { timeout: 30_000 }, () => {
  it('runs the actual CLI entry point without exposing credentials on stdout/stderr', async () => {
    const destination = path.join(directory, 'entrypoint.vaultx-key.json');
    const result = await new Promise<{ status: number; output: string }>((resolve, reject) => {
      const child = spawn(
        process.execPath,
        [
          '--import',
          'tsx',
          fileURLToPath(new URL('../../src/cli/staging-operator.ts', import.meta.url)),
          'ensure',
          '--operator-code',
          code,
          '--key-file',
          destination,
        ],
        { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] },
      );
      let output = '';
      child.stdout.on('data', (chunk: Buffer) => {
        output += chunk.toString();
      });
      child.stderr.on('data', (chunk: Buffer) => {
        output += chunk.toString();
      });
      child.once('error', () => reject(new Error('Could not start the CLI test process.')));
      child.once('exit', (status) => resolve({ status: status ?? 1, output }));
    });
    expect(result.status).toBe(0);
    const saved = await readIssuedKey(destination);
    expect(result.output.includes(saved.apiKey)).toBe(false);
    expect(result.output.includes(env.DATABASE_URL!)).toBe(false);
    expect((await authenticateOperatorKey(pool, saved.apiKey))?.id).toBe(saved.operatorId);
  });

  it('independently refuses the disposable test database even through the internal service', async () => {
    const testPool = await openTestDatabase();
    try {
      await expect(
        provisionStagingOperator(testPool, env.STAGING_DATABASE_USER!, {
          operation: 'ensure',
          operatorCode: code,
        }),
      ).rejects.toThrow('Staging provisioning refused (target).');
    } finally {
      await testPool.end();
    }
  });

  it('verifies the authenticated session identity across SET ROLE, not an impersonated current role', async () => {
    const client = await pool.connect();
    try {
      await client.query('SET ROLE vaultx_test_switched');
      const identity = await client.query<{ session_user: string; current_user: string }>(
        'SELECT session_user, current_user',
      );
      expect(identity.rows[0]).toEqual({
        session_user: env.STAGING_DATABASE_USER,
        current_user: 'vaultx_test_switched',
      });
      await expect(
        verifyStagingTarget(client, env.STAGING_DATABASE_USER!),
      ).resolves.toBeUndefined();
      await expect(verifyStagingTarget(client, 'vaultx_test_switched')).rejects.toThrow(
        'Staging provisioning refused (target).',
      );
    } finally {
      await client.query('RESET ROLE');
      client.release();
    }
  });

  it('issues an authentication-compatible key and stores only its hash', async () => {
    const key = await issue();
    expect(/^vxp_[a-f0-9]{64}$/.test(key.apiKey)).toBe(true);
    expect(await authenticateOperatorKey(pool, key.apiKey)).toEqual({
      id: key.operatorId,
      code,
      permission: 'read_write',
    });
    const persisted = await pool.query<{ key_hash: string }>(
      'SELECT key_hash FROM operator_api_keys WHERE id = $1',
      [key.keyId],
    );
    expect(/^[a-f0-9]{64}$/.test(persisted.rows[0]!.key_hash)).toBe(true);
    expect(persisted.rows[0]!.key_hash.includes(key.apiKey)).toBe(false);
  });

  it('does not issue or create an operator without explicit delivery', async () => {
    expect((await cli('ensure')).status).toBe(1);
    const rows = await pool.query('SELECT id FROM operators WHERE code = $1', [code]);
    expect(rows.rowCount).toBe(0);
  });

  it('makes duplicate and concurrent ensures safe without duplicate keys or overwriting files', async () => {
    const results = await Promise.all(
      ['first', 'second'].map((name) =>
        cli('ensure', ['--key-file', path.join(directory, `${name}.vaultx-key.json`)]),
      ),
    );
    expect(results.map((r) => r.status)).toEqual([0, 0]);
    const actions = results.map((r) => (JSON.parse(r.output) as { action: string }).action).sort();
    expect(actions).toEqual(['issued', 'unchanged']);
    const retry = await cli('ensure');
    expect(retry.status).toBe(0);
    expect((JSON.parse(retry.output) as { action: string }).action).toBe('unchanged');
    const keys = await pool.query(
      'SELECT k.id FROM operator_api_keys k JOIN operators o ON o.id = k.operator_id WHERE o.code = $1',
      [code],
    );
    expect(keys.rowCount).toBe(1);
  });

  it('rolls back when secret delivery cannot succeed', async () => {
    expect((await cli('ensure', ['--key-file', 'relative-not-allowed'])).status).toBe(1);
    expect((await pool.query('SELECT id FROM operators WHERE code = $1', [code])).rowCount).toBe(0);
  });

  it('rotates once, revokes the old key, and safely retries the same rotation', async () => {
    const old = await issue();
    const destination = path.join(directory, 'rotation.vaultx-key.json');
    const rotated = await cli('rotate', ['--key-id', old.keyId, '--key-file', destination]);
    expect(rotated.status).toBe(0);
    const fresh = await readIssuedKey(destination);
    expect(fresh.apiKey === old.apiKey).toBe(false);
    expect(await authenticateOperatorKey(pool, old.apiKey)).toBeNull();
    expect(await authenticateOperatorKey(pool, fresh.apiKey)).toEqual({
      id: old.operatorId,
      code,
      permission: 'read_write',
    });
    const originalFile = await readFile(destination, 'utf8');
    const retry = await cli('rotate', ['--key-id', old.keyId, '--key-file', destination]);
    expect(retry.status).toBe(0);
    const metadata = JSON.parse(retry.output) as { action: string; keyId: string; keys: unknown[] };
    expect(metadata.action).toBe('unchanged');
    expect(metadata.keyId).toBe(fresh.keyId);
    expect(metadata.keys).toHaveLength(2);
    expect((await readFile(destination, 'utf8')) === originalFile).toBe(true);
    expect((await readIssuedKey(destination)).apiKey === fresh.apiKey).toBe(true);
  });

  it('preserves read-only permissions across rotation and duplicate rotation without enabling writes', async () => {
    const old = await createOperatorWithApiKey(
      pool,
      STAGING_OPERATOR_NAME,
      code,
      'Read-only',
      'read_only',
    );
    const destination = path.join(directory, 'readonly-rotation.vaultx-key.json');
    expect((await cli('rotate', ['--key-id', old.keyId, '--key-file', destination])).status).toBe(
      0,
    );
    const fresh = await readIssuedKey(destination);
    const originalFile = await readFile(destination, 'utf8');
    expect((await authenticateOperatorKey(pool, fresh.apiKey))?.permission).toBe('read_only');
    expect(await authenticateOperatorKey(pool, old.apiKey)).toBeNull();
    expect((await cli('rotate', ['--key-id', old.keyId, '--key-file', destination])).status).toBe(
      0,
    );
    expect(await readFile(destination, 'utf8')).toBe(originalFile);
    expect(
      (
        await pool.query('SELECT id FROM operator_api_keys WHERE operator_id = $1', [
          old.operatorId,
        ])
      ).rowCount,
    ).toBe(2);
    const app = createApp({ config: testConfig(), logger: captureLogger().logger, pool });
    await request(app).get('/payments').auth(fresh.apiKey, { type: 'bearer' }).expect(200);
    await request(app)
      .post('/payments')
      .auth(fresh.apiKey, { type: 'bearer' })
      .set('Idempotency-Key', randomUUID())
      .send({ amountMinor: 100, currency: 'EUR' })
      .expect(403);
    await request(app)
      .post('/payments/' + randomUUID() + '/simulate')
      .auth(fresh.apiKey, { type: 'bearer' })
      .send({ outcome: 'succeeded' })
      .expect(403);
  });

  it('rolls back old-key revocation when rotation delivery fails', async () => {
    const old = await issue();
    expect(
      (await cli('rotate', ['--key-id', old.keyId, '--key-file', 'relative-not-allowed'])).status,
    ).toBe(1);
    expect((await authenticateOperatorKey(pool, old.apiKey))?.id).toBe(old.operatorId);
    const metadata = JSON.parse((await cli('status')).output) as { keys: unknown[] };
    expect(metadata.keys).toHaveLength(1);
  });

  it('serializes concurrent rotations of the same old key into one replacement', async () => {
    const old = await issue();
    const destination = path.join(directory, 'concurrent.vaultx-key.json');
    const rotate = () => cli('rotate', ['--key-id', old.keyId, '--key-file', destination]);
    const results = await Promise.all([rotate(), rotate()]);
    expect(results.map((r) => r.status)).toEqual([0, 0]);
    expect(results.map((r) => (JSON.parse(r.output) as { action: string }).action).sort()).toEqual([
      'issued',
      'unchanged',
    ]);
    const metadata = JSON.parse((await cli('status')).output) as { keys: unknown[] };
    expect(metadata.keys).toHaveLength(2);
    expect(await authenticateOperatorKey(pool, old.apiKey)).toBeNull();
  });

  it('revokes idempotently and refuses silent replacement on ensure', async () => {
    const key = await issue();
    expect((await cli('revoke', ['--key-id', key.keyId])).status).toBe(0);
    expect((await cli('revoke', ['--key-id', key.keyId])).status).toBe(0);
    expect(await authenticateOperatorKey(pool, key.apiKey)).toBeNull();
    expect(
      (await cli('ensure', ['--key-file', path.join(directory, 'unintended.vaultx-key.json')]))
        .status,
    ).toBe(1);
  });

  it('does not revoke an unrelated key ID or overwrite an existing operator identity', async () => {
    const key = await issue();
    expect((await cli('revoke', ['--key-id', randomUUID()])).status).toBe(1);
    expect((await authenticateOperatorKey(pool, key.apiKey))?.id).toBe(key.operatorId);
    await pool.query('UPDATE operators SET name = $2 WHERE id = $1', [
      key.operatorId,
      'Existing unrelated operator',
    ]);
    expect((await cli('ensure')).status).toBe(1);
    expect(
      (await pool.query('SELECT name FROM operators WHERE id = $1', [key.operatorId])).rows[0].name,
    ).toBe('Existing unrelated operator');
  });

  it('refuses a suspended staging operator', async () => {
    const key = await issue();
    await pool.query("UPDATE operators SET status = 'suspended' WHERE id = $1", [key.operatorId]);
    expect(
      (
        await cli('rotate', [
          '--key-id',
          key.keyId,
          '--key-file',
          path.join(directory, 'suspended.vaultx-key.json'),
        ])
      ).status,
    ).toBe(1);
    expect((await cli('revoke', ['--key-id', key.keyId])).status).toBe(0);
  });

  it('independently rejects an unmarked server-side database before creating records', async () => {
    await pool.query('COMMENT ON DATABASE vaultx_pay_staging IS NULL');
    try {
      const result = await cli('ensure', [
        '--key-file',
        path.join(directory, 'unmarked.vaultx-key.json'),
      ]);
      expect(result.status).toBe(1);
      expect(result.errors.includes('(target)')).toBe(true);
      expect((await pool.query('SELECT id FROM operators WHERE code = $1', [code])).rowCount).toBe(
        0,
      );
    } finally {
      await pool.query("COMMENT ON DATABASE vaultx_pay_staging IS 'vaultx-pay:staging'");
    }
  });

  it('completes success and failure lifecycles using the provisioned key and persisted records', async () => {
    const key = await issue();
    const app = createApp({
      config: testConfig({ NODE_ENV: 'production' }),
      logger: captureLogger().logger,
      pool,
    });
    for (const outcome of ['succeeded', 'failed']) {
      const created = await request(app)
        .post('/payments')
        .set('Authorization', `Bearer ${key.apiKey}`)
        .set('Idempotency-Key', randomUUID())
        .send({ amountMinor: 1000, currency: 'EUR' });
      expect(created.status).toBe(201);
      expect(
        (
          await request(app)
            .get(`/payments/${created.body.id}`)
            .set('Authorization', `Bearer ${key.apiKey}`)
        ).status,
      ).toBe(200);
      const completed = await request(app)
        .post(`/payments/${created.body.id}/simulate`)
        .set('Authorization', `Bearer ${key.apiKey}`)
        .send({ outcome });
      expect(completed.status).toBe(200);
      const persisted = await pool.query(
        'SELECT status FROM payments WHERE id = $1 AND operator_id = $2',
        [created.body.id, key.operatorId],
      );
      expect(persisted.rows[0].status).toBe(outcome);
    }
    const operator = await pool.query('SELECT name FROM operators WHERE id = $1', [key.operatorId]);
    expect(operator.rows[0].name).toBe(STAGING_OPERATOR_NAME);
  });

  it('does not expose database errors or key material in command output', async () => {
    let delivered: IssuedOperatorKey | undefined;
    const result = await provisionStagingOperator(
      pool,
      env.STAGING_DATABASE_USER!,
      { operation: 'ensure', operatorCode: code },
      (key) => {
        delivered = key;
        return Promise.resolve();
      },
    );
    expect(JSON.stringify(result).includes(delivered!.apiKey)).toBe(false);
    const cliResult = await cli('status');
    expect(cliResult.output.includes(delivered!.apiKey)).toBe(false);
    expect(cliResult.output.includes('key_hash')).toBe(false);
    expect(cliResult.output.includes(env.DATABASE_URL!)).toBe(false);
  });
});
