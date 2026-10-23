import { loadConfig } from '../config/index.js';
import { assertRealPaymentsDisabled } from '../config/safety.js';
import type { PoolConfig } from 'pg';

export class ProvisioningError extends Error {
  constructor(readonly code: 'configuration' | 'target' | 'operator' | 'key' | 'delivery') {
    super(`Staging provisioning refused (${code}). See docs/staging-provisioning.md.`);
    this.name = 'ProvisioningError';
  }
}

export function stagingPoolConfig(env: Readonly<Record<string, string | undefined>>): PoolConfig {
  try {
    assertRealPaymentsDisabled(loadConfig(env));
    if (
      env.VAULTX_ENVIRONMENT !== 'staging' ||
      env.ALLOW_STAGING_OPERATOR_PROVISIONING !== 'true'
    ) {
      throw new Error();
    }
    const url = new URL(env.DATABASE_URL!);
    const user = decodeURIComponent(url.username);
    const password = decodeURIComponent(url.password);
    if (
      !['postgres:', 'postgresql:'].includes(url.protocol) ||
      url.pathname !== '/vaultx_pay_staging' ||
      !url.hostname ||
      !user ||
      !password ||
      url.hostname !== env.STAGING_DATABASE_HOST ||
      user !== env.STAGING_DATABASE_USER ||
      url.hash ||
      [...url.searchParams].some(([key, value]) => key !== 'sslmode' || value !== 'verify-full')
    )
      throw new Error();

    return {
      host: url.hostname,
      port: url.port ? Number(url.port) : 5432,
      database: 'vaultx_pay_staging',
      user,
      password,
      // Only loopback disposable/local staging can omit TLS. Remote staging
      // always verifies the certificate; URL/PG* overrides are not used.
      ssl:
        url.hostname === '127.0.0.1' && !url.searchParams.has('sslmode')
          ? false
          : { rejectUnauthorized: true },
      max: 1,
      connectionTimeoutMillis: 5_000,
      options: '-c search_path=public -c lock_timeout=5000 -c statement_timeout=15000',
      application_name: 'vaultx-staging-provisioning',
    };
  } catch {
    throw new ProvisioningError('configuration');
  }
}
