import { loadConfig } from '../config/index.js';
import { assertRealPaymentsDisabled } from '../config/safety.js';
import type { PoolConfig } from 'pg';

export class ProvisioningError extends Error {
  constructor(
    readonly code:
      'configuration' | 'target' | 'operator' | 'key' | 'delivery' | 'internal_endpoint',
  ) {
    super(
      code === 'internal_endpoint'
        ? "Render internal PostgreSQL endpoints do not support this CLI's verified TLS. Use the approved full external hostname. See docs/staging-provisioning.md."
        : `Staging provisioning refused (${code}). See docs/staging-provisioning.md.`,
    );
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
    // Render's documented short internal hostnames have self-signed TLS and are
    // private-network-only. Never silently fall back to require/no-verify.
    if (/^dpg-[a-z0-9-]+$/i.test(url.hostname)) throw new ProvisioningError('internal_endpoint');
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
          : { rejectUnauthorized: true, minVersion: 'TLSv1.2', servername: url.hostname },
      max: 1,
      connectionTimeoutMillis: 5_000,
      options: '-c search_path=public -c lock_timeout=5000 -c statement_timeout=15000',
      application_name: 'vaultx-staging-provisioning',
    };
  } catch (error) {
    if (error instanceof ProvisioningError) throw error;
    throw new ProvisioningError('configuration');
  }
}
