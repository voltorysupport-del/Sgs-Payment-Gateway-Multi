import { parseArgs } from 'node:util';
import { Pool } from 'pg';
import { z } from 'zod';
import { deliverKeyFile } from './key-delivery.js';
import { ProvisioningError, stagingPoolConfig } from './staging-config.js';
import { provisionStagingOperator, type ProvisioningRequest } from './staging-operator.js';

export const HELP = `Usage: npm run staging:operator -- <status|ensure|rotate|revoke>
  --operator-code staging-e2e       Optional staging-* operator code
  --key-file <absolute-path>        Explicit one-time delivery for ensure/rotate
  --key-id <UUID>                   Required for rotate/revoke; identifies the old key

Requires DATABASE_URL, VAULTX_ENVIRONMENT=staging,
ALLOW_STAGING_OPERATOR_PROVISIONING=true, STAGING_DATABASE_HOST, STAGING_DATABASE_USER,
and an independently designated staging database. Never prints a raw key.
See docs/staging-provisioning.md before use.\n`;

export function parseProvisioningArgs(args: string[]): ProvisioningRequest & { keyFile?: string } {
  try {
    const parsed = parseArgs({
      args,
      allowPositionals: true,
      strict: true,
      options: {
        'operator-code': { type: 'string', default: 'staging-e2e' },
        'key-file': { type: 'string' },
        'key-id': { type: 'string' },
      },
    });
    if (parsed.positionals.length !== 1) throw new Error();
    const operation = z.enum(['status', 'ensure', 'rotate', 'revoke']).parse(parsed.positionals[0]);
    const operatorCode = z
      .string()
      .regex(/^staging-[a-z0-9][a-z0-9_-]{0,47}$/)
      .parse(parsed.values['operator-code']);
    const keyId = parsed.values['key-id'];
    const keyFile = parsed.values['key-file'];
    if (operation === 'rotate' || operation === 'revoke') z.uuid().parse(keyId);
    else if (keyId) throw new Error();
    if (keyFile && operation !== 'rotate' && operation !== 'ensure') throw new Error();
    return { operation, operatorCode, keyId, keyFile };
  } catch {
    throw new ProvisioningError('configuration');
  }
}

export async function runStagingCli(
  args: string[],
  env: Readonly<Record<string, string | undefined>>,
  stdout: (text: string) => void,
  stderr: (text: string) => void,
): Promise<number> {
  if (args.length === 1 && args[0] === '--help') {
    stdout(HELP);
    return 0;
  }
  let pool: Pool | undefined;
  try {
    const request = parseProvisioningArgs(args);
    const config = stagingPoolConfig(env);
    pool = new Pool(config);
    const metadata = await provisionStagingOperator(
      pool,
      String(config.user),
      request,
      request.keyFile ? (key) => deliverKeyFile(request.keyFile!, key) : undefined,
    );
    stdout(JSON.stringify(metadata) + '\n');
    return 0;
  } catch (error) {
    stderr(
      error instanceof ProvisioningError
        ? error.message + '\n'
        : 'Staging provisioning failed. No error details are logged. Check status before retrying.\n',
    );
    return 1;
  } finally {
    await pool?.end().catch(() => undefined);
  }
}
