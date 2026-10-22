import { describe, expect, it } from 'vitest';
import { REDACTED } from '../../src/shared/logger.js';
import { captureLogger } from '../helpers.js';

describe('logger redaction', () => {
  it('writes structured JSON lines', () => {
    const { logger, output } = captureLogger();
    logger.info({ paymentId: 'pay_123' }, 'hello');

    const line = JSON.parse(output()) as Record<string, unknown>;
    expect(line.msg).toBe('hello');
    expect(line.paymentId).toBe('pay_123');
    expect(line.service).toBe('vaultx-pay');
    expect(typeof line.time).toBe('string');
  });

  it('hides secret-looking fields at the top level', () => {
    const { logger, output } = captureLogger();
    logger.info(
      {
        password: 'pw-SHOULD-NOT-APPEAR',
        apiKey: 'vxp_test_SHOULD_NOT_APPEAR',
        token: 'tok-SHOULD-NOT-APPEAR',
        databaseUrl: 'postgres://u:dbpw-SHOULD-NOT-APPEAR@h/db',
      },
      'secrets',
    );

    const text = output();
    expect(text).not.toContain('SHOULD-NOT-APPEAR');
    expect(text).not.toContain('SHOULD_NOT_APPEAR');
    expect(text).toContain(REDACTED);
  });

  it('hides secret-looking fields one level deep', () => {
    const { logger, output } = captureLogger();
    logger.info({ operator: { name: 'Operator A', secret: 'nested-SHOULD-NOT-APPEAR' } }, 'x');

    const text = output();
    expect(text).toContain('Operator A');
    expect(text).not.toContain('nested-SHOULD-NOT-APPEAR');
  });

  it('hides Authorization and Cookie headers', () => {
    const { logger, output } = captureLogger();
    logger.info(
      {
        req: {
          headers: {
            authorization: 'Bearer vxp_test_HEADER_SHOULD_NOT_APPEAR',
            cookie: 'session=COOKIE_SHOULD_NOT_APPEAR',
          },
        },
      },
      'request',
    );

    const text = output();
    expect(text).not.toContain('HEADER_SHOULD_NOT_APPEAR');
    expect(text).not.toContain('COOKIE_SHOULD_NOT_APPEAR');
  });
});
