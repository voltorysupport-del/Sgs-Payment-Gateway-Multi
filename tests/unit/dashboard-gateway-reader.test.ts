import http from 'node:http';
import { EventEmitter } from 'node:events';
import { afterEach, expect, it, vi } from 'vitest';
import { readGateway as gateway } from '../../src/dashboard/gateway-reader.js';
import type { GatewayRead } from '../../src/dashboard/gateway-reader.js';
const expectedOperator = '00000000-0000-4000-8000-000000000001';
const readGateway = (port: number, key: string, read: GatewayRead) =>
  gateway(port, key, read, expectedOperator);
import { ConfigError } from '../../src/config/index.js';
import { testConfig } from '../helpers.js';

function wire() {
  const req = new EventEmitter();
  let idle = () => {};
  let response: ((res: http.IncomingMessage) => void) | undefined;
  const hooks = {
    setTimeout: vi.fn((_ms: number, callback: () => void) => {
      idle = callback;
    }),
    end: vi.fn(),
    destroy: vi.fn(() => {
      req.emit('error', new Error('PRIVATE_NETWORK_DETAIL'));
    }),
  };
  Object.assign(req, hooks);
  const spy = vi.spyOn(http, 'request').mockImplementation((...args: unknown[]) => {
    response = args[1] as (res: http.IncomingMessage) => void;
    return req as unknown as http.ClientRequest;
  });
  return {
    req,
    hooks,
    spy,
    idle: () => idle(),
    respond(statusCode: number, headers = { 'content-type': 'application/json' }) {
      const res = Object.assign(new EventEmitter(), { statusCode, headers, destroy: vi.fn() });
      response!(res as unknown as http.IncomingMessage);
      return res;
    },
  };
}
afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});
it('fixes destination/method and constructs only normalized read paths and server headers', async () => {
  const w = wire();
  const result = readGateway(12345, 'SYNTHETIC-NOT-A-REAL-KEY', {
    kind: 'history',
    query: { limit: 25, offset: 0, status: 'pending', currency: 'EUR' },
  });
  expect(w.spy).toHaveBeenCalledWith(
    expect.objectContaining({
      hostname: '127.0.0.1',
      family: 4,
      port: 12345,
      method: 'GET',
      path: '/payments?limit=25&offset=0&status=pending&currency=EUR',
      headers: expect.objectContaining({
        Accept: 'application/json',
        Authorization: 'Bearer SYNTHETIC-NOT-A-REAL-KEY',
        'x-vaultx-read-operator': expectedOperator,
        'x-vaultx-read-permission': 'read_only',
      }),
    }),
    expect.any(Function),
  );
  expect(w.hooks.setTimeout).toHaveBeenCalledWith(2000, expect.any(Function));
  const res = w.respond(200);
  res.emit('data', Buffer.from('{}'));
  res.emit('end');
  expect(await result).toEqual({});
  expect(w.spy).toHaveBeenCalledTimes(1);
});
it.each(['idle', 'deadline'])(
  'bounds %s time without retrying or exposing the underlying network error',
  async (mode) => {
    vi.useFakeTimers();
    const w = wire();
    const pending = readGateway(12345, '', { kind: 'health' });
    const assertion = expect(pending).rejects.toMatchObject({
      status: 504,
      message: 'Dashboard upstream unavailable.',
    });
    if (mode === 'idle') w.idle();
    else await vi.advanceTimersByTimeAsync(5000);
    await assertion;
    expect(w.spy).toHaveBeenCalledTimes(1);
    expect(w.hooks.destroy).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  },
);
it.each([302, 307, 401, 403, 500])(
  'refuses upstream status %i without following redirects or returning upstream bodies',
  async (status) => {
    const w = wire();
    const pending = readGateway(12345, '', { kind: 'health' });
    const assertion = expect(pending).rejects.toMatchObject({
      status: [401, 403].includes(status) ? 503 : 502,
    });
    w.respond(status);
    await assertion;
    expect(w.spy).toHaveBeenCalledTimes(1);
  },
);
it.each(['size', 'malformed', 'type', 'aborted', 'network'])(
  'contains invalid upstream %s responses',
  async (mode) => {
    const w = wire();
    const pending = readGateway(12345, '', { kind: 'health' });
    const assertion = expect(pending).rejects.toMatchObject({
      status: 502,
      message: 'Dashboard upstream unavailable.',
    });
    if (mode === 'network') w.req.emit('error', new Error('PRIVATE_NETWORK_DETAIL'));
    else {
      const res = w.respond(200, {
        'content-type': mode === 'type' ? 'text/html' : 'application/json',
      });
      if (mode === 'aborted') res.emit('aborted');
      if (mode === 'size') res.emit('data', Buffer.alloc(256 * 1024 + 1));
      if (mode === 'malformed') {
        res.emit('data', Buffer.from('{'));
        res.emit('end');
      }
    }
    await assertion;
    expect(w.spy).toHaveBeenCalledTimes(1);
  },
);
it('rejects unsafe detail paths before opening any connection', async () => {
  const w = wire();
  await expect(readGateway(12345, '', { kind: 'detail', id: '../../keys' })).rejects.toMatchObject({
    status: 502,
  });
  expect(w.spy).not.toHaveBeenCalled();
});
it('fails closed on BFF configuration and never echoes invalid credential values', () => {
  expect(testConfig().dashboardBffEnabled).toBe(false);
  const settings = {
    DASHBOARD_ENABLED: 'true',
    DASHBOARD_PUBLIC_ORIGIN: 'https://bff.example.invalid',
    DASHBOARD_BFF_ENABLED: 'true',
  };
  expect(() => testConfig(settings)).toThrow();
  expect(() => testConfig({ ...settings, DASHBOARD_OPERATOR_ID: 'not-a-uuid' })).toThrow();
  const invalid = 'SYNTHETIC-PRIVATE-CONFIG';
  try {
    testConfig({ ...settings, DASHBOARD_READ_ONLY_API_KEY: invalid });
    expect.unreachable();
  } catch (error) {
    expect(error).toBeInstanceOf(ConfigError);
    expect(error instanceof Error && error.message.includes(invalid)).toBe(false);
  }
});
