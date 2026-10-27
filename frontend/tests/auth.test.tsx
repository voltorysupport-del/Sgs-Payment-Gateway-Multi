import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { DashboardAuth } from '../src/auth';
import { api, ApiError, type Identity } from '../src/api';

const identity: Identity = {
  user: { id: '11111111-1111-4111-8111-111111111111', username: 'synthetic-viewer' },
  operator: { id: '22222222-2222-4222-8222-222222222222' },
  role: 'viewer',
  authentication: {
    passkeyRequired: false,
    passkeyVerified: false,
    passkeyFresh: false,
    passkeysEnabled: false,
  },
};
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
// Faithful origin-wide exclusive queue: aborted queued locks never execute work.
export function installLocks() {
  let queue = Promise.resolve();
  Object.defineProperty(navigator, 'locks', {
    configurable: true,
    value: {
      request: vi.fn(
        (_name: string, options: { signal?: AbortSignal }, work: () => Promise<unknown>) => {
          const result = queue.then(() => {
            if (options.signal?.aborted) throw new DOMException('Aborted', 'AbortError');
            return work();
          });
          queue = result.then(
            () => undefined,
            () => undefined,
          );
          return result;
        },
      ),
    },
  });
}
const stops: (() => void)[] = [];
function start(client: typeof api) {
  const auth = new DashboardAuth(client);
  stops.push(auth.start());
  return auth;
}
function visibility(value: 'visible' | 'hidden') {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value });
  document.dispatchEvent(new Event('visibilitychange'));
}
const notices: unknown[] = [];
class Channel {
  static all = new Set<Channel>();
  onmessage: ((event: MessageEvent<unknown>) => void) | null = null;
  constructor(_topic: string) {
    Channel.all.add(this);
  }
  postMessage(data: unknown) {
    notices.push(data);
    for (const c of Channel.all)
      if (c !== this) queueMicrotask(() => c.onmessage?.({ data } as MessageEvent<unknown>));
  }
  close() {
    Channel.all.delete(this);
  }
}
beforeEach(() => {
  installLocks();
  visibility('visible');
  vi.stubGlobal('BroadcastChannel', undefined);
});
afterEach(() => {
  stops.splice(0).forEach((stop) => stop());
  Channel.all.clear();
  notices.length = 0;
  vi.unstubAllGlobals();
});
for (const channel of [false, true])
  it(`never restores identity across overlapping logout, history, visibility and late reads (channel=${channel})`, async () => {
    if (channel) vi.stubGlobal('BroadcastChannel', Channel);
    const logout = deferred<void>();
    const me = vi.fn().mockResolvedValue(identity),
      write = vi.fn(() => logout.promise);
    const auth = start({ ...api, me, logout: write });
    await vi.waitFor(() => expect(auth.snapshot().phase).toBe('authenticated'));
    const pending = auth.logout();
    expect(auth.snapshot()).toEqual({ phase: 'logout' });
    visibility('hidden');
    visibility('visible');
    window.dispatchEvent(new Event('pageshow'));
    await auth.check();
    await vi.waitFor(() => expect(write).toHaveBeenCalledOnce());
    expect(auth.snapshot()).toEqual({ phase: 'logout' });
    me.mockRejectedValue(new ApiError(401));
    logout.resolve();
    await pending;
    expect(auth.snapshot()).toEqual({ phase: 'anonymous' });
    await auth.check();
    expect(auth.snapshot()).toEqual({ phase: 'anonymous' });
  });
it('keeps a failed logout blocked across automatic events until explicit reconciliation', async () => {
  const me = vi.fn().mockResolvedValue(identity),
    logout = vi.fn().mockRejectedValue(new ApiError(503));
  const auth = start({ ...api, me, logout });
  await vi.waitFor(() => expect(auth.snapshot().phase).toBe('authenticated'));
  await auth.logout();
  const calls = me.mock.calls.length;
  visibility('hidden');
  visibility('visible');
  window.dispatchEvent(new Event('pageshow'));
  await auth.check();
  expect(me).toHaveBeenCalledTimes(calls);
  expect(auth.snapshot().phase).toBe('blocked');
  await auth.check(true);
  expect(auth.snapshot().phase).toBe('authenticated');
  expect(logout).toHaveBeenCalledOnce();
});
it('retains app ownership of pending login across hide/show and ignores duplicate submissions', async () => {
  const pending = deferred<void>();
  let active = false;
  const me = vi.fn(() => (active ? Promise.resolve(identity) : Promise.reject(new ApiError(401))));
  const login = vi.fn(async () => {
    await pending.promise;
    active = true;
  });
  const auth = start({ ...api, me, login });
  await vi.waitFor(() => expect(auth.snapshot().phase).toBe('anonymous'));
  const operation = auth.login('viewer', 'synthetic password');
  await vi.waitFor(() => expect(login).toHaveBeenCalledOnce());
  visibility('hidden');
  visibility('visible');
  window.dispatchEvent(new Event('pageshow'));
  await auth.login('other', 'other synthetic password');
  expect(auth.snapshot().phase).toBe('login');
  expect(login).toHaveBeenCalledOnce();
  visibility('hidden');
  pending.resolve();
  await operation;
  expect(auth.snapshot()).toEqual({ phase: 'checking' });
  visibility('visible');
  await vi.waitFor(() => expect(auth.snapshot().phase).toBe('authenticated'));
});
it('blocks ambiguous login outcomes even when a cookie was committed; never automatically retries', async () => {
  let active = false;
  const login = vi.fn(() => {
    active = true;
    return Promise.reject(new ApiError(503));
  });
  const me = vi.fn(() => (active ? Promise.resolve(identity) : Promise.reject(new ApiError(401))));
  const auth = start({ ...api, login, me });
  await vi.waitFor(() => expect(auth.snapshot().phase).toBe('anonymous'));
  await auth.login('viewer', 'synthetic password');
  expect(auth.snapshot().phase).toBe('blocked');
  await auth.login('viewer', 'synthetic password');
  visibility('hidden');
  visibility('visible');
  await auth.check();
  expect(auth.snapshot().phase).toBe('blocked');
  expect(login).toHaveBeenCalledOnce();
  await auth.check(true);
  expect(auth.snapshot().phase).toBe('authenticated');
});
it('synchronizes login/logout across tabs and avoids submitting a stale login against a shared authenticated cookie', async () => {
  vi.stubGlobal('BroadcastChannel', Channel);
  let active = false;
  const me = vi.fn(() => (active ? Promise.resolve(identity) : Promise.reject(new ApiError(401))));
  const login = vi.fn(() => {
      active = true;
      return Promise.resolve();
    }),
    logout = vi.fn(() => {
      active = false;
      return Promise.resolve();
    });
  const client = { ...api, me, login, logout };
  const a = start(client),
    b = start(client);
  await vi.waitFor(() =>
    expect([a.snapshot().phase, b.snapshot().phase]).toEqual(['anonymous', 'anonymous']),
  );
  await a.login('viewer', 'synthetic password');
  await vi.waitFor(() => expect(b.snapshot().phase).toBe('authenticated'));
  await b.logout();
  await vi.waitFor(() => expect(a.snapshot().phase).toBe('anonymous'));
  active = true;
  await a.login('stale', 'synthetic password');
  expect(a.snapshot().identity).toEqual(identity);
  expect(login).toHaveBeenCalledOnce();
  expect(
    notices.every((value) =>
      ['auth-start', 'auth-changed', 'auth-unconfirmed'].includes(String(value)),
    ),
  ).toBe(true);
});
it('fails closed for authentication writes without origin-wide lock support', async () => {
  Object.defineProperty(navigator, 'locks', { configurable: true, value: undefined });
  const login = vi.fn();
  const auth = start({ ...api, me: vi.fn().mockRejectedValue(new ApiError(401)), login });
  await vi.waitFor(() => expect(auth.snapshot().phase).toBe('anonymous'));
  await auth.login('viewer', 'synthetic password');
  expect(login).not.toHaveBeenCalled();
  expect(auth.snapshot().phase).toBe('blocked');
});
it('reconciles a queued mutation after owner cleanup/restart and ignores stale expiry callbacks', async () => {
  const login = deferred<void>();
  let active = false;
  const client = {
    ...api,
    me: vi.fn(() => (active ? Promise.resolve(identity) : Promise.reject(new ApiError(401)))),
    login: vi.fn(async () => {
      await login.promise;
      active = true;
    }),
  };
  const auth = new DashboardAuth(client);
  let stop = auth.start();
  await vi.waitFor(() => expect(auth.snapshot().phase).toBe('anonymous'));
  const oldVersion = auth.version();
  const pending = auth.login('viewer', 'synthetic password');
  await vi.waitFor(() => expect(client.login).toHaveBeenCalledOnce());
  stop();
  stop = auth.start();
  stops.push(stop);
  expect(auth.snapshot().phase).toBe('login');
  login.resolve();
  await pending;
  await vi.waitFor(() => expect(auth.snapshot().phase).toBe('authenticated'));
  auth.expire(oldVersion);
  expect(auth.snapshot().phase).toBe('authenticated');
});
it('retains an unconfirmed logout barrier across owner cleanup/restart', async () => {
  const response = deferred<void>();
  const auth = new DashboardAuth({
    ...api,
    me: vi.fn().mockResolvedValue(identity),
    logout: vi.fn(() =>
      response.promise.then(() => {
        throw new ApiError(503);
      }),
    ),
  });
  let stop = auth.start();
  await vi.waitFor(() => expect(auth.snapshot().phase).toBe('authenticated'));
  const pending = auth.logout();
  await Promise.resolve();
  await Promise.resolve();
  stop();
  stop = auth.start();
  stops.push(stop);
  response.resolve();
  await pending;
  await vi.waitFor(() => expect(auth.snapshot().phase).toBe('blocked'));
  await auth.check();
  expect(auth.snapshot().phase).toBe('blocked');
});
it('uses authoritative visibility reconciliation when BroadcastChannel construction is denied', async () => {
  vi.stubGlobal(
    'BroadcastChannel',
    class {
      constructor() {
        throw new DOMException('Unavailable', 'SecurityError');
      }
    },
  );
  const me = vi.fn().mockRejectedValue(new ApiError(401));
  const auth = start({ ...api, me });
  await vi.waitFor(() => expect(auth.snapshot().phase).toBe('anonymous'));
  me.mockResolvedValue(identity);
  visibility('hidden');
  visibility('visible');
  await vi.waitFor(() => expect(auth.snapshot().phase).toBe('authenticated'));
});
