import { afterEach, expect, it, vi } from 'vitest';
import { api, ApiError } from '../src/api';
afterEach(() => vi.unstubAllGlobals());
it('uses same-origin cookies and CSRF with no Bearer headers or storage', async () => {
  const token = 'a'.repeat(64);
  const fetcher = vi
    .fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({ csrfToken: token })))
    .mockResolvedValueOnce(new Response(JSON.stringify({ authenticated: true, csrfToken: token })));
  vi.stubGlobal('fetch', fetcher);
  await api.login('viewer', 'synthetic fixture password');
  expect(fetcher).toHaveBeenNthCalledWith(
    1,
    '/dashboard-api/auth/csrf',
    expect.objectContaining({ credentials: 'same-origin', cache: 'no-store', redirect: 'error' }),
  );
  const [, init] = fetcher.mock.calls[1]! as [string, RequestInit];
  expect(init.headers).toEqual({ 'Content-Type': 'application/json', 'X-CSRF-Token': token });
  expect(localStorage.length).toBe(0);
  expect(sessionStorage.length).toBe(0);
});
it('logout accepts empty 204 and obtains a fresh CSRF token', async () => {
  vi.stubGlobal(
    'fetch',
    vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ csrfToken: 'a'.repeat(64) })))
      .mockResolvedValueOnce(new Response(null, { status: 204 })),
  );
  await api.logout();
});
it('rejects unexpected live provider / payment detail ID and never returns raw error bodies', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(new Response('PRIVATE ERROR DETAILS', { status: 503 })),
  );
  await expect(api.status()).rejects.toThrow('This request could not be completed.');
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          status: 'ok',
          gateway: 'ok',
          database: 'reachable',
          provider: 'live',
          realPaymentsEnabled: true,
        }),
      ),
    ),
  );
  await expect(api.status()).rejects.toBeInstanceOf(ApiError);
});
it('rejects malformed IDs before fetch', async () => {
  const fetcher = vi.fn();
  vi.stubGlobal('fetch', fetcher);
  await expect(api.detail('../../payments')).rejects.toThrow('Payment not found.');
  expect(fetcher).not.toHaveBeenCalled();
});
it('rejects mismatched pagination and non-simulator payment records', async () => {
  const p = {
    id: '33333333-3333-4333-8333-333333333333',
    amountMinor: 100,
    currency: 'EUR',
    status: 'pending',
    provider: 'simulator',
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
  };
  vi.stubGlobal(
    'fetch',
    vi
      .fn()
      .mockResolvedValue(
        new Response(
          JSON.stringify({ payments: [p], pagination: { limit: 10, offset: 10, hasMore: false } }),
        ),
      ),
  );
  await expect(api.history(0, '', '')).rejects.toBeInstanceOf(ApiError);
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...p, provider: 'live' }))),
  );
  await expect(api.detail(p.id)).rejects.toBeInstanceOf(ApiError);
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(p))));
  await expect(api.detail('44444444-4444-4444-8444-444444444444')).rejects.toBeInstanceOf(ApiError);
});
it('keeps cookie-setting sequences pending beyond the read deadline instead of allowing late-cookie retries', async () => {
  vi.useFakeTimers();
  try {
    let release!: (response: Response) => void;
    const pending = new Promise<Response>((resolve) => {
      release = resolve;
    });
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ csrfToken: 'a'.repeat(64) })))
      .mockReturnValueOnce(pending);
    vi.stubGlobal('fetch', fetcher);
    const operation = api.login('viewer', 'synthetic password only');
    await vi.advanceTimersByTimeAsync(13000);
    expect(fetcher).toHaveBeenCalledTimes(2);
    const options = fetcher.mock.calls[1]![1] as RequestInit;
    expect(options.signal?.aborted).toBe(false);
    release(new Response(JSON.stringify({ authenticated: true, csrfToken: 'a'.repeat(64) })));
    await operation;
  } finally {
    vi.useRealTimers();
  }
});
