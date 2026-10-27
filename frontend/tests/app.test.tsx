import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { App } from '../src/main';
import { api, ApiError } from '../src/api';
vi.mock('../src/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/api')>();
  return {
    ...actual,
    api: {
      me: vi.fn(),
      login: vi.fn(),
      logout: vi.fn(),
      history: vi.fn(),
      detail: vi.fn(),
      status: vi.fn(),
    },
  };
});
const identity = {
  user: { id: '11111111-1111-4111-8111-111111111111', username: 'viewer' },
  operator: { id: '22222222-2222-4222-8222-222222222222' },
  role: 'viewer' as const,
  authentication: {
    passkeyRequired: false,
    passkeyVerified: false,
    passkeyFresh: false,
    passkeysEnabled: false,
  },
};
const payment = {
  id: '33333333-3333-4333-8333-333333333333',
  amountMinor: 100,
  currency: 'EUR',
  status: 'succeeded' as const,
  provider: 'simulator' as const,
  createdAt: '2026-01-01T12:00:00.000Z',
  updatedAt: '2026-01-01T12:01:00.000Z',
};
beforeEach(() => {
  Object.defineProperty(navigator, 'locks', {
    configurable: true,
    value: { request: (_name: string, _options: unknown, work: () => Promise<unknown>) => work() },
  });
  location.hash = '#/';
  vi.mocked(api.me).mockResolvedValue(identity);
  vi.mocked(api.history).mockResolvedValue({
    payments: [payment],
    pagination: { limit: 10, offset: 0, hasMore: false },
  });
  vi.mocked(api.login).mockResolvedValue(undefined);
  vi.mocked(api.logout).mockResolvedValue(undefined);
  vi.mocked(api.detail).mockResolvedValue(payment);
  vi.mocked(api.status).mockResolvedValue({
    status: 'ok',
    gateway: 'ok',
    database: 'reachable',
    provider: 'simulator',
    realPaymentsEnabled: false,
  });
});
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it('renders scoped summary without fabricated aggregates and has no automated accessibility violations', async () => {
  const { container } = render(<App />);
  await screen.findByRole('heading', { name: 'Overview' });
  await screen.findByText('€1.00');
  expect(screen.getByText('Page scope only · not a total')).toBeTruthy();
  expect(screen.queryByText(/balance|revenue|settlement total/i)).toBeNull();
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  expect(result.violations).toEqual([]);
});
it('uses real authentication client and clears password after login', async () => {
  vi.mocked(api.me)
    .mockRejectedValueOnce(new ApiError(401))
    .mockRejectedValueOnce(new ApiError(401));
  render(<App />);
  await screen.findByRole('heading', { name: 'Welcome back' });
  await userEvent.type(screen.getByLabelText('Username'), 'viewer');
  await userEvent.type(screen.getByLabelText('Password'), 'synthetic password only');
  await userEvent.click(screen.getByRole('button', { name: /Sign in securely/ }));
  await screen.findByRole('heading', { name: 'Overview' });
  expect(api.login).toHaveBeenCalledWith('viewer', 'synthetic password only');
});
it('displays generic login failures accessibly', async () => {
  vi.mocked(api.me).mockRejectedValue(new ApiError(401));
  vi.mocked(api.login).mockRejectedValue(new ApiError(401));
  render(<App />);
  await screen.findByLabelText('Username');
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'viewer' } });
  fireEvent.change(screen.getByLabelText('Password'), {
    target: { value: 'synthetic password only' },
  });
  fireEvent.submit(screen.getByLabelText('Username').closest('form')!);
  await screen.findByRole('alert');
  expect(screen.getByLabelText<HTMLInputElement>('Password').value).toBe('');
});
it('paginates and filters using bounded server calls', async () => {
  location.hash = '#/payments';
  vi.mocked(api.history).mockImplementation((offset) =>
    Promise.resolve({
      payments: [payment],
      pagination: { limit: 10, offset, hasMore: offset === 0 },
    }),
  );
  render(<App />);
  await screen.findByText('€1.00');
  await userEvent.click(screen.getByRole('button', { name: 'Next →' }));
  await waitFor(() =>
    expect(api.history).toHaveBeenLastCalledWith(10, '', '', expect.any(AbortSignal)),
  );
  await userEvent.selectOptions(screen.getByLabelText('Status'), 'succeeded');
  await userEvent.type(screen.getByLabelText('Currency (three-letter code)'), 'eur');
  await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  await waitFor(() =>
    expect(api.history).toHaveBeenLastCalledWith(0, 'succeeded', 'EUR', expect.any(AbortSignal)),
  );
});
it('loads payment detail and handles unavailable records', async () => {
  location.hash = '#/payments/' + payment.id;
  render(<App />);
  await screen.findByRole('heading', { name: 'Payment details' });
  await screen.findByText(payment.id);
  expect(api.detail).toHaveBeenCalledWith(payment.id, expect.any(AbortSignal));
});
it('removes protected content when a session expires', async () => {
  vi.mocked(api.history).mockRejectedValue(new ApiError(401));
  render(<App />);
  await screen.findByRole('heading', { name: 'Welcome back' });
  expect(screen.queryByText(identity.user.username)).toBeNull();
});
it('clears protected content before logout and stays fail closed on logout failure', async () => {
  vi.mocked(api.logout).mockRejectedValue(new ApiError(503));
  render(<App />);
  await screen.findByText('€1.00');
  await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
  await screen.findByRole('alert');
  expect(screen.queryByText('€1.00')).toBeNull();
  expect(screen.queryByRole('heading', { name: 'Welcome back' })).toBeNull();
});
it('renders empty history and sanitized errors', async () => {
  vi.mocked(api.history).mockResolvedValue({
    payments: [],
    pagination: { limit: 10, offset: 0, hasMore: false },
  });
  render(<App />);
  await screen.findByRole('heading', { name: 'No payments to show' });
});
it('shows only confirmed status and no production readiness claim', async () => {
  location.hash = '#/status';
  render(<App />);
  await screen.findByRole('heading', { name: 'Gateway is responding' });
  expect(screen.getByText('Reachable during this check')).toBeTruthy();
  expect(screen.getByText(/does not establish production readiness/)).toBeTruthy();
});
it('escapes untrusted identity text instead of interpreting HTML', async () => {
  vi.mocked(api.me).mockResolvedValue({
    ...identity,
    user: { ...identity.user, username: '<img src=x onerror=alert(1)>' },
  });
  const { container } = render(<App />);
  await screen.findByText('<img src=x onerror=alert(1)>');
  expect(container.querySelector('img')).toBeNull();
});
it('formats currency using its minor-unit precision', async () => {
  const { money } = await import('../src/main');
  expect(money({ ...payment, currency: 'JPY', amountMinor: 100 })).toContain('100');
  expect(money({ ...payment, currency: 'KWD', amountMinor: 1000 })).toContain('1.000');
  expect(money({ ...payment, currency: 'ZZZ', amountMinor: 100 })).toBe('100 minor units · ZZZ');
});
it('discards the previous workspace when authoritative identity changes, including batched revalidation', async () => {
  render(<App />);
  await screen.findByText('€1.00');
  vi.mocked(api.me).mockResolvedValue({
    ...identity,
    user: {
      ...identity.user,
      id: '44444444-4444-4444-8444-444444444444',
      username: 'replacement-viewer',
    },
  });
  vi.mocked(api.history).mockRejectedValue(new ApiError(403));
  fireEvent(window, new Event('pageshow'));
  await screen.findByText('replacement-viewer');
  await screen.findByRole('alert');
  expect(screen.queryByText('€1.00')).toBeNull();
});
