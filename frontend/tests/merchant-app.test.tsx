import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { api, ApiError } from '../src/api';
import { DashboardAuth } from '../src/auth';
import { MerchantApp, MerchantWorkspace } from '../src/merchant/main';
import { merchantApi, MerchantApiError, type MerchantIdentity } from '../src/merchant/api';
const admin = '11111111-1111-4111-8111-111111111111';
const identity: MerchantIdentity = {
  user: { id: '22222222-2222-4222-8222-222222222222', username: 'synthetic_admin' },
  operator: { id: '33333333-3333-4333-8333-333333333333' },
  membership: { id: admin, version: 1 },
  permissions: [
    'client.users.read',
    'client.users.manage_subaccounts',
    'client.permissions.delegate',
    'client.payments.read',
    'client.status.read',
    'client.terminals.read',
    'client.audit.read',
  ],
};
const member = {
  id: '44444444-4444-4444-8444-444444444444',
  username: 'synthetic_child',
  status: 'active' as const,
  kind: 'submerchant' as const,
  version: 1,
  sponsorMembershipId: admin,
};
const page = { limit: 20 as const, offset: 0, hasMore: false };
afterEach(() => {
  cleanup();
  sessionStorage.clear();
  vi.restoreAllMocks();
  Object.defineProperty(navigator, 'locks', { configurable: true, value: undefined });
});
it('navigates actual merchant contracts and labels unavailable lifecycle boundaries', async () => {
  vi.spyOn(merchantApi, 'members').mockResolvedValue({ members: [member], pagination: page });
  vi.spyOn(merchantApi, 'terminals').mockResolvedValue({
    terminals: [
      {
        id: '55555555-5555-4555-8555-555555555555',
        code: 'synthetic_terminal',
        name: 'Synthetic terminal',
        status: 'active',
      },
    ],
    pagination: page,
  });
  vi.spyOn(merchantApi, 'audit').mockResolvedValue({ events: [], pagination: page });
  render(<MerchantWorkspace identity={identity} expired={vi.fn()} />);
  expect(
    screen.getByText(
      /Production enrollment, real invitation delivery and recovery remain disabled/,
    ),
  ).toBeTruthy();
  await userEvent.click(screen.getByRole('button', { name: 'Team and permissions' }));
  expect(await screen.findByText('synthetic_child')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Disable synthetic_child' })).toBeTruthy();
  await userEvent.click(screen.getByRole('button', { name: 'Terminals' }));
  expect(await screen.findByText('Synthetic terminal')).toBeTruthy();
  await userEvent.click(screen.getByRole('button', { name: 'Audit activity' }));
  expect(await screen.findByText('No events on this page.')).toBeTruthy();
});
it('does not show sponsor-only action buttons for another administrator’s restricted member', async () => {
  vi.spyOn(merchantApi, 'members').mockResolvedValue({
    members: [{ ...member, sponsorMembershipId: '66666666-6666-4666-8666-666666666666' }],
    pagination: page,
  });
  render(<MerchantWorkspace identity={identity} expired={vi.fn()} />);
  await userEvent.click(screen.getByRole('button', { name: 'Team and permissions' }));
  await screen.findByText('synthetic_child');
  expect(screen.queryByRole('button', { name: 'Disable synthetic_child' })).toBeNull();
  expect(
    screen.queryByRole('button', { name: 'Withdraw payment read for synthetic_child' }),
  ).toBeNull();
});
it('clears records and closes protected views on denied reads', async () => {
  const expired = vi.fn();
  vi.spyOn(merchantApi, 'members').mockRejectedValue(new MerchantApiError(403));
  render(<MerchantWorkspace identity={identity} expired={expired} />);
  await userEvent.click(screen.getByRole('button', { name: 'Team and permissions' }));
  await waitFor(() => expect(expired).toHaveBeenCalledTimes(1));
  expect(screen.queryByText('synthetic_child')).toBeNull();
  expect(screen.getByText(/Protected records are closed/)).toBeTruthy();
});
it('an ambiguous write closes records and offers no automatic retry', async () => {
  vi.spyOn(merchantApi, 'members').mockResolvedValue({ members: [member], pagination: page });
  const disable = vi.spyOn(merchantApi, 'disable').mockRejectedValue(new MerchantApiError(503));
  render(<MerchantWorkspace identity={identity} expired={vi.fn()} />);
  await userEvent.click(screen.getByRole('button', { name: 'Team and permissions' }));
  await userEvent.click(await screen.findByRole('button', { name: 'Disable synthetic_child' }));
  expect(await screen.findByText(/No automatic retry is permitted/)).toBeTruthy();
  expect(disable).toHaveBeenCalledTimes(1);
  expect(screen.queryByText('synthetic_child')).toBeNull();
});
it('hides invitation controls without exact nondelegable permissions', async () => {
  vi.spyOn(merchantApi, 'members').mockResolvedValue({ members: [], pagination: page });
  render(
    <MerchantWorkspace
      identity={{ ...identity, permissions: ['client.users.read'] }}
      expired={vi.fn()}
    />,
  );
  await userEvent.click(screen.getByRole('button', { name: 'Team and permissions' }));
  await screen.findByText('No members are available on this page.');
  expect(screen.queryByRole('button', { name: 'Record pending invitation' })).toBeNull();
});
it('prevents navigation or duplicate invocation while a write is pending and retains denial evidence after remount', async () => {
  vi.spyOn(merchantApi, 'members').mockResolvedValue({ members: [member], pagination: page });
  let reject!: (error: Error) => void;
  const pending = new Promise<never>((_resolve, fail) => {
    reject = fail;
  });
  const disable = vi.spyOn(merchantApi, 'disable').mockReturnValue(pending);
  const view = render(<MerchantWorkspace identity={identity} expired={vi.fn()} />);
  await userEvent.click(screen.getByRole('button', { name: 'Team and permissions' }));
  const action = await screen.findByRole('button', { name: 'Disable synthetic_child' });
  await userEvent.click(action);
  await userEvent.click(action);
  await userEvent.click(screen.getByRole('button', { name: 'Terminals' }));
  expect(disable).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('heading', { name: 'Team and permissions' })).toBeTruthy();
  expect(sessionStorage.getItem('vaultx-merchant-write-unconfirmed')).toBe('true');
  reject(new MerchantApiError(503));
  await screen.findByText(/No automatic retry is permitted/);
  view.unmount();
  const reads = vi.spyOn(merchantApi, 'members');
  reads.mockClear();
  render(<MerchantWorkspace identity={identity} expired={vi.fn()} />);
  expect(screen.getByText(/Protected records are closed/)).toBeTruthy();
  expect(reads).not.toHaveBeenCalled();
  expect(disable).toHaveBeenCalledTimes(1);
});
it('clears the per-tab deny flag only after a confirmed successful mutation', async () => {
  vi.spyOn(merchantApi, 'members').mockResolvedValue({ members: [member], pagination: page });
  vi.spyOn(merchantApi, 'disable').mockResolvedValue({ revoked: true, version: 2 });
  render(<MerchantWorkspace identity={identity} expired={vi.fn()} />);
  await userEvent.click(screen.getByRole('button', { name: 'Team and permissions' }));
  await userEvent.click(await screen.findByRole('button', { name: 'Disable synthetic_child' }));
  await screen.findByText('Restricted membership disabled.');
  expect(sessionStorage.getItem('vaultx-merchant-write-unconfirmed')).toBeNull();
});
it('provides direct secure client login without requiring the payment BFF and serializes duplicate submissions', async () => {
  let queue = Promise.resolve<unknown>(undefined);
  Object.defineProperty(navigator, 'locks', {
    configurable: true,
    value: {
      request: (_name: string, _options: unknown, work: () => Promise<unknown>) => {
        const result = queue.then(work);
        queue = result.catch(() => undefined);
        return result;
      },
    },
  });
  let finish!: () => void;
  const login = vi.fn(
    () =>
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
  );
  const me = vi
    .fn()
    .mockRejectedValueOnce(new ApiError(401))
    .mockRejectedValueOnce(new ApiError(401))
    .mockResolvedValue({
      user: identity.user,
      operator: identity.operator,
      role: 'viewer',
      authentication: {
        passkeyRequired: false,
        passkeyVerified: false,
        passkeyFresh: false,
        passkeysEnabled: false,
      },
    });
  const controller = new DashboardAuth({ ...api, me, login });
  vi.spyOn(merchantApi, 'me').mockResolvedValue(identity);
  render(<MerchantApp controller={controller} />);
  const form = await screen.findByRole('form', { name: 'Merchant sign-in' });
  const password = screen.getByLabelText<HTMLInputElement>('Password');
  await userEvent.type(screen.getByLabelText('Username'), 'synthetic_admin');
  await userEvent.type(password, 'synthetic-password-for-test');
  fireEvent.submit(form);
  fireEvent.submit(form);
  await waitFor(() => expect(login).toHaveBeenCalledTimes(1));
  expect(login).toHaveBeenCalledWith('synthetic_admin', 'synthetic-password-for-test');
  expect(password.value).toBe('');
  expect(screen.queryByRole('button', { name: 'Sign in securely' })).toBeNull();
  finish();
  expect(
    await screen.findByRole('heading', { name: 'Authorized merchant workspace' }),
  ).toBeTruthy();
});
it('refuses client authentication mutation when the browser has no Web Locks', async () => {
  const login = vi.fn().mockResolvedValue(undefined);
  const controller = new DashboardAuth({
    ...api,
    me: vi.fn().mockRejectedValue(new ApiError(401)),
    login,
  });
  render(<MerchantApp controller={controller} />);
  const form = await screen.findByRole('form', { name: 'Merchant sign-in' });
  await userEvent.type(screen.getByLabelText('Username'), 'synthetic_admin');
  await userEvent.type(screen.getByLabelText('Password'), 'synthetic-password-for-test');
  fireEvent.submit(form);
  await screen.findByText(/Sign-in could not be confirmed/);
  expect(login).not.toHaveBeenCalled();
});
