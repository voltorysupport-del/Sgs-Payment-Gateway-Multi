import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { OwnerApp } from '../src/owner/main';
import { ownerApi, OwnerApiError } from '../src/owner/api';
vi.mock('../src/owner/api', async (original) => {
  const actual = await original<typeof import('../src/owner/api')>();
  return {
    ...actual,
    ownerApi: {
      me: vi.fn(),
      logout: vi.fn(),
      operators: vi.fn(),
      operator: vi.fn(),
      memberships: vi.fn(),
      updateOperator: vi.fn(),
      createMerchant: vi.fn(),
      inviteAdministrator: vi.fn(),
      setStatus: vi.fn(),
      withdraw: vi.fn(),
      audit: vi.fn(),
    },
  };
});
const owner = {
  owner: { id: '11111111-1111-4111-8111-111111111111', username: 'synthetic.owner' },
  permissions: ['platform.clients.read', 'platform.clients.manage', 'platform.audit.read'] as (
    'platform.clients.read' | 'platform.clients.manage' | 'platform.audit.read'
  )[],
};
const operator = {
  id: '22222222-2222-4222-8222-222222222222',
  name: 'Synthetic client A',
  code: 'client_a',
  status: 'active' as const,
  version: 7,
};
const pagination = { limit: 20 as const, offset: 0, hasMore: false };
beforeEach(() => {
  location.hash = '#/';
  sessionStorage.clear();
  vi.mocked(ownerApi.me).mockResolvedValue(owner);
  vi.mocked(ownerApi.operators).mockResolvedValue({ operators: [operator], pagination });
  vi.mocked(ownerApi.operator).mockResolvedValue(operator);
  vi.mocked(ownerApi.memberships).mockResolvedValue({
    operatorId: operator.id,
    members: [
      {
        id: '33333333-3333-4333-8333-333333333333',
        role: 'viewer',
        status: 'active',
        authorizationVersion: 2,
        grants: [
          {
            id: '44444444-4444-4444-8444-444444444444',
            permission: 'client.payments.read',
            revokedAt: null,
          },
        ],
      },
    ],
    pagination,
  });
  vi.mocked(ownerApi.audit).mockResolvedValue({
    events: [
      {
        id: '55555555-5555-4555-8555-555555555555',
        actorId: owner.owner.id,
        operatorId: operator.id,
        action: 'operator.metadata.updated',
        occurredAt: '2026-01-01T00:00:00.000Z',
      },
    ],
    pagination,
  });
  vi.mocked(ownerApi.updateOperator).mockResolvedValue({ operator: { ...operator, version: 8 } });
  vi.mocked(ownerApi.setStatus).mockResolvedValue({
    operator: { ...operator, version: 8, status: 'suspended' },
  });
  vi.mocked(ownerApi.withdraw).mockResolvedValue(undefined);
  vi.mocked(ownerApi.logout).mockResolvedValue(undefined);
  vi.mocked(ownerApi.createMerchant).mockResolvedValue({ operator: { ...operator, version: 1 } });
  vi.mocked(ownerApi.inviteAdministrator).mockResolvedValue({
    invitationId: '77777777-7777-4777-8777-777777777777',
    expiresAt: '2026-12-01T00:00:00.000Z',
    status: 'pending',
    activationEnabled: false,
  });
});
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
  vi.unstubAllGlobals();
  sessionStorage.clear();
});
async function openOperators() {
  await userEvent.click(await screen.findByRole('link', { name: 'Operators' }));
  await screen.findByText(operator.name);
}
it('has a separate denied owner entry, no password-only login, and no directory calls', async () => {
  vi.mocked(ownerApi.me).mockRejectedValue(new OwnerApiError(401));
  render(<OwnerApp />);
  await screen.findByRole('heading', { name: 'Owner authentication required' });
  expect(screen.queryByLabelText(/password/i)).toBeNull();
  expect(ownerApi.operators).not.toHaveBeenCalled();
  expect(screen.getByText(/MFA and recovery require separately approved/)).toBeTruthy();
});
it('renders server-returned capabilities without fabricated metrics and passes automated accessibility checks', async () => {
  const { container } = render(<OwnerApp />);
  await screen.findByRole('heading', { name: 'Owner overview' });
  expect(screen.getByText('platform.clients.manage')).toBeTruthy();
  expect(screen.queryByText(/settlement balance/i)).toBeNull();
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  expect(result.violations).toEqual([]);
});
it('inspects clients and sends optimistic versioned metadata changes', async () => {
  render(<OwnerApp />);
  await openOperators();
  await userEvent.click(screen.getByRole('button', { name: 'Inspect client_a' }));
  const input = await screen.findByLabelText('Display name');
  await userEvent.clear(input);
  await userEvent.type(input, 'Updated synthetic client');
  await userEvent.click(screen.getByRole('button', { name: 'Save display name' }));
  await waitFor(() =>
    expect(ownerApi.updateOperator).toHaveBeenCalledWith(operator.id, {
      name: 'Updated synthetic client',
      expectedVersion: 7,
    }),
  );
});
it('team data uses explicit retained membership grants and provides no promotions or invitations', async () => {
  render(<OwnerApp />);
  await userEvent.click(await screen.findByRole('link', { name: 'Team and permissions' }));
  await screen.findByText(operator.name);
  await userEvent.click(screen.getByRole('button', { name: 'Inspect client_a' }));
  await screen.findByText('client.payments.read');
  expect(screen.queryByRole('button', { name: /promote|invite|create account/i })).toBeNull();
});
it('shows sanitized audit fields through its own authorized route', async () => {
  render(<OwnerApp />);
  await userEvent.click(await screen.findByRole('link', { name: 'Audit activity' }));
  await screen.findByText('operator.metadata.updated');
  expect(ownerApi.audit).toHaveBeenCalled();
});
it('403 during inspection clears already-rendered directory data and cached owner identity', async () => {
  render(<OwnerApp />);
  await openOperators();
  vi.mocked(ownerApi.operator).mockRejectedValue(new OwnerApiError(403));
  await userEvent.click(screen.getByRole('button', { name: 'Inspect client_a' }));
  await screen.findByRole('heading', { name: 'Owner authentication required' });
  expect(screen.queryByText(operator.name)).toBeNull();
  expect(screen.queryByText(owner.owner.username)).toBeNull();
});
it('logout clears protected views before its request completes and prevents focus from reviving stale cookies', async () => {
  let resolve!: () => void;
  vi.mocked(ownerApi.logout).mockImplementation(
    () =>
      new Promise<void>((r) => {
        resolve = r;
      }),
  );
  render(<OwnerApp />);
  await openOperators();
  await userEvent.click(screen.getByRole('button', { name: 'Sign out owner' }));
  await screen.findByRole('heading', { name: 'Signing out owner…' });
  expect(screen.queryByText(operator.name)).toBeNull();
  const checks = vi.mocked(ownerApi.me).mock.calls.length;
  fireEvent.focus(window);
  await act(async () => {
    resolve();
    await Promise.resolve();
  });
  expect(ownerApi.me).toHaveBeenCalledTimes(checks);
  expect(screen.queryByRole('button', { name: 'Check existing owner session' })).toBeNull();
});
it('ignores a late directory response after local logout', async () => {
  let resolve!: (value: Awaited<ReturnType<typeof ownerApi.operators>>) => void;
  vi.mocked(ownerApi.operators).mockImplementation(
    () =>
      new Promise((r) => {
        resolve = r;
      }),
  );
  render(<OwnerApp />);
  await userEvent.click(await screen.findByRole('link', { name: 'Operators' }));
  await waitFor(() => expect(ownerApi.operators).toHaveBeenCalled());
  await userEvent.click(screen.getByRole('button', { name: 'Sign out owner' }));
  await act(async () => {
    resolve({ operators: [operator], pagination });
    await Promise.resolve();
  });
  expect(screen.queryByText(operator.name)).toBeNull();
});
it('a session-close cross-tab notice clears owner-only data without trusting any identity payload', async () => {
  let message: ((value: unknown) => void) | undefined;
  class Channel {
    set onmessage(value: ((value: unknown) => void) | null) {
      message = value ?? undefined;
    }
    postMessage() {}
    close() {}
  }
  vi.stubGlobal('BroadcastChannel', Channel);
  render(<OwnerApp />);
  await openOperators();
  act(() => {
    message?.({ data: { owner: owner, permissions: ['*'] } });
  });
  await screen.findByRole('heading', { name: 'Owner authentication required' });
  expect(screen.queryByText(operator.name)).toBeNull();
  vi.unstubAllGlobals();
});
it('does not call the client directory for an owner lacking its exact permission', async () => {
  vi.mocked(ownerApi.me).mockResolvedValue({ ...owner, permissions: ['platform.audit.read'] });
  render(<OwnerApp />);
  await userEvent.click(await screen.findByRole('link', { name: 'Operators' }));
  await screen.findByRole('alert');
  expect(ownerApi.operators).not.toHaveBeenCalled();
});
it('clears the previous owner view before resolving a different identity after focus', async () => {
  render(<OwnerApp />);
  await openOperators();
  let resolve!: (v: typeof owner) => void;
  vi.mocked(ownerApi.me).mockImplementation(
    () =>
      new Promise((r) => {
        resolve = r;
      }),
  );
  fireEvent.focus(window);
  expect(screen.queryByText(operator.name)).toBeNull();
  expect(screen.queryByText(owner.owner.username)).toBeNull();
  await act(async () => {
    resolve({
      ...owner,
      owner: {
        ...owner.owner,
        id: '66666666-6666-4666-8666-666666666666',
        username: 'second.owner',
      },
    });
    await Promise.resolve();
  });
  await screen.findByText('second.owner');
});
it('version conflicts are shown without automatically retrying a privileged change', async () => {
  vi.mocked(ownerApi.updateOperator).mockRejectedValue(new OwnerApiError(409));
  render(<OwnerApp />);
  await openOperators();
  await userEvent.click(screen.getByRole('button', { name: 'Inspect client_a' }));
  await screen.findByLabelText('Display name');
  await userEvent.click(screen.getByRole('button', { name: 'Save display name' }));
  await screen.findByText(/This record changed/);
  expect(ownerApi.updateOperator).toHaveBeenCalledTimes(1);
});
it('ambiguous writes close stale forms and require explicit session and record refresh without retry', async () => {
  vi.mocked(ownerApi.updateOperator).mockRejectedValue(new OwnerApiError(503));
  render(<OwnerApp />);
  await openOperators();
  await userEvent.click(screen.getByRole('button', { name: 'Inspect client_a' }));
  await screen.findByLabelText('Display name');
  await userEvent.click(screen.getByRole('button', { name: 'Save display name' }));
  await screen.findByText(/Change outcome not confirmed/);
  expect(screen.queryByLabelText('Display name')).toBeNull();
  const checks = vi.mocked(ownerApi.me).mock.calls.length;
  fireEvent.focus(window);
  await act(async () => {
    await Promise.resolve();
  });
  expect(ownerApi.me).toHaveBeenCalledTimes(checks);
  expect(ownerApi.updateOperator).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByRole('button', { name: 'Check existing owner session' }));
  await screen.findByRole('heading', { name: 'Operators' });
  expect(ownerApi.me).toHaveBeenCalledTimes(checks + 1);
  expect(screen.queryByLabelText('Display name')).toBeNull();
});
it('reports unconfirmed logout even when persistent denial storage is unavailable', async () => {
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new Error('Storage unavailable');
  });
  vi.mocked(ownerApi.logout).mockRejectedValue(new OwnerApiError(503));
  render(<OwnerApp />);
  await openOperators();
  await userEvent.click(screen.getByRole('button', { name: 'Sign out owner' }));
  await screen.findByRole('heading', { name: 'Owner sign-out not confirmed' });
  expect(screen.getByText(/The server session may still be active/)).toBeTruthy();
  expect(screen.queryByText(operator.name)).toBeNull();
  const checks = vi.mocked(ownerApi.me).mock.calls.length;
  fireEvent.focus(window);
  await act(async () => {
    await Promise.resolve();
  });
  expect(ownerApi.me).toHaveBeenCalledTimes(checks);
  expect(screen.queryByRole('button', { name: 'Check existing owner session' })).toBeNull();
});

it('creates an empty merchant organization through its authorized API without provisioning credentials', async () => {
  vi.stubGlobal(
    'confirm',
    vi.fn(() => true),
  );
  render(<OwnerApp />);
  await openOperators();
  await userEvent.type(screen.getByLabelText('Immutable merchant code'), 'synthetic-merchant');
  await userEvent.type(screen.getByLabelText('Merchant display name'), 'Synthetic Merchant');
  await userEvent.click(screen.getByRole('button', { name: 'Create merchant' }));
  await waitFor(() =>
    expect(ownerApi.createMerchant).toHaveBeenCalledWith({
      code: 'synthetic-merchant',
      name: 'Synthetic Merchant',
    }),
  );
  expect(ownerApi.createMerchant).toHaveBeenCalledTimes(1);
});
it('hides creation and administrator invitations without their exact permissions', async () => {
  vi.mocked(ownerApi.me).mockResolvedValue({ ...owner, permissions: ['platform.clients.read'] });
  render(<OwnerApp />);
  await openOperators();
  expect(screen.queryByLabelText('Immutable merchant code')).toBeNull();
  await userEvent.click(screen.getByRole('link', { name: 'Team and permissions' }));
  await screen.findByText(operator.name);
  await userEvent.click(screen.getByRole('button', { name: 'Inspect client_a' }));
  await screen.findByText('client.payments.read');
  expect(screen.queryByLabelText('Proposed administrator username')).toBeNull();
});
it('records pending administrator intent only with the separate bootstrap permission and explicit choices', async () => {
  vi.stubGlobal(
    'confirm',
    vi.fn(() => true),
  );
  vi.mocked(ownerApi.me).mockResolvedValue({
    ...owner,
    permissions: [...owner.permissions, 'platform.clients.bootstrap_admin'],
  });
  render(<OwnerApp />);
  await userEvent.click(await screen.findByRole('link', { name: 'Team and permissions' }));
  await screen.findByText(operator.name);
  await userEvent.click(screen.getByRole('button', { name: 'Inspect client_a' }));
  await userEvent.type(
    await screen.findByLabelText('Proposed administrator username'),
    'synthetic.admin',
  );
  expect(screen.getByText(/Activation is not available/)).toBeTruthy();
  await userEvent.click(screen.getByRole('checkbox', { name: 'client.users.manage_subaccounts' }));
  await userEvent.click(
    screen.getByRole('button', { name: 'Record pending administrator invitation' }),
  );
  await waitFor(() =>
    expect(ownerApi.inviteAdministrator).toHaveBeenCalledWith(operator.id, {
      username: 'synthetic.admin',
      permissions: ['client.users.manage_subaccounts'],
      terminalIds: [],
    }),
  );
  await screen.findByText(/Activation remains disabled/);
  expect(screen.queryByLabelText(/password/i)).toBeNull();
});
it('stops ambiguous merchant creation and never repeats it on focus', async () => {
  vi.stubGlobal(
    'confirm',
    vi.fn(() => true),
  );
  vi.mocked(ownerApi.createMerchant).mockRejectedValue(new OwnerApiError(503));
  render(<OwnerApp />);
  await openOperators();
  await userEvent.type(screen.getByLabelText('Immutable merchant code'), 'synthetic-merchant');
  await userEvent.type(screen.getByLabelText('Merchant display name'), 'Synthetic Merchant');
  await userEvent.click(screen.getByRole('button', { name: 'Create merchant' }));
  await screen.findByText(/Reconcile the current merchant or invitation records/);
  fireEvent.focus(window);
  expect(ownerApi.createMerchant).toHaveBeenCalledTimes(1);
  expect(screen.queryByLabelText('Immutable merchant code')).toBeNull();
});
it('does not duplicate an in-flight merchant creation or dispatch a cancelled confirmation', async () => {
  const confirm = vi.fn(() => false);
  vi.stubGlobal('confirm', confirm);
  let resolve!: (value: Awaited<ReturnType<typeof ownerApi.createMerchant>>) => void;
  vi.mocked(ownerApi.createMerchant).mockImplementation(
    () =>
      new Promise((r) => {
        resolve = r;
      }),
  );
  render(<OwnerApp />);
  await openOperators();
  const code = screen.getByLabelText('Immutable merchant code');
  await userEvent.type(code, 'synthetic-merchant');
  await userEvent.type(screen.getByLabelText('Merchant display name'), 'Synthetic Merchant');
  await userEvent.click(screen.getByRole('button', { name: 'Create merchant' }));
  expect(ownerApi.createMerchant).not.toHaveBeenCalled();
  confirm.mockReturnValue(true);
  const form = code.closest('form')!;
  fireEvent.submit(form);
  fireEvent.submit(form);
  expect(ownerApi.createMerchant).toHaveBeenCalledTimes(1);
  await act(async () => {
    resolve({ operator: { ...operator, version: 1 } });
    await Promise.resolve();
  });
});

it('retains an ambiguous merchant-creation outcome after its form is unmounted by navigation', async () => {
  vi.stubGlobal(
    'confirm',
    vi.fn(() => true),
  );
  let rejectWrite!: (reason: unknown) => void;
  vi.mocked(ownerApi.createMerchant).mockImplementation(
    () =>
      new Promise((_resolve, reject) => {
        rejectWrite = reject;
      }),
  );
  render(<OwnerApp />);
  await openOperators();
  await userEvent.type(screen.getByLabelText('Immutable merchant code'), 'unconfirmed_merchant');
  await userEvent.type(
    screen.getByLabelText('Merchant display name'),
    'Synthetic unconfirmed merchant',
  );
  await userEvent.click(screen.getByRole('button', { name: 'Create merchant' }));
  await waitFor(() => expect(ownerApi.createMerchant).toHaveBeenCalledTimes(1));
  await userEvent.click(screen.getByRole('link', { name: 'Audit activity' }));
  await screen.findByRole('heading', { name: 'Audit activity' });
  await act(async () => {
    rejectWrite(new OwnerApiError(503));
    await Promise.resolve();
  });
  await screen.findByText(/Change outcome not confirmed/);
  expect(screen.queryByRole('heading', { name: 'Audit activity' })).toBeNull();
  expect(ownerApi.createMerchant).toHaveBeenCalledTimes(1);
});
