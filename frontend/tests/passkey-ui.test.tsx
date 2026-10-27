import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import axe from 'axe-core';
import { InvitationAcceptance, PasskeyGate } from '../src/passkey-ui';
import { DashboardAuth } from '../src/auth';
import { api, ApiError, type Identity } from '../src/api';
import { PasskeyError } from '../src/passkeys';
const identity: Identity = {
  user: { id: '11111111-1111-4111-8111-111111111111', username: 'synthetic-admin' },
  operator: { id: '22222222-2222-4222-8222-222222222222' },
  role: 'viewer',
  authentication: {
    passkeyRequired: true,
    passkeyVerified: false,
    passkeyFresh: false,
    passkeysEnabled: true,
  },
};
const stops: (() => void)[] = [];
beforeEach(() => {
  vi.stubGlobal('isSecureContext', true);
  vi.stubGlobal('PublicKeyCredential', class {});
  vi.stubGlobal('BroadcastChannel', undefined);
  Object.defineProperty(navigator, 'credentials', {
    configurable: true,
    value: { create: vi.fn(), get: vi.fn() },
  });
  Object.defineProperty(navigator, 'locks', {
    configurable: true,
    value: { request: (_n: string, _o: unknown, work: () => Promise<unknown>) => work() },
  });
});
afterEach(() => {
  stops.splice(0).forEach((stop) => stop());
  cleanup();
  vi.unstubAllGlobals();
});
it('has labelled accessible enrollment controls and clears private fields before submission', async () => {
  const controller = new DashboardAuth(),
    submit = vi.spyOn(controller, 'enroll').mockResolvedValue(undefined);
  const { container } = render(
    <InvitationAcceptance controller={controller} onClose={() => undefined} />,
  );
  fireEvent.change(screen.getByLabelText('Private invitation value'), {
    target: { value: 'a'.repeat(64) },
  });
  fireEvent.change(screen.getByLabelText('Create password'), {
    target: { value: 'Synthetic enrollment password!' },
  });
  fireEvent.change(screen.getByLabelText('Confirm password'), {
    target: { value: 'Synthetic enrollment password!' },
  });
  expect(screen.getByRole('form', { name: 'Invitation acceptance' }).getAttribute('method')).toBe(
    'post',
  );
  expect(screen.getByRole('form', { name: 'Invitation acceptance' }).getAttribute('action')).toBe(
    '/dashboard-api/auth/passkeys/enrollment/options',
  );
  fireEvent.submit(screen.getByRole('form', { name: 'Invitation acceptance' }));
  expect(submit).toHaveBeenCalledOnce();
  expect(screen.getByLabelText<HTMLInputElement>('Private invitation value').value).toBe('');
  expect(screen.getByLabelText<HTMLInputElement>('Create password').value).toBe('');
  expect(
    (await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })).violations,
  ).toEqual([]);
});
it('clears fields on page hide and disables unsupported enrollment', () => {
  vi.stubGlobal('PublicKeyCredential', undefined);
  render(<InvitationAcceptance controller={new DashboardAuth()} onClose={() => undefined} />);
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Enroll passkey' }).disabled).toBe(
    true,
  );
  fireEvent.change(screen.getByLabelText('Create password'), {
    target: { value: 'Synthetic only' },
  });
  window.dispatchEvent(new Event('pagehide'));
  expect(screen.getByLabelText<HTMLInputElement>('Create password').value).toBe('');
});
it('never treats a successful browser helper as privileged proof without a fresh server identity', async () => {
  const me = vi.fn().mockResolvedValue(identity),
    ceremonies = { enroll: vi.fn(), authenticate: vi.fn().mockResolvedValue(undefined) };
  const controller = new DashboardAuth({ ...api, me }, ceremonies);
  stops.push(controller.start());
  await vi.waitFor(() => expect(controller.snapshot().phase).toBe('passkey-required'));
  await controller.verifyPasskey();
  expect(controller.snapshot().phase).toBe('blocked');
  expect(ceremonies.authenticate).toHaveBeenCalledOnce();
});
it('serializes duplicate prompt clicks and requires a new login after cancellation', async () => {
  let reject!: (error: unknown) => void;
  const ceremonies = {
    enroll: vi.fn(),
    authenticate: vi.fn(
      () =>
        new Promise<void>((_r, r) => {
          reject = r;
        }),
    ),
  };
  const controller = new DashboardAuth(
    { ...api, me: vi.fn().mockResolvedValue(identity) },
    ceremonies,
  );
  stops.push(controller.start());
  await vi.waitFor(() => expect(controller.snapshot().phase).toBe('passkey-required'));
  const first = controller.verifyPasskey(),
    second = controller.verifyPasskey();
  await vi.waitFor(() => expect(ceremonies.authenticate).toHaveBeenCalledOnce());
  reject(new PasskeyError('cancelled'));
  await Promise.all([first, second]);
  expect(controller.snapshot().needsRestart).toBe(true);
  await controller.verifyPasskey();
  expect(ceremonies.authenticate).toHaveBeenCalledOnce();
});
it('does not unlock or resubmit ambiguous enrollment after explicit anonymous session checks', async () => {
  const ceremonies = {
    enroll: vi.fn().mockRejectedValue(new PasskeyError('unconfirmed')),
    authenticate: vi.fn(),
  };
  const controller = new DashboardAuth(
    { ...api, me: vi.fn().mockRejectedValue(new ApiError(401)) },
    ceremonies,
  );
  stops.push(controller.start());
  await vi.waitFor(() => expect(controller.snapshot().phase).toBe('anonymous'));
  await controller.enroll('a'.repeat(64), 'Synthetic enrollment password!');
  expect(controller.snapshot().phase).toBe('blocked');
  await controller.check(true);
  expect(controller.snapshot().phase).toBe('blocked');
  await controller.enroll('a'.repeat(64), 'Synthetic enrollment password!');
  expect(ceremonies.enroll).toHaveBeenCalledOnce();
});
it('focuses the verification heading and explains password-only authority without exposing protected details', async () => {
  const { container } = render(
    <PasskeyGate
      controller={new DashboardAuth()}
      state={{ phase: 'passkey-required', identity }}
    />,
  );
  expect(document.activeElement).toBe(
    screen.getByRole('heading', { name: 'Passkey verification required' }),
  );
  expect(screen.getByText(/Privileged access remains closed/)).toBeTruthy();
  expect(
    (await axe.run(container, { rules: { 'color-contrast': { enabled: false } } })).violations,
  ).toEqual([]);
});
it('rejects an account switch while a queued verification starts before invoking any authenticator', async () => {
  const other = {
    ...identity,
    user: { ...identity.user, id: '33333333-3333-4333-8333-333333333333' },
  };
  const me = vi.fn().mockResolvedValueOnce(identity).mockResolvedValue(other),
    ceremonies = { enroll: vi.fn(), authenticate: vi.fn() };
  const controller = new DashboardAuth({ ...api, me }, ceremonies);
  stops.push(controller.start());
  await vi.waitFor(() => expect(controller.snapshot().phase).toBe('passkey-required'));
  await controller.verifyPasskey();
  expect(controller.snapshot().phase).toBe('blocked');
  expect(ceremonies.authenticate).not.toHaveBeenCalled();
});
it('uses server freshness to keep merchant administration closed for stale assurance', async () => {
  const stale = {
    ...identity,
    authentication: { ...identity.authentication, passkeyVerified: true, passkeyFresh: false },
  };
  const controller = new DashboardAuth(
    { ...api, me: vi.fn().mockResolvedValue(stale) },
    { enroll: vi.fn(), authenticate: vi.fn() },
    true,
  );
  stops.push(controller.start());
  await vi.waitFor(() => expect(controller.snapshot().phase).toBe('passkey-required'));
});
it('a broadcast cannot clear local cancellation, and joining an existing session is not a fresh password login', async () => {
  const channels: { onmessage: ((event: MessageEvent<unknown>) => void) | null }[] = [];
  vi.stubGlobal(
    'BroadcastChannel',
    class {
      onmessage: ((event: MessageEvent<unknown>) => void) | null = null;
      constructor() {
        channels.push(this);
      }
      postMessage() {}
      close() {}
    },
  );
  const me = vi.fn().mockResolvedValue(identity),
    passwordLogin = vi.fn().mockResolvedValue(undefined);
  const ceremonies = {
    enroll: vi.fn(),
    authenticate: vi.fn().mockRejectedValue(new PasskeyError('cancelled')),
  };
  const controller = new DashboardAuth({ ...api, me, login: passwordLogin }, ceremonies);
  stops.push(controller.start());
  await vi.waitFor(() => expect(controller.snapshot().phase).toBe('passkey-required'));
  await controller.verifyPasskey();
  expect(controller.snapshot().needsRestart).toBe(true);
  channels[0]!.onmessage?.({ data: 'auth-changed' } as MessageEvent<unknown>);
  await vi.waitFor(() => expect(controller.snapshot().phase).toBe('passkey-required'));
  expect(controller.snapshot().needsRestart).toBe(true);
  // A stale anonymous UI can discover the same already-authenticated cookie.
  // It must not pretend a new password login occurred.
  controller.expire(controller.version());
  await controller.login('synthetic-admin', 'Synthetic password only!');
  expect(passwordLogin).not.toHaveBeenCalled();
  expect(controller.snapshot().needsRestart).toBe(true);
  // Only an actual password login AND its successful server identity read reset.
  controller.expire(controller.version());
  me.mockRejectedValueOnce(new ApiError(401));
  await controller.login('synthetic-admin', 'Synthetic password only!');
  expect(passwordLogin).toHaveBeenCalledOnce();
  expect(controller.snapshot().needsRestart).toBe(false);
});
