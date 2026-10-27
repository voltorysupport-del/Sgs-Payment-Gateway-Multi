import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { passkeys, PasskeyError } from '../src/passkeys';
import { identitySchema } from '../src/api';
const csrf = 'c'.repeat(64),
  challenge = 'c3ludGhldGljLWNoYWxsZW5nZQ',
  id = 'c3ludGhldGljLWNyZWRlbnRpYWw';
const registration = {
  challenge,
  rp: { id: location.hostname, name: 'VaultX Pay' },
  user: { id: 'c3ludGhldGljLXVzZXI', name: 'Invited user', displayName: '' },
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  timeout: 300000,
  attestation: 'none',
  authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
};
const authentication = {
  challenge,
  rpId: location.hostname,
  timeout: 300000,
  userVerification: 'required',
  allowCredentials: [{ type: 'public-key', id }],
};
const buffer = () => new Uint8Array([1, 2, 3]).buffer;
let create: ReturnType<typeof vi.fn>, get: ReturnType<typeof vi.fn>;
beforeEach(() => {
  Object.defineProperty(navigator, 'locks', { configurable: true, value: { request: vi.fn() } });
  vi.stubGlobal('isSecureContext', true);
  vi.stubGlobal('PublicKeyCredential', class {});
  create = vi.fn().mockResolvedValue({
    type: 'public-key',
    id,
    rawId: buffer(),
    response: { clientDataJSON: buffer(), attestationObject: buffer() },
  });
  get = vi.fn().mockResolvedValue({
    type: 'public-key',
    id,
    rawId: buffer(),
    response: {
      clientDataJSON: buffer(),
      authenticatorData: buffer(),
      signature: buffer(),
      userHandle: null,
    },
  });
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create, get } });
});
afterEach(() => vi.unstubAllGlobals());
function fetcher(
  options: unknown,
  verify: () => Promise<Response> = () =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          enrolled: true,
          privilegedAccess: false,
          authenticated: true,
          csrfToken: csrf,
        }),
      ),
    ),
) {
  return vi.fn(async (path: string) =>
    path.endsWith('/csrf')
      ? new Response(JSON.stringify({ csrfToken: csrf }))
      : path.endsWith('/logout')
        ? new Response(null, { status: 204 })
        : path.endsWith('/options')
          ? new Response(JSON.stringify(options))
          : verify(),
  );
}
it('uses only same-origin fixed POST paths/CSRF, converts buffers and never stores ceremony values', async () => {
  const fetch = fetcher(registration);
  vi.stubGlobal('fetch', fetch);
  await passkeys.enroll(
    'a'.repeat(64),
    'Synthetic enrollment password!',
    new AbortController().signal,
  );
  const call = create.mock.calls[0]![0] as CredentialCreationOptions;
  expect(call.publicKey?.challenge).toBeInstanceOf(Uint8Array);
  expect(call.publicKey?.authenticatorSelection).toEqual({
    residentKey: 'required',
    userVerification: 'required',
  });
  for (const [, init] of fetch.mock.calls as unknown as [string, RequestInit][])
    expect(init).toMatchObject({
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
    });
  expect(localStorage.length).toBe(0);
  expect(sessionStorage.length).toBe(0);
  expect(location.search + location.hash).not.toContain(challenge);
});
it.each(['rp', 'uv', 'attestation'] as const)(
  'refuses tampered %s options before the native prompt',
  async (mode) => {
    vi.stubGlobal(
      'fetch',
      fetcher({
        ...registration,
        ...(mode === 'rp'
          ? { rp: { id: 'foreign.invalid', name: 'Wrong' } }
          : mode === 'uv'
            ? { authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' } }
            : { attestation: 'enterprise' }),
      }),
    );
    await expect(
      passkeys.enroll(
        'a'.repeat(64),
        'Synthetic enrollment password!',
        new AbortController().signal,
      ),
    ).rejects.toBeInstanceOf(PasskeyError);
    expect(create).not.toHaveBeenCalled();
  },
);
it('does not send authentication verification after cancellation or abort', async () => {
  const fetch = fetcher(authentication);
  vi.stubGlobal('fetch', fetch);
  get.mockRejectedValue(new DOMException('PRIVATE browser details', 'NotAllowedError'));
  await expect(passkeys.authenticate(new AbortController().signal)).rejects.toMatchObject({
    kind: 'cancelled',
  });
  expect(fetch.mock.calls.some(([p]) => p.endsWith('/verify'))).toBe(false);
  const controller = new AbortController();
  controller.abort();
  await expect(passkeys.authenticate(controller.signal)).rejects.toMatchObject({
    kind: 'cancelled',
  });
});
it('blocks ambiguous verification and never retries a submitted request', async () => {
  const fetch = fetcher(registration, () => Promise.reject(new Error('PRIVATE transport details')));
  vi.stubGlobal('fetch', fetch);
  await expect(
    passkeys.enroll('a'.repeat(64), 'Synthetic enrollment password!', new AbortController().signal),
  ).rejects.toMatchObject({ kind: 'unconfirmed' });
  expect(fetch.mock.calls.filter(([p]) => p.endsWith('/verify'))).toHaveLength(1);
});
it('fails closed for unsupported browsers and identity responses without authoritative assurance metadata', async () => {
  vi.stubGlobal('PublicKeyCredential', undefined);
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  await expect(passkeys.authenticate(new AbortController().signal)).rejects.toMatchObject({
    kind: 'unsupported',
  });
  expect(fetch).not.toHaveBeenCalled();
  expect(
    identitySchema.safeParse({
      user: { id: '11111111-1111-4111-8111-111111111111', username: 'viewer' },
      operator: { id: '22222222-2222-4222-8222-222222222222' },
      role: 'viewer',
    }).success,
  ).toBe(false);
});
