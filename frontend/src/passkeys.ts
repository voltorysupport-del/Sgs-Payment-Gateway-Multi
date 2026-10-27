import { z } from 'zod';
import { api, ApiError, request } from './api';

export class PasskeyError extends Error {
  constructor(
    readonly kind: 'unsupported' | 'cancelled' | 'unconfirmed' | 'rejected' | 'unavailable',
  ) {
    super(
      kind === 'unsupported'
        ? 'Passkeys require a supported browser on a secure HTTPS connection.'
        : kind === 'cancelled'
          ? 'Passkey prompt cancelled or unavailable. Nothing will be submitted automatically.'
          : kind === 'unavailable'
            ? 'The ceremony could not start. Check your connection and start again; no verification was submitted.'
            : kind === 'unconfirmed'
              ? 'The outcome could not be confirmed. Do not repeat enrollment. Contact your administrator.'
              : 'The invitation or verification is unavailable. It may be expired, used or invalid. Contact your administrator.',
    );
  }
}
const encoded = z
  .string()
  .min(1)
  .max(1400)
  .regex(/^[A-Za-z0-9_-]+$/);
const challenge = encoded.max(256);
const creation = z.object({
  challenge,
  rp: z.object({ id: z.string().max(253), name: z.string().max(120) }),
  user: z.object({
    id: encoded.max(86),
    name: z.string().max(120),
    displayName: z.string().max(120),
  }),
  pubKeyCredParams: z
    .array(z.object({ type: z.literal('public-key'), alg: z.literal(-7) }))
    .min(1)
    .max(1),
  timeout: z.number().int().min(1).max(300000),
  attestation: z.literal('none'),
  authenticatorSelection: z.object({
    residentKey: z.literal('required'),
    userVerification: z.literal('required'),
  }),
});
const assertion = z.object({
  challenge,
  rpId: z.string().max(253),
  timeout: z.number().int().min(1).max(300000),
  userVerification: z.literal('required'),
  allowCredentials: z
    .array(z.object({ id: encoded, type: z.literal('public-key') }))
    .min(1)
    .max(10),
});
const csrfSchema = z.object({ csrfToken: z.string().regex(/^[a-f0-9]{64}$/) });
const csrf = () => request('/dashboard-api/auth/csrf', csrfSchema, undefined, undefined, true);
const post = <T>(path: string, schema: z.ZodType<T>, body: unknown, token: string) =>
  request(
    path,
    schema,
    undefined,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
      body: JSON.stringify(body),
    },
    true,
  );
const bytes = (value: string) =>
  Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.charCodeAt(0));
const encodedBytes = (value: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(value)))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
export function passkeysSupported() {
  return (
    window.isSecureContext &&
    typeof PublicKeyCredential !== 'undefined' &&
    typeof navigator.credentials?.create === 'function' &&
    typeof navigator.credentials?.get === 'function' &&
    typeof navigator.locks?.request === 'function'
  );
}
function check(signal: AbortSignal, rp?: string) {
  if (!passkeysSupported()) throw new PasskeyError('unsupported');
  if (signal.aborted) throw new PasskeyError('cancelled');
  if (rp !== undefined && rp !== location.hostname) throw new PasskeyError('rejected');
}
function localFailure(): never {
  throw new PasskeyError('cancelled');
}
function serverFailure(error: unknown, verification = false): never {
  if (error instanceof ApiError && [400, 401, 403, 404, 429].includes(error.status))
    throw new PasskeyError('rejected');
  throw new PasskeyError(verification ? 'unconfirmed' : 'unavailable');
}
export const passkeys = {
  enroll: async (invitationToken: string, password: string, signal: AbortSignal) => {
    check(signal);
    let options: z.infer<typeof creation>, csrfToken: string;
    try {
      // Called only after the shared controller verified anonymity under Web Lock.
      // Discard the old anonymous ceremony with existing CSRF-protected logout;
      // never replace an invitation or reuse a cancelled/expired challenge.
      await api.logout();
      csrfToken = (await csrf()).csrfToken;
      options = await post(
        '/dashboard-api/auth/passkeys/enrollment/options',
        creation,
        { invitationToken, password },
        csrfToken,
      );
    } catch (error) {
      serverFailure(error);
    } finally {
      invitationToken = '';
      password = '';
    }
    check(signal, options.rp.id);
    let credential: PublicKeyCredential;
    try {
      const result = await navigator.credentials.create({
        signal,
        publicKey: {
          ...options,
          challenge: bytes(options.challenge),
          user: { ...options.user, id: bytes(options.user.id) },
        },
      });
      if (!result || result.type !== 'public-key') localFailure();
      credential = result as PublicKeyCredential;
    } catch {
      localFailure();
    }
    check(signal);
    const response = credential.response as AuthenticatorAttestationResponse;
    try {
      await post(
        '/dashboard-api/auth/passkeys/enrollment/verify',
        z.object({ enrolled: z.literal(true), privilegedAccess: z.literal(false) }),
        {
          credential: {
            id: credential.id,
            rawId: encodedBytes(credential.rawId),
            type: 'public-key',
            clientExtensionResults: {},
            response: {
              clientDataJSON: encodedBytes(response.clientDataJSON),
              attestationObject: encodedBytes(response.attestationObject),
            },
          },
        },
        csrfToken,
      );
    } catch (error) {
      serverFailure(error, true);
    }
  },
  authenticate: async (signal: AbortSignal) => {
    check(signal);
    let options: z.infer<typeof assertion>, csrfToken: string;
    try {
      // Clear an earlier cancelled ceremony using logout only for anonymous
      // enrollment. Authenticated ceremonies cannot be silently reset; see below.
      csrfToken = (await csrf()).csrfToken;
      options = await post(
        '/dashboard-api/auth/passkeys/authentication/options',
        assertion,
        {},
        csrfToken,
      );
    } catch (error) {
      serverFailure(error);
    }
    check(signal, options.rpId);
    let credential: PublicKeyCredential;
    try {
      const result = await navigator.credentials.get({
        signal,
        publicKey: {
          ...options,
          challenge: bytes(options.challenge),
          allowCredentials: options.allowCredentials.map((c) => ({ ...c, id: bytes(c.id) })),
        },
      });
      if (!result || result.type !== 'public-key') localFailure();
      credential = result as PublicKeyCredential;
    } catch {
      localFailure();
    }
    check(signal);
    const response = credential.response as AuthenticatorAssertionResponse;
    try {
      await post(
        '/dashboard-api/auth/passkeys/authentication/verify',
        z.object({ authenticated: z.literal(true), csrfToken: csrfSchema.shape.csrfToken }),
        {
          credential: {
            id: credential.id,
            rawId: encodedBytes(credential.rawId),
            type: 'public-key',
            clientExtensionResults: {},
            response: {
              clientDataJSON: encodedBytes(response.clientDataJSON),
              authenticatorData: encodedBytes(response.authenticatorData),
              signature: encodedBytes(response.signature),
              ...(response.userHandle ? { userHandle: encodedBytes(response.userHandle) } : {}),
            },
          },
        },
        csrfToken,
      );
    } catch (error) {
      serverFailure(error, true);
    }
  },
};
