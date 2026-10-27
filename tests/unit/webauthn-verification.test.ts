import { expect, it } from 'vitest';
import { verifyRegistrationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { syntheticAuthenticator } from '../webauthn-authenticator.js';
const origin = 'https://dashboard.example.invalid',
  rpID = 'dashboard.example.invalid';
it('uses real WebAuthn ES256 verification with required UV and exact RP/origin', async () => {
  const key = syntheticAuthenticator(),
    challenge = 'synthetic-cryptographic-challenge';
  const result = await verifyRegistrationResponse({
    response: key.registration(challenge, origin),
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    requireUserVerification: true,
  });
  expect(result.verified).toBe(true);
  const credential = result.registrationInfo!.credential;
  const assertion = key.assertion(challenge, origin, 'synthetic-subject');
  expect(
    (
      await verifyAuthenticationResponse({
        response: assertion,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true,
        credential,
      })
    ).verified,
  ).toBe(true);
  for (const response of [
    key.assertion(challenge, 'https://wrong.invalid', 'synthetic-subject'),
    key.assertion(challenge, origin, 'synthetic-subject', 1, 'wrong.invalid'),
    key.assertion(challenge, origin, 'synthetic-subject', 1, rpID, false),
  ]) {
    await expect(
      verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true,
        credential,
      }),
    ).rejects.toThrow();
  }
});
