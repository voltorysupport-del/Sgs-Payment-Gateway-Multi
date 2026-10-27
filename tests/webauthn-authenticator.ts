import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
/** Real ES256 signatures/CBOR, synthetic authenticator only. Never mock verification. */
export function syntheticAuthenticator() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const id = randomBytes(32).toString('base64url');
  const key = isoCBOR.encode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, Buffer.from(jwk.x!, 'base64url')],
      [-3, Buffer.from(jwk.y!, 'base64url')],
    ]),
  );
  const hash = (v: string | Buffer) => createHash('sha256').update(v).digest();
  const client = (type: string, challenge: string, origin: string) =>
    Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  const auth = (rp: string, flags: number, count: number) => {
    const n = Buffer.alloc(4);
    n.writeUInt32BE(count);
    return Buffer.concat([hash(rp), Buffer.from([flags]), n]);
  };
  return {
    id,
    publicKey: Buffer.from(key),
    registration(
      challenge: string,
      origin: string,
      rp = new URL(origin).hostname,
      uv = true,
    ): RegistrationResponseJSON {
      const cred = Buffer.from(id, 'base64url'),
        len = Buffer.alloc(2);
      len.writeUInt16BE(cred.length);
      const data = Buffer.concat([auth(rp, uv ? 0x45 : 0x41, 0), Buffer.alloc(16), len, cred, key]);
      return {
        id,
        rawId: id,
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          clientDataJSON: client('webauthn.create', challenge, origin).toString('base64url'),
          attestationObject: Buffer.from(
            isoCBOR.encode(
              new Map<string, string | Map<string, string> | Uint8Array>([
                ['fmt', 'none'],
                ['attStmt', new Map()],
                ['authData', data],
              ]),
            ),
          ).toString('base64url'),
        },
      };
    },
    assertion(
      challenge: string,
      origin: string,
      user: string,
      count = 1,
      rp = new URL(origin).hostname,
      uv = true,
    ): AuthenticationResponseJSON {
      const data = auth(rp, uv ? 0x05 : 0x01, count),
        json = client('webauthn.get', challenge, origin);
      return {
        id,
        rawId: id,
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          clientDataJSON: json.toString('base64url'),
          authenticatorData: data.toString('base64url'),
          signature: sign('sha256', Buffer.concat([data, hash(json)]), pair.privateKey).toString(
            'base64url',
          ),
          userHandle: Buffer.from(user).toString('base64url'),
        },
      };
    },
  };
}
