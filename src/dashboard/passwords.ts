import { randomBytes } from 'node:crypto';
import { argon2id, hash, verify } from 'argon2';

// OWASP baseline, bounded parallel work; benchmark before broader exposure.
const parameters = { type: argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };
export function hashDashboardPassword(password: string): Promise<string> {
  if (password.length < 15 || password.length > 128) throw new Error('Invalid password length.');
  return hash(password, parameters);
}
// One startup-generated verifier, never a usable account or logged credential.
let dummy: Promise<string> | undefined;
export function dummyPasswordHash(): Promise<string> {
  return (dummy ??= hash(randomBytes(32).toString('hex'), parameters));
}
export async function verifyDashboardPassword(encoded: string, password: string): Promise<boolean> {
  if (!encoded.startsWith('$argon2id$')) return false;
  try {
    return await verify(encoded, password);
  } catch {
    return false;
  }
}
