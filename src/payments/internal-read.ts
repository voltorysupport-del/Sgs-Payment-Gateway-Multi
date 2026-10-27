import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request } from 'express';
import { z } from 'zod';

// Process-local capability, never configured, persisted, logged or sent to browsers.
// The supported hosting model is one Node process; another process fails closed.
const secret = randomBytes(32);
const prefix = 'x-vaultx-read-';
const names = ['operator', 'permission', 'expires', 'proof', 'scope'].map((name) => prefix + name);
export const terminalReadScopeSchema = z
  .object({
    userId: z.uuid(),
    membershipId: z.uuid(),
    sessionHash: z.string().regex(/^[a-f0-9]{64}$/),
    membershipVersion: z.number().int().positive(),
    operatorVersion: z.number().int().positive(),
    terminalIds: z.array(z.uuid()).min(1).max(100),
  })
  .strict();
export type TerminalReadScope = z.infer<typeof terminalReadScopeSchema>;
export interface ReadRestriction {
  operatorId: string;
  permission: 'read_only';
  terminalScope?: TerminalReadScope;
}
export class InvalidReadRestriction extends Error {
  constructor() {
    super('Internal read authorization refused.');
  }
}
export function hasReadRestriction(headers: Request['headers']): boolean {
  return Object.keys(headers).some((name) => name.toLowerCase().startsWith(prefix));
}
function proof(
  path: string,
  apiKey: string,
  operator: string,
  expires: string,
  scope = '',
): string {
  return createHmac('sha256', secret)
    .update(
      JSON.stringify([
        'GET',
        path,
        createHash('sha256').update(apiKey).digest('hex'),
        operator,
        'read_only',
        expires,
        scope,
      ]),
    )
    .digest('hex');
}
export function signReadRestriction(
  path: string,
  apiKey: string,
  operatorId: string,
  scope?: TerminalReadScope,
): Record<string, string> {
  const operator = z.uuid().parse(operatorId).toLowerCase();
  const expires = String(Date.now() + 10_000);
  const encodedScope = scope
    ? Buffer.from(JSON.stringify(terminalReadScopeSchema.parse(scope))).toString('base64url')
    : '';
  return {
    [names[0]!]: operator,
    [names[1]!]: 'read_only',
    [names[2]!]: expires,
    [names[3]!]: proof(path, apiKey, operator, expires, encodedScope),
    ...(encodedScope ? { [names[4]!]: encodedScope } : {}),
  };
}
export function readRestriction(req: Request, apiKey: string): ReadRestriction | undefined {
  if (!hasReadRestriction(req.headers)) return undefined;
  const values = names.slice(0, 4).map((name) => req.headers[name]);
  const encodedScope = req.headers[names[4]!];
  if (
    encodedScope !== undefined &&
    (typeof encodedScope !== 'string' ||
      encodedScope.length > 10000 ||
      !/^[A-Za-z0-9_-]+$/.test(encodedScope))
  )
    throw new InvalidReadRestriction();
  const [operator, permission, expires, signature] = values;
  if (
    req.method !== 'GET' ||
    !apiKey ||
    values.some((value) => typeof value !== 'string') ||
    Object.keys(req.headers).some((name) => name.startsWith(prefix) && !names.includes(name)) ||
    typeof operator !== 'string' ||
    !z.uuid().safeParse(operator).success ||
    permission !== 'read_only' ||
    typeof expires !== 'string' ||
    !/^[0-9]{13}$/.test(expires) ||
    Number(expires) < Date.now() ||
    Number(expires) > Date.now() + 10_000 ||
    typeof signature !== 'string' ||
    !/^[a-f0-9]{64}$/.test(signature) ||
    !timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(proof(req.originalUrl, apiKey, operator, expires, encodedScope ?? ''), 'hex'),
    )
  ) {
    throw new InvalidReadRestriction();
  }
  try {
    const terminalScope = encodedScope
      ? terminalReadScopeSchema.parse(
          JSON.parse(Buffer.from(encodedScope, 'base64url').toString('utf8')),
        )
      : undefined;
    return {
      operatorId: operator,
      permission: 'read_only',
      ...(terminalScope ? { terminalScope } : {}),
    };
  } catch {
    throw new InvalidReadRestriction();
  }
}
