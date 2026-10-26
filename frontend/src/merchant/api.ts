import { z } from 'zod';
const uuid = z.uuid();
export const permissions = [
  'client.users.read',
  'client.users.manage_subaccounts',
  'client.permissions.delegate',
  'client.audit.read',
  'client.terminals.read',
  'client.payments.read',
  'client.status.read',
] as const;
export const identitySchema = z.object({
  user: z.object({ id: uuid, username: z.string().max(80) }),
  operator: z.object({ id: uuid }),
  membership: z.object({ id: uuid, version: z.number().int().positive() }),
  permissions: z.array(z.enum(permissions)).max(7),
});
export type MerchantIdentity = z.infer<typeof identitySchema>;
const pagination = z.object({
  limit: z.literal(20),
  offset: z.number().int().min(0).max(10000),
  hasMore: z.boolean(),
});
export const memberSchema = z.object({
  id: uuid,
  status: z.enum(['active', 'disabled']),
  username: z.string().max(80),
  kind: z.enum(['merchant_admin', 'submerchant']).nullable(),
  version: z.number().int().positive(),
  sponsorMembershipId: uuid.nullable(),
});
export type MerchantMember = z.infer<typeof memberSchema>;
const members = z.object({ members: z.array(memberSchema).max(20), pagination });
const terminals = z.object({
  terminals: z
    .array(
      z.object({
        id: uuid,
        code: z.string().max(64),
        name: z.string().max(120),
        status: z.enum(['active', 'suspended']),
      }),
    )
    .max(20),
  pagination,
});
const audit = z.object({
  events: z
    .array(
      z.object({
        id: uuid,
        action: z.string().max(80),
        occurred_at: z.iso.datetime(),
        target_membership_id: uuid.nullable(),
        target_version: z.number().int().positive().nullable(),
      }),
    )
    .max(20),
  pagination,
});
const invitation = z.object({
  invitationId: uuid,
  expiresAt: z.iso.datetime(),
  status: z.literal('pending'),
  activationEnabled: z.literal(false),
});
export class MerchantApiError extends Error {
  constructor(public readonly status: number) {
    super(
      status === 409
        ? 'This record changed. Reload before making another change.'
        : status === 401
          ? 'Your session is no longer valid.'
          : status === 403
            ? 'This action is not permitted.'
            : 'The merchant request could not be confirmed.',
    );
  }
}
async function read<T>(
  path: string,
  schema: z.ZodType<T>,
  signal?: AbortSignal,
  init?: RequestInit,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      signal: signal
        ? AbortSignal.any([signal, AbortSignal.timeout(10000)])
        : AbortSignal.timeout(10000),
    });
  } catch {
    throw new MerchantApiError(503);
  }
  if (!response.ok) throw new MerchantApiError(response.status);
  const body: unknown = await response.json().catch(() => {
    throw new MerchantApiError(502);
  });
  const parsed = schema.safeParse(body);
  if (!parsed.success) throw new MerchantApiError(502);
  return parsed.data;
}
function page(offset: number) {
  if (!Number.isInteger(offset) || offset < 0 || offset > 10000 || offset % 20)
    throw new MerchantApiError(400);
  return '?limit=20&offset=' + offset;
}
function id(value: string) {
  if (!uuid.safeParse(value).success) throw new MerchantApiError(400);
  return value;
}
const me = (signal?: AbortSignal) => read('/merchant-api/me', identitySchema, signal);
async function write<T>(
  identity: MerchantIdentity,
  path: string,
  schema: z.ZodType<T>,
  body: unknown,
): Promise<T> {
  // Reuse the EXISTING client realm lock. A different tab cannot race CSRF,
  // logout or account switching while this authorized mutation is in flight.
  if (!navigator.locks) throw new MerchantApiError(503);
  return navigator.locks.request('vaultx-dashboard-auth', { mode: 'exclusive' }, async () => {
    const current = await me();
    if (
      current.user.id !== identity.user.id ||
      current.operator.id !== identity.operator.id ||
      current.membership.id !== identity.membership.id ||
      current.membership.version !== identity.membership.version
    )
      throw new MerchantApiError(401);
    const { csrfToken } = await read(
      '/dashboard-api/auth/csrf',
      z.object({ csrfToken: z.string().regex(/^[a-f0-9]{64}$/) }),
    );
    return read('/merchant-api' + path, schema, undefined, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify(body),
    });
  });
}
export const merchantApi = {
  me,
  members: async (offset: number, signal?: AbortSignal) => {
    const data = await read('/merchant-api/members' + page(offset), members, signal);
    if (data.pagination.offset !== offset) throw new MerchantApiError(502);
    return data;
  },
  terminals: async (offset: number, signal?: AbortSignal) => {
    const data = await read('/merchant-api/terminals' + page(offset), terminals, signal);
    if (data.pagination.offset !== offset) throw new MerchantApiError(502);
    return data;
  },
  audit: async (offset: number, signal?: AbortSignal) => {
    const data = await read('/merchant-api/audit' + page(offset), audit, signal);
    if (data.pagination.offset !== offset) throw new MerchantApiError(502);
    return data;
  },
  invite: (
    identity: MerchantIdentity,
    body: {
      username: string;
      permissions: ('client.payments.read' | 'client.status.read')[];
      terminalIds: string[];
    },
  ) => write(identity, '/invitations', invitation, body),
  disable: (identity: MerchantIdentity, member: MerchantMember) =>
    write(
      identity,
      '/members/' + id(member.id) + '/disable',
      z.object({ revoked: z.literal(true), version: z.number().int().positive() }),
      { expectedVersion: member.version },
    ),
  withdraw: (
    identity: MerchantIdentity,
    member: MerchantMember,
    permission: 'client.payments.read' | 'client.status.read',
  ) =>
    write(
      identity,
      '/members/' + id(member.id) + '/grants/' + permission + '/withdraw',
      z.object({ revoked: z.literal(true), version: z.number().int().positive() }),
      { expectedVersion: member.version },
    ),
};
