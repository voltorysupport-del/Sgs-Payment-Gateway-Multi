import { z } from 'zod';
const uuid = z.uuid();
const version = z.number().int().positive();
const permission = z.enum([
  'platform.clients.read',
  'platform.clients.manage',
  'platform.audit.read',
  'platform.clients.bootstrap_admin',
]);
export const ownerIdentitySchema = z.object({
  owner: z.object({ id: uuid, username: z.string().min(1).max(80) }),
  permissions: z.array(permission).max(4),
});
export type OwnerIdentity = z.infer<typeof ownerIdentitySchema>;
export const operatorSchema = z.object({
  id: uuid,
  name: z.string().min(1).max(120),
  code: z.string().max(80),
  status: z.enum(['active', 'suspended']),
  version,
});
export type ManagedOperator = z.infer<typeof operatorSchema>;
const pagination = z.object({
  limit: z.literal(20),
  offset: z.number().int().min(0).max(10000),
  hasMore: z.boolean(),
});
export const operatorsSchema = z.object({ operators: z.array(operatorSchema).max(20), pagination });
const grantSchema = z.object({
  id: uuid,
  permission: z.enum([
    'client.payments.read',
    'client.status.read',
    'client.users.read',
    'client.users.manage_subaccounts',
    'client.permissions.delegate',
    'client.audit.read',
    'client.terminals.read',
  ]),
  revokedAt: z.iso.datetime().nullable(),
});
export const membershipsSchema = z.object({
  operatorId: uuid,
  members: z
    .array(
      z.object({
        id: uuid,
        status: z.enum(['active', 'disabled']),
        role: z.literal('viewer'),
        authorizationVersion: version,
        grants: z.array(grantSchema).max(100),
      }),
    )
    .max(20),
  pagination,
});
export const auditSchema = z.object({
  events: z
    .array(
      z.object({
        id: uuid,
        actorId: uuid,
        action: z.string().min(1).max(80),
        operatorId: uuid.nullable(),
        occurredAt: z.iso.datetime(),
      }),
    )
    .max(20),
  pagination,
});
const operatorResult = z.object({ operator: operatorSchema });
export const merchantPermissions = [
  'client.payments.read',
  'client.status.read',
  'client.users.read',
  'client.users.manage_subaccounts',
  'client.permissions.delegate',
  'client.audit.read',
  'client.terminals.read',
] as const;
export type MerchantPermission = (typeof merchantPermissions)[number];
const invitationResult = z.object({
  invitationId: uuid,
  expiresAt: z.iso.datetime(),
  status: z.literal('pending'),
  activationEnabled: z.literal(false),
});
export class OwnerApiError extends Error {
  constructor(public status: number) {
    super(
      status === 409
        ? 'This record changed. Reload it before making another change.'
        : status === 403
          ? 'This owner action is not permitted or requires fresh verification.'
          : status === 401
            ? 'Owner authentication is required.'
            : 'The owner request could not be completed.',
    );
  }
}
async function read<T>(
  path: string,
  schema: z.ZodType<T>,
  signal?: AbortSignal,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch('/owner-api' + path, {
    ...init,
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    signal: signal
      ? AbortSignal.any([signal, AbortSignal.timeout(10000)])
      : AbortSignal.timeout(10000),
  }).catch(() => {
    throw new OwnerApiError(503);
  });
  if (!response.ok) throw new OwnerApiError(response.status);
  if (response.status === 204) return schema.parse(undefined);
  const raw: unknown = await response.json().catch(() => {
    throw new OwnerApiError(502);
  });
  const parsed = schema.safeParse(raw);
  if (!parsed.success) throw new OwnerApiError(502);
  return parsed.data;
}
async function write<T>(path: string, schema: z.ZodType<T>, method: string, body?: unknown) {
  const { csrfToken } = await read(
    '/auth/csrf',
    z.object({ csrfToken: z.string().regex(/^[a-f0-9]{64}$/) }),
  );
  return read(path, schema, undefined, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}
function page(offset: number) {
  if (!Number.isInteger(offset) || offset < 0 || offset > 10000 || offset % 20 !== 0)
    throw new OwnerApiError(400);
  return '?limit=20&offset=' + offset;
}
function id(value: string) {
  if (!uuid.safeParse(value).success) throw new OwnerApiError(404);
  return value;
}
export const ownerApi = {
  me: (signal?: AbortSignal) => read('/auth/me', ownerIdentitySchema, signal),
  logout: () => write('/auth/logout', z.unknown(), 'POST', {}),
  operators: async (offset: number, signal?: AbortSignal) => {
    const data = await read('/clients' + page(offset), operatorsSchema, signal);
    if (data.pagination.offset !== offset) throw new OwnerApiError(502);
    return data;
  },
  operator: async (target: string, signal?: AbortSignal) => {
    const data = await read('/clients/' + id(target), operatorResult, signal);
    if (data.operator.id !== target) throw new OwnerApiError(502);
    return data.operator;
  },
  memberships: async (target: string, offset: number, signal?: AbortSignal) => {
    const data = await read(
      '/clients/' + id(target) + '/members' + page(offset),
      membershipsSchema,
      signal,
    );
    if (data.pagination.offset !== offset || data.operatorId !== target)
      throw new OwnerApiError(502);
    return data;
  },
  createMerchant: (body: { code: string; name: string }) =>
    write('/clients', operatorResult, 'POST', body),
  inviteAdministrator: (
    target: string,
    body: { username: string; permissions: MerchantPermission[]; terminalIds: string[] },
  ) =>
    write('/clients/' + id(target) + '/administrator-invitations', invitationResult, 'POST', body),
  updateOperator: (target: string, body: { name: string; expectedVersion: number }) =>
    write('/clients/' + id(target), operatorResult, 'PATCH', body),
  setStatus: (target: string, body: { status: 'active' | 'suspended'; expectedVersion: number }) =>
    write('/clients/' + id(target), operatorResult, 'PATCH', body),
  withdraw: (
    target: string,
    permission: 'client.payments.read' | 'client.status.read',
    expectedVersion: number,
  ) =>
    write(
      '/clients/' + id(target) + '/entitlements/' + encodeURIComponent(permission) + '/withdraw',
      z.unknown(),
      'POST',
      { expectedVersion },
    ),
  audit: async (offset: number, signal?: AbortSignal) => {
    const data = await read('/audit' + page(offset), auditSchema, signal);
    if (data.pagination.offset !== offset) throw new OwnerApiError(502);
    return data;
  },
};
