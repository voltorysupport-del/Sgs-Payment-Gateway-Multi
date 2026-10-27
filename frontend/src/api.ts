import { z } from 'zod';
export const identitySchema = z.object({
  user: z.object({ id: z.uuid(), username: z.string().max(80) }),
  operator: z.object({ id: z.uuid() }),
  role: z.literal('viewer'),
  readAccess: z
    .object({ scope: z.enum(['operator', 'terminal']), payments: z.boolean(), status: z.boolean() })
    .optional(),
  authentication: z.object({
    passkeyRequired: z.boolean(),
    passkeyVerified: z.boolean(),
    passkeyFresh: z.boolean(),
    passkeysEnabled: z.boolean(),
  }),
});
export type Identity = z.infer<typeof identitySchema>;
export const paymentSchema = z.object({
  id: z.uuid(),
  amountMinor: z.number().int().positive().max(100_000_000),
  currency: z.string().regex(/^[A-Z]{3}$/),
  status: z.enum(['pending', 'succeeded', 'failed', 'cancelled']),
  provider: z.literal('simulator'),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
export type Payment = z.infer<typeof paymentSchema>;
export const historySchema = z.object({
  payments: z.array(paymentSchema).max(100),
  pagination: z.object({
    limit: z.number().int().min(1).max(100),
    offset: z.number().int().min(0).max(10000),
    hasMore: z.boolean(),
  }),
});
export const statusSchema = z.object({
  status: z.literal('ok'),
  gateway: z.literal('ok'),
  database: z.literal('reachable'),
  provider: z.literal('simulator'),
  realPaymentsEnabled: z.literal(false),
});
const csrfSchema = z.object({ csrfToken: z.string().regex(/^[a-f0-9]{64}$/) });
export class ApiError extends Error {
  constructor(public status: number) {
    super(
      status === 401
        ? 'Your session has expired. Please sign in again.'
        : status === 403
          ? 'Payment access is not available for this account. Contact your administrator.'
          : status === 429
            ? 'Too many attempts. Please wait before trying again.'
            : status === 404
              ? 'Payment not found.'
              : 'This request could not be completed. Please try again.',
    );
  }
}
// Fixed same-origin paths only. No caller-supplied URL, operator, or credential headers.
export async function request<T>(
  path: string,
  schema: z.ZodType<T>,
  signal?: AbortSignal,
  init?: RequestInit,
  cookieSequence = false,
): Promise<T> {
  const controller = new AbortController();
  const timeout = cookieSequence ? undefined : setTimeout(() => controller.abort(), 12000);
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) controller.abort();
  try {
    const response = await fetch(path, {
      ...init,
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      signal: controller.signal,
    });
    if (!response.ok) throw new ApiError(response.status);
    if (response.status === 204) return schema.parse(undefined);
    const value: unknown = await response.json();
    const parsed = schema.safeParse(value);
    if (!parsed.success) throw new ApiError(502);
    return parsed.data;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(503);
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener('abort', abort);
  }
}
export const api = {
  me: (signal?: AbortSignal) => request('/dashboard-api/auth/me', identitySchema, signal),
  login: async (username: string, password: string) => {
    const { csrfToken } = await request(
      '/dashboard-api/auth/csrf',
      csrfSchema,
      undefined,
      undefined,
      true,
    );
    await request(
      '/dashboard-api/auth/login',
      z.object({ authenticated: z.literal(true), csrfToken: csrfSchema.shape.csrfToken }),
      undefined,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ username, password }),
      },
      true,
    );
  },
  logout: async () => {
    const { csrfToken } = await request(
      '/dashboard-api/auth/csrf',
      csrfSchema,
      undefined,
      undefined,
      true,
    );
    await request(
      '/dashboard-api/auth/logout',
      z.unknown(),
      undefined,
      {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrfToken },
      },
      true,
    );
  },
  history: async (offset: number, status: string, currency: string, signal?: AbortSignal) => {
    const query = new URLSearchParams({ limit: '10', offset: String(offset) });
    if (status) query.set('status', status);
    if (currency) query.set('currency', currency);
    const value = await request(
      '/dashboard-api/payments?' + query.toString(),
      historySchema,
      signal,
    );
    if (
      value.pagination.limit !== 10 ||
      value.pagination.offset !== offset ||
      value.payments.length > 10
    )
      throw new ApiError(502);
    return value;
  },
  detail: async (id: string, signal?: AbortSignal) => {
    if (!z.uuid().safeParse(id).success) throw new ApiError(404);
    const value = await request(
      '/dashboard-api/payments/' + encodeURIComponent(id),
      paymentSchema,
      signal,
    );
    if (value.id.toLowerCase() !== id.toLowerCase()) throw new ApiError(502);
    return value;
  },
  status: (signal?: AbortSignal) => request('/dashboard-api/status', statusSchema, signal),
};
