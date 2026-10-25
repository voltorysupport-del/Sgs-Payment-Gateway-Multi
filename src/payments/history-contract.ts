import { z } from 'zod';

export const paymentHistoryQuerySchema = z
  .object({
    limit: z
      .string()
      .regex(/^[1-9][0-9]*$/)
      .transform(Number)
      .pipe(z.number().int().max(100))
      .default(25),
    offset: z
      .string()
      .regex(/^(0|[1-9][0-9]*)$/)
      .transform(Number)
      .pipe(z.number().int().max(10000))
      .default(0),
    status: z.enum(['pending', 'succeeded', 'failed', 'cancelled']).optional(),
    currency: z
      .string()
      .regex(/^[A-Z]{3}$/)
      .optional(),
  })
  .strict();
