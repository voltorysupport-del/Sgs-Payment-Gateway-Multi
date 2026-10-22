/**
 * One consistent error format for every API response:
 *
 *   { "error": { "code": "not_found", "message": "...", "requestId": "..." } }
 *
 * The requestId lets you find the matching lines in the logs.
 * Internal details (stack traces, database messages) are never sent to callers.
 */
import type { Response } from 'express';

export interface ErrorBody {
  error: {
    code: string;
    message: string;
    requestId: string | undefined;
  };
}

export function sendError(res: Response, status: number, code: string, message: string): void {
  const requestId = res.getHeader('x-request-id');
  const body: ErrorBody = {
    error: {
      code,
      message,
      requestId: typeof requestId === 'string' ? requestId : undefined,
    },
  };
  res.status(status).json(body);
}
