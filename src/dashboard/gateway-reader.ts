import http from 'node:http';
import { z } from 'zod';
import { paymentHistoryQuerySchema } from '../payments/history-contract.js';

export type GatewayRead =
  | { kind: 'history'; query: z.output<typeof paymentHistoryQuerySchema> }
  | { kind: 'detail'; id: string }
  | { kind: 'health' };
export class GatewayReadError extends Error {
  constructor(readonly status: 404 | 502 | 503 | 504) {
    super('Dashboard upstream unavailable.');
  }
}
function readPath(read: GatewayRead): string {
  if (read.kind === 'health') return '/health';
  if (read.kind === 'detail') {
    if (!z.uuid().safeParse(read.id).success) throw new GatewayReadError(502);
    return '/payments/' + read.id;
  }
  if (read.kind === 'history') {
    // Revalidate at the transport boundary; build the path from known fields only.
    const q = paymentHistoryQuerySchema.parse({
      limit: String(read.query.limit),
      offset: String(read.query.offset),
      ...(read.query.status ? { status: read.query.status } : {}),
      ...(read.query.currency ? { currency: read.query.currency } : {}),
    });
    return (
      '/payments?' +
      new URLSearchParams({
        limit: String(q.limit),
        offset: String(q.offset),
        ...(q.status ? { status: q.status } : {}),
        ...(q.currency ? { currency: q.currency } : {}),
      }).toString()
    );
  }
  throw new GatewayReadError(502);
}

/** The only destination is this application's own IPv4 loopback listening port.
 * No URL, method, proxy configuration or browser headers enter this interface.
 */
export async function readGateway(
  port: number,
  apiKey: string,
  read: GatewayRead,
): Promise<unknown> {
  const path = readPath(read);
  const agent = new http.Agent({ keepAlive: false });
  try {
    return await new Promise((resolve, reject) => {
      let settled = false;
      const fail = (status: 404 | 502 | 503 | 504) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        reject(new GatewayReadError(status));
        req.destroy();
      };
      const req = http.request(
        {
          hostname: '127.0.0.1',
          family: 4,
          port,
          path,
          method: 'GET',
          agent,
          headers:
            read.kind === 'health'
              ? { Accept: 'application/json' }
              : { Accept: 'application/json', Authorization: 'Bearer ' + apiKey },
        },
        (res) => {
          // No redirects, upstream error messages, cookies or headers are returned.
          if (res.statusCode !== 200) {
            fail(
              res.statusCode === 404 && read.kind === 'detail'
                ? 404
                : [401, 403].includes(res.statusCode ?? 0)
                  ? 503
                  : 502,
            );
            res.destroy();
            return;
          }
          if (
            res.headers['content-type']?.split(';')[0]?.trim().toLowerCase() !== 'application/json'
          ) {
            fail(502);
            res.destroy();
            return;
          }
          let size = 0;
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > 256 * 1024) {
              fail(502);
              res.destroy();
            } else chunks.push(chunk);
          });
          res.on('aborted', () => fail(502));
          res.on('error', () => fail(502));
          res.on('end', () => {
            if (settled) return;
            try {
              const value: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
              settled = true;
              clearTimeout(deadline);
              resolve(value);
            } catch {
              fail(502);
            }
          });
        },
      );
      const deadline = setTimeout(() => fail(504), 5000);
      req.setTimeout(2000, () => fail(504));
      req.on('error', () => fail(502));
      req.end();
    });
  } finally {
    agent.destroy();
  }
}
