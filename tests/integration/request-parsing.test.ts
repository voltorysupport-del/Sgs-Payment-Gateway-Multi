import { fork, type ChildProcess } from 'node:child_process';
import { Agent, request } from 'node:http';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { brotliCompressSync, deflateSync, gzipSync } from 'node:zlib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

// A crash in the decompressor must fail a test, not terminate Vitest. All HTTP
// requests stay on loopback; the child uses the real app with a forbidden DB stub.
describe('request parsing security regression (GHSA-27r3-jxmh-p828)', () => {
  let child: ChildProcess;
  let port: number;
  let diagnostics = '';
  beforeAll(async () => {
    child = fork(fileURLToPath(new URL('../fixtures/parser-server.ts', import.meta.url)), [], {
      // Resolve to a file URL so Windows drive letters and spaces are safe.
      execArgv: ['--import', pathToFileURL(createRequire(import.meta.url).resolve('tsx')).href],
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      env: {
        ...process.env,
        DATABASE_URL: '',
        TEST_DATABASE_URL: '',
        TEST_DATABASE_TOKEN: '',
        NODE_ENV: 'test',
      },
    });
    child.stdout?.on('data', (chunk: Buffer) => {
      diagnostics += chunk.toString();
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      diagnostics += chunk.toString();
    });
    port = await new Promise<number>((resolve, reject) => {
      const failure = (reason: string) => {
        // Report useful loader/runtime codes without dumping inherited env or
        // arbitrary child output. Never turn a crashed fixture into a skipped test.
        const codes = [
          ...new Set(diagnostics.match(/\b(?:ERR_[A-Z_]+|MODULE_NOT_FOUND)\b/g) ?? []),
        ];
        return new Error(
          `Parser fixture ${reason}; exit=${child.exitCode}, signal=${child.signalCode}, codes=${codes.join(',') || 'none'}.`,
        );
      };
      const timer = setTimeout(() => reject(failure('startup timed out')), 25_000);
      child.once('message', (message: unknown) => {
        clearTimeout(timer);
        const candidate = (message as { port?: unknown }).port;
        if (typeof candidate !== 'number') reject(new Error('Invalid parser fixture port.'));
        else resolve(candidate);
      });
      child.once('error', () => {
        clearTimeout(timer);
        reject(failure('failed to launch'));
      });
      child.once('close', () => {
        clearTimeout(timer);
        reject(failure('exited during startup'));
      });
    });
  }, 30_000);
  afterAll(async () => {
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        child.kill();
        resolve();
      }, 3000);
      child.once('exit', () => {
        clearTimeout(timer);
        resolve();
      });
      if (child.connected) child.send('stop', () => {});
      else child.kill();
    });
  });

  function send(body: Buffer, encoding?: string, delayedTail?: Buffer) {
    return new Promise<{ status: number; body: string }>((resolve, reject) => {
      let tailTimer: ReturnType<typeof setTimeout> | undefined;
      const agent = new Agent({ keepAlive: true });
      let sent = false;
      let result: { status: number; body: string } | undefined;
      const complete = () => {
        if (sent && result) {
          agent.destroy();
          resolve(result);
        }
      };
      const req = request(
        {
          host: '127.0.0.1',
          port,
          method: 'POST',
          path: '/payments',
          agent,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': body.length + (delayedTail?.length ?? 0),
            ...(encoding ? { 'Content-Encoding': encoding } : {}),
          },
        },
        (res) => {
          let response = '';
          res.setEncoding('utf8');
          res.on('data', (chunk: string) => {
            response += chunk;
          });
          res.once('error', (error) => {
            agent.destroy();
            reject(error);
          });
          res.once('end', () => {
            result = { status: res.statusCode ?? 0, body: response };
            complete();
          });
        },
      );
      req.setTimeout(3000, () => req.destroy(new Error('Parser request timed out.')));
      // Do not pass an early-response test until every trailing byte was flushed.
      req.once('finish', () => {
        sent = true;
        complete();
      });
      req.once('error', (error) => {
        if (tailTimer) clearTimeout(tailTimer);
        agent.destroy();
        reject(error);
      });
      if (delayedTail) {
        req.write(body);
        tailTimer = setTimeout(() => req.end(delayedTail), 50);
      } else req.end(body);
    });
  }

  async function assertAlive() {
    // Let late decoder errors surface before checking process and HTTP health.
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(child.exitCode, 'Parser fixture must survive every request').toBeNull();
    expect(child.signalCode).toBeNull();
    const response = await fetch(`http://127.0.0.1:${port}/health`, {
      signal: AbortSignal.timeout(3000),
    });
    expect(response.status).toBe(200);
    expect(diagnostics.includes('uncaught')).toBe(false);
  }

  const valid = Buffer.from('{"amountMinor":1000,"currency":"EUR"}');
  it('accepts normal JSON up to the authentication boundary', async () => {
    expect((await send(valid)).status).toBe(401);
    await assertAlive();
  });
  it.each([
    { encoding: 'gzip', compress: gzipSync },
    { encoding: 'deflate', compress: deflateSync },
    { encoding: 'br', compress: brotliCompressSync },
  ])(
    'accepts valid $encoding JSON without changing authentication',
    async ({ encoding, compress }) => {
      expect((await send(compress(valid), encoding)).status).toBe(401);
      await assertAlive();
    },
  );
  it('rejects malformed JSON with the existing structured 400 response', async () => {
    const response = await send(Buffer.from('{'));
    expect(response.status).toBe(400);
    expect(JSON.parse(response.body)).toMatchObject({ error: { code: 'invalid_json' } });
    await assertAlive();
  });
  it('contains malformed compressed data without terminating the process', async () => {
    const response = await send(Buffer.from('not-a-gzip-stream'), 'gzip');
    // Existing app behavior: decoder errors use the generic internal-error
    // response. Changing that mapping is outside this dependency-only fix.
    expect(response.status).toBe(500);
    expect(JSON.parse(response.body)).toMatchObject({ error: { code: 'internal_error' } });
    await assertAlive();
  });
  it('survives a valid gzip frame followed by trailing bytes', async () => {
    const body = Buffer.concat([gzipSync(valid), Buffer.from([0]), Buffer.alloc(100 * 1024, 0x58)]);
    expect((await send(body, 'gzip')).status).toBe(401);
    await assertAlive();
  });
  it('survives delayed trailing bytes after a deflate decoder finishes early', async () => {
    const first = Buffer.concat([deflateSync(valid), Buffer.from([0])]);
    expect((await send(first, 'deflate', Buffer.alloc(1024))).status).toBe(401);
    await assertAlive();
  });
  it.each(['identity', 'gzip'])(
    'keeps the 100 KB limit for oversized $encoding JSON',
    async (encoding) => {
      const oversized = Buffer.from(JSON.stringify({ padding: 'x'.repeat(101 * 1024) }));
      const response = await send(
        encoding === 'gzip' ? gzipSync(oversized) : oversized,
        encoding === 'gzip' ? 'gzip' : undefined,
      );
      expect(response.status).toBe(413);
      expect(JSON.parse(response.body)).toMatchObject({ error: { code: 'payload_too_large' } });
      await assertAlive();
    },
  );
});
