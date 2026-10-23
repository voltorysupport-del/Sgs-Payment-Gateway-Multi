import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  connect,
  createSecureContext,
  createServer,
  type ConnectionOptions,
  type Server,
} from 'node:tls';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { stagingPoolConfig } from '../../src/admin/staging-config.js';

// Local TLS only: no PostgreSQL protocol, credentials, Render host, or external connection.
describe.skipIf(process.platform === 'win32')('staging TLS certificate verification', () => {
  let directory: string;
  let server: Server;
  let certificate: Buffer;
  let port: number;
  let sni: string;
  let ssl: ConnectionOptions;
  beforeAll(async () => {
    directory = await mkdtemp(path.join(tmpdir(), 'vaultx-local-tls-'));
    const keyFile = path.join(directory, 'key.pem');
    const certFile = path.join(directory, 'cert.pem');
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        keyFile,
        '-out',
        certFile,
        '-days',
        '1',
        '-subj',
        '/CN=db.example',
        '-addext',
        'subjectAltName=DNS:db.example',
      ],
      { stdio: 'ignore', timeout: 10_000 },
    );
    certificate = await readFile(certFile);
    const key = await readFile(keyFile);
    const context = createSecureContext({ key, cert: certificate });
    server = createServer(
      {
        key,
        cert: certificate,
        SNICallback: (name, callback) => {
          sni = name;
          callback(null, context);
        },
      },
      (socket) => {
        socket.end();
      },
    );
    server.on('tlsClientError', () => undefined);
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Local TLS fixture failed.');
    port = address.port;
    const config = stagingPoolConfig({
      NODE_ENV: 'production',
      DATABASE_URL: 'postgres://staging_user:synthetic@db.example/vaultx_pay_staging',
      VAULTX_ENVIRONMENT: 'staging',
      ALLOW_STAGING_OPERATOR_PROVISIONING: 'true',
      STAGING_DATABASE_HOST: 'db.example',
      STAGING_DATABASE_USER: 'staging_user',
    });
    if (!config.ssl || typeof config.ssl === 'boolean') throw new Error('Expected verified TLS.');
    ssl = config.ssl;
  });
  afterAll(async () => {
    if (server)
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    if (directory) await rm(directory, { recursive: true, force: true });
  });
  function handshake(overrides: ConnectionOptions): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = connect({ host: '127.0.0.1', port, ...ssl, ...overrides });
      socket.setTimeout(3000, () => {
        socket.destroy();
        resolve(false);
      });
      socket.once('secureConnect', () => {
        socket.end();
        resolve(true);
      });
      socket.once('error', () => {
        socket.destroy();
        resolve(false);
      });
    });
  }
  it('accepts an explicitly trusted matching certificate and sends hostname SNI', async () => {
    expect(await handshake({ ca: certificate })).toBe(true);
    expect(sni).toBe('db.example');
  });
  it('rejects an untrusted self-signed certificate', async () => {
    expect(await handshake({})).toBe(false);
  });
  it('rejects a trusted certificate for a different hostname', async () => {
    expect(await handshake({ ca: certificate, servername: 'different.example' })).toBe(false);
  });
});
