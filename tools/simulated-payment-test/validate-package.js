/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, process, setImmediate */
const assert = require('node:assert/strict'),
  path = require('node:path'),
  https = require('node:https'),
  { EventEmitter } = require('node:events');
const directory = path.resolve(process.argv[2] || '');
assert.ok(process.argv[2]);
const { verify } = require(path.join(directory, 'launcher.js'));
const { origin, run, CONFIRM, transport, TestFailure } = require(path.join(directory, 'flow.js'));
const id = '00000000-0000-4000-8000-000000000001';
let total = 0;
function fixture(mode) {
  const calls = [],
    events = [];
  let state = 'pending',
    writes = 0,
    begun = false;
  const pending = () => ({
    id,
    amountMinor: 100,
    currency: 'EUR',
    provider: mode === 'wrong-provider' ? 'real' : 'simulator',
    status: state,
  });
  const options = {
    confirm: async () => (mode === 'cancel' ? '' : CONFIRM),
    runId: '00000000-0000-4000-8000-000000000009',
    begin: async (value) => {
      if (mode === 'existing-journal') throw Error();
      begun = true;
      events.push(value);
    },
    record: async (value) => events.push(value),
    request: async (method, p, body, settings) => {
      calls.push({ method, path: p, body, settings });
      if (p === '/health')
        return {
          status: 200,
          body: {
            status: 'ok',
            service: 'vaultx-pay',
            realPaymentsEnabled: mode === 'unsafe-health',
          },
        };
      if (settings.auth === false && p !== '/payments')
        return { status: 401, body: { error: { code: 'unauthorized' } } };
      if (p !== '/payments' && !p.startsWith('/payments/' + id))
        return {
          status: mode === 'unauthorized' ? 401 : 404,
          body: { error: { code: 'not_found' } },
        };
      if (method === 'POST' && p === '/payments') {
        assert.ok(begun);
        writes++;
        if (mode === 'create-timeout') throw new TestFailure('NETWORK');
        return {
          status: writes === 1 ? 201 : 200,
          body: {
            ...pending(),
            ...(mode === 'duplicate-ID' && writes === 2
              ? { id: '00000000-0000-4000-8000-000000000002' }
              : {}),
          },
        };
      }
      if (p.endsWith('/simulate')) {
        assert.deepEqual(body, { outcome: 'succeeded' });
        state = mode === 'failed-state' ? 'failed' : 'succeeded';
        return { status: mode === 'simulate-error' ? 500 : 200, body: pending() };
      }
      return { status: 200, body: pending() };
    },
  };
  return { options, calls, events, getWrites: () => writes };
}
(async () => {
  verify();
  total++;
  for (const url of [
    'http://staging.onrender.com',
    'https://user:NOT-A-CREDENTIAL@staging.onrender.com',
    'https://staging.onrender.com/path',
    'https://staging.onrender.com?secret=invalid',
    'https://127.0.0.1',
    'https://other.example.invalid',
    'https://staging.onrender.com:444',
  ]) {
    assert.throws(() => origin(url));
    total++;
  }
  assert.equal(
    origin('https://vaultx-staging.onrender.com/'),
    'https://vaultx-staging.onrender.com',
  );
  total++;
  for (const mode of [
    'success',
    'cancel',
    'unsafe-health',
    'unauthorized',
    'existing-journal',
    'create-timeout',
    'wrong-provider',
    'duplicate-ID',
    'failed-state',
    'simulate-error',
  ]) {
    const f = fixture(mode);
    let result, error;
    try {
      result = await run(f.options);
    } catch (e) {
      error = e;
    }
    if (mode === 'success') {
      assert.equal(result.result, 'SIMULATED_PAYMENT_VERIFIED');
      assert.equal(f.getWrites(), 2); // initial + same-idempotency replay, not two records
      const posts = f.calls.filter((c) => c.method === 'POST' && c.path === '/payments');
      assert.equal(posts[0].settings.idempotencyKey, posts[1].settings.idempotencyKey);
      assert.deepEqual(posts[0].body, posts[1].body);
      assert.equal(f.calls.at(-1).method, 'GET');
      assert.equal(f.events.at(-1).status, 'succeeded');
    } else if (mode === 'cancel') {
      assert.equal(result.writesAttempted, false);
      assert.equal(f.getWrites(), 0);
      assert.equal(f.events.length, 0);
    } else {
      assert.ok(error instanceof TestFailure);
      if (['unsafe-health', 'unauthorized', 'existing-journal'].includes(mode))
        assert.equal(f.getWrites(), 0);
      if (mode === 'create-timeout') {
        assert.equal(f.getWrites(), 1);
        assert.equal(error.phase, 'CREATE');
        assert.equal(error.reason, 'NETWORK');
      }
    }
    assert.ok(!JSON.stringify(result || { phase: error.phase }).includes('Authorization'));
    total++;
    process.stdout.write(`Simulated client ${mode}: expected safety/call-count result passed.\n`);
  }
  const saved = https.request;
  let captured;
  try {
    https.request = (url, options, callback) => {
      captured = { url, options };
      const req = new EventEmitter();
      req.setTimeout = () => {};
      req.write = () => {};
      req.destroy = () => req.emit('error', Error());
      req.end = () =>
        setImmediate(() => {
          const res = new EventEmitter();
          res.statusCode = 302;
          res.setEncoding = () => {};
          callback(res);
          res.emit('data', '{}');
          res.emit('end');
          req.emit('close');
        });
      return req;
    };
    await assert.rejects(
      transport('https://vaultx-staging.onrender.com', 'SYNTHETIC-NOT-A-VALID-KEY')(
        'GET',
        '/payments/' + id,
      ),
      (e) => e.phase === 'REDIRECT_REFUSED',
    );
    assert.ok(captured.options.agent.options.rejectUnauthorized);
    assert.equal(captured.options.agent.options.minVersion, 'TLSv1.2');
    assert.equal(captured.url.hostname, 'vaultx-staging.onrender.com');
    total++;
  } finally {
    https.request = saved;
  }
  if (process.platform === 'win32') {
    const { execFile } = require('node:child_process');
    const { decrypt } = require(path.join(directory, 'key-reader.js'));
    const text = { apiKey: 'SYNTHETIC-NOT-A-VALID-API-KEY-\u20ac-\u03bb' };
    const ciphertext = await new Promise((resolve, reject) => {
      const script =
        "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security; [Console]::InputEncoding=[Text.UTF8Encoding]::new($false); $bytes=[Text.Encoding]::UTF8.GetBytes([Console]::In.ReadToEnd()); [Console]::Out.Write([Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)));";
      const child = execFile(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-Command', script],
        { timeout: 15000, maxBuffer: 16384 },
        (error, stdout) => (error ? reject(Error()) : resolve(stdout)),
      );
      child.stdin.end(JSON.stringify(text));
    });
    const recovered = await decrypt(ciphertext);
    assert.ok(recovered.apiKey === text.apiKey);
    total++;
    await assert.rejects(decrypt('invalid blob'));
    total++;
    process.stdout.write(
      'Native Windows DPAPI synthetic round-trip and invalid-input refusal passed.\n',
    );
  } else process.stdout.write('SKIPPED: native DPAPI requires Windows, not claimed passed.\n');
  process.stdout.write(
    `${total} simulated-payment workflow checks passed. No staging/server connection or actual key access.\n`,
  );
})().catch(() => {
  process.stderr.write('Simulated workflow validation failed; details suppressed.\n');
  process.exitCode = 1;
});
