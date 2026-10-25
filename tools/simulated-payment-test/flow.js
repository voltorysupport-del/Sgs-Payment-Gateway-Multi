/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require,module,URL,Buffer,setTimeout,clearTimeout */
const crypto = require('node:crypto'),
  https = require('node:https');
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const CONFIRM = 'RUN ONE SIMULATED PAYMENT';
class TestFailure extends Error {
  constructor(phase, status) {
    super('Simulated test stopped.');
    this.phase = phase;
    this.httpStatus =
      Number.isInteger(status) && status >= 100 && status <= 599 ? status : undefined;
  }
}
function origin(value) {
  const u = new URL(value);
  if (
    u.protocol !== 'https:' ||
    u.username ||
    u.password ||
    u.search ||
    u.hash ||
    !['', '/'].includes(u.pathname) ||
    (u.port && u.port !== '443') ||
    !/^[a-z0-9][a-z0-9-]*\.onrender\.com$/.test(u.hostname)
  )
    throw new TestFailure('ORIGIN');
  return u.origin;
}
function transport(base, apiKey) {
  const trusted = origin(base),
    agent = new https.Agent({ keepAlive: false, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
  return async (method, pathname, body, { auth = true, idempotencyKey } = {}) =>
    new Promise((resolve, reject) => {
      if (!/^\/(health|payments(?:\/[a-f0-9-]{36}(?:\/simulate)?)?)$/.test(pathname)) {
        reject(new TestFailure('PATH'));
        return;
      }
      const encoded = body === undefined ? undefined : JSON.stringify(body);
      const req = https.request(
        new URL(pathname, trusted),
        {
          method,
          agent,
          headers: {
            ...(auth ? { Authorization: 'Bearer ' + apiKey } : {}),
            ...(encoded
              ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(encoded) }
              : {}),
            ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}),
          },
        },
        (res) => {
          let text = '';
          res.setEncoding('utf8');
          res.on('data', (chunk) => {
            text += chunk;
            if (text.length > 65536) res.destroy();
          });
          res.on('error', () => reject(new TestFailure('NETWORK')));
          res.on('end', () => {
            if (res.statusCode >= 300 && res.statusCode < 400) {
              reject(new TestFailure('REDIRECT_REFUSED', res.statusCode));
              return;
            }
            try {
              resolve({ status: res.statusCode, body: JSON.parse(text) });
            } catch {
              reject(new TestFailure('RESPONSE', res.statusCode));
            }
          });
        },
      );
      const deadline = setTimeout(() => req.destroy(), 30000);
      req.once('close', () => clearTimeout(deadline));
      req.setTimeout(15000, () => req.destroy());
      req.on('error', () => reject(new TestFailure('NETWORK')));
      if (encoded) req.write(encoded);
      req.end();
    });
}
function payment(value, status, id) {
  if (
    !value ||
    !uuid.test(value.id) ||
    value.provider !== 'simulator' ||
    value.amountMinor !== 100 ||
    value.currency !== 'EUR' ||
    value.status !== status ||
    (id && value.id !== id)
  )
    throw new TestFailure('PAYMENT_CONTRACT');
  return value.id;
}
async function run({ request, confirm, begin, record, runId = crypto.randomUUID() }) {
  let phase = 'HEALTH',
    id,
    writesAttempted = false;
  async function call(name, method, path, body, options, status) {
    phase = name;
    const r = await request(method, path, body, options);
    if (r.status !== status) throw new TestFailure(phase, r.status);
    return r.body;
  }
  try {
    const health = await call('HEALTH', 'GET', '/health', undefined, { auth: false }, 200);
    if (
      health.status !== 'ok' ||
      health.service !== 'vaultx-pay' ||
      health.realPaymentsEnabled !== false
    )
      throw new TestFailure('SIMULATOR_SAFETY');
    const missing = '/payments/' + crypto.randomUUID();
    const unauth = await call(
      'UNAUTHENTICATED_REJECTION',
      'GET',
      missing,
      undefined,
      { auth: false },
      401,
    );
    if (unauth.error?.code !== 'unauthorized') throw new TestFailure(phase);
    const authorized = await call('AUTHENTICATION', 'GET', missing, undefined, {}, 404);
    if (authorized.error?.code !== 'not_found') throw new TestFailure(phase);
    phase = 'CONFIRMATION';
    if ((await confirm(CONFIRM)) !== CONFIRM)
      return { result: 'CANCELLED_BEFORE_PAYMENT', writesAttempted: false };
    const idem = 'vaultx-e2e-' + runId;
    phase = 'JOURNAL';
    await begin({
      mode: 'simulator',
      liveModeEnabled: false,
      amountMinor: 100,
      currency: 'EUR',
      idempotencyKey: idem,
    });
    const body = { amountMinor: 100, currency: 'EUR' };
    writesAttempted = true;
    const created = await call('CREATE', 'POST', '/payments', body, { idempotencyKey: idem }, 201);
    id = payment(created, 'pending');
    await record({ phase: 'CREATED', paymentId: id });
    const replay = await call(
      'IDEMPOTENCY_REPLAY',
      'POST',
      '/payments',
      body,
      { idempotencyKey: idem },
      200,
    );
    payment(replay, 'pending', id);
    payment(await call('GET_PENDING', 'GET', '/payments/' + id, undefined, {}, 200), 'pending', id);
    payment(
      await call(
        'SIMULATE_SUCCESS',
        'POST',
        '/payments/' + id + '/simulate',
        { outcome: 'succeeded' },
        {},
        200,
      ),
      'succeeded',
      id,
    );
    payment(
      await call('GET_PERSISTED_SUCCESS', 'GET', '/payments/' + id, undefined, {}, 200),
      'succeeded',
      id,
    );
    const result = {
      result: 'SIMULATED_PAYMENT_VERIFIED',
      paymentId: id,
      provider: 'simulator',
      status: 'succeeded',
      amountMinor: 100,
      currency: 'EUR',
      idempotencyVerified: true,
    };
    await record(result);
    return result;
  } catch (error) {
    const failure = new TestFailure(
      phase,
      error instanceof TestFailure ? error.httpStatus : undefined,
    );
    failure.reason = error instanceof TestFailure ? error.phase : 'UNEXPECTED';
    failure.writesAttempted = writesAttempted;
    if (id) failure.paymentId = id;
    throw failure;
  }
}
module.exports = { origin, transport, run, CONFIRM, TestFailure };
