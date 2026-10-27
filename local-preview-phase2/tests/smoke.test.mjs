/* global fetch */
import test from 'node:test';
import http from 'node:http';
import assert from 'node:assert/strict';
import { startPreview } from '../scripts/server.mjs';
async function fixture(t) {
  const { server, origin } = await startPreview({ port: 0 });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const actor = () => ({ cookie: '', csrf: '' });
  async function request(path, method = 'GET', body, session = actor(), headers = {}) {
    const response = await fetch(origin + path, {
      method,
      headers: {
        ...(method !== 'GET'
          ? { Origin: origin, 'Content-Type': 'application/json', 'X-Demo-CSRF': session.csrf }
          : {}),
        ...(session.cookie ? { Cookie: session.cookie } : {}),
        ...headers,
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (response.headers.get('set-cookie'))
      session.cookie = response.headers.get('set-cookie').split(';')[0];
    const result = await response.json();
    return { status: response.status, result, headers: response.headers };
  }
  async function login(session, body) {
    assert.equal((await request('/demo/login', 'POST', body, session)).status, 200);
    const me = await request('/api/me', 'GET', null, session);
    session.csrf = me.result.csrf;
    return me.result;
  }
  return { request, login, actor, origin };
}
test('owner → merchant → invitation → bounded submerchant → simulator → revocation', async (t) => {
  const { request, login, actor } = await fixture(t),
    owner = actor(),
    merchant = actor(),
    user = actor();
  await login(owner, { role: 'owner' });
  const created = await request('/api/merchants', 'POST', { name: 'Aurora · Synthetic' }, owner);
  assert.equal(created.status, 201);
  const newMerchant = created.result.merchant.id;
  await login(merchant, { role: 'merchant', merchantId: newMerchant });
  assert.equal((await request('/api/merchants', 'GET', null, merchant)).status, 403);
  const invitation = await request(
    '/api/invitations',
    'POST',
    { name: 'Taylor · Synthetic', merchantId: 'merchant-orbit' },
    merchant,
  );
  assert.equal(invitation.result.invitation.merchantId, newMerchant);
  assert.equal(
    (await request('/demo/activate', 'POST', { invitationId: invitation.result.invitation.id }))
      .status,
    200,
  );
  let team = (await request('/api/team', 'GET', null, merchant)).result;
  const u = team.users[0];
  await login(user, { role: 'submerchant', userId: u.id });
  assert.equal((await request('/api/payments', 'GET', null, user)).status, 403);
  assert.equal(
    (
      await request(
        '/api/team/' + u.id,
        'PATCH',
        { version: 1, permissions: ['platform.owner'], terminals: [], status: 'active' },
        merchant,
      )
    ).status,
    403,
  );
  assert.equal(
    (
      await request(
        '/api/team/' + u.id,
        'PATCH',
        {
          version: 1,
          permissions: ['payments.read'],
          terminals: ['terminal-orbit'],
          status: 'active',
        },
        merchant,
      )
    ).status,
    403,
  );
  const grant = {
    version: 1,
    permissions: ['payments.read'],
    terminals: ['terminal-web'],
    status: 'active',
  };
  assert.equal((await request('/api/team/' + u.id, 'PATCH', grant, merchant)).status, 200);
  assert.equal((await request('/api/team/' + u.id, 'PATCH', grant, merchant)).status, 409);
  assert.equal((await request('/api/me', 'GET', null, user)).status, 401);
  await login(user, { role: 'submerchant', userId: u.id });
  assert.equal((await request('/api/payments', 'GET', null, user)).result.total, 0);
  await login(merchant, { role: 'merchant', merchantId: 'merchant-north' });
  team = (await request('/api/team', 'GET', null, merchant)).result;
  const north = team.users[0];
  assert.equal(
    (
      await request(
        '/api/team/' + north.id,
        'PATCH',
        {
          version: north.version,
          permissions: ['payments.read', 'payments.simulate', 'audit.read'],
          terminals: ['terminal-web'],
          status: 'active',
        },
        merchant,
      )
    ).status,
    200,
  );
  await login(user, { role: 'submerchant', userId: north.id });
  const payments = (await request('/api/payments', 'GET', null, user)).result;
  assert.ok(payments.total > 10);
  assert.ok(
    payments.payments.every(
      (p) =>
        p.terminal === 'terminal-web' &&
        p.merchantId === 'merchant-north' &&
        p.provider === 'simulator',
    ),
  );
  assert.equal((await request('/api/payments/demo-payment-031', 'GET', null, user)).status, 404);
  assert.equal((await request('/api/payments/demo-payment-001', 'GET', null, user)).status, 404);
  const pending = (await request('/api/payments?status=pending', 'GET', null, user)).result
    .payments[0];
  assert.equal(
    (
      await request(
        '/api/payments/' + pending.id + '/simulate',
        'POST',
        { outcome: 'succeeded' },
        user,
      )
    ).status,
    200,
  );
  assert.equal(
    (
      await request(
        '/api/payments/' + pending.id + '/simulate',
        'POST',
        { outcome: 'failed' },
        user,
      )
    ).status,
    409,
  );
  assert.ok(
    (await request('/api/audit', 'GET', null, user)).result.events.some(
      (e) => e.action === 'demo.payment.succeeded',
    ),
  );
  team = (await request('/api/team', 'GET', null, merchant)).result;
  assert.equal(
    (
      await request(
        '/api/team/' + north.id,
        'PATCH',
        { version: team.users[0].version, permissions: [], terminals: [], status: 'active' },
        merchant,
      )
    ).status,
    200,
  );
  assert.equal((await request('/api/payments', 'GET', null, user)).status, 401);
  await login(user, { role: 'submerchant', userId: north.id });
  assert.equal((await request('/api/payments', 'GET', null, user)).status, 403);
});
test('suspension, permanent entitlement withdrawal and optimistic revisions', async (t) => {
  const { request, login, actor } = await fixture(t),
    owner = actor(),
    merchant = actor(),
    user = actor();
  await login(owner, { role: 'owner' });
  await login(merchant, { role: 'merchant', merchantId: 'merchant-north' });
  await login(user, { role: 'submerchant', userId: 'user-analyst' });
  assert.equal(
    (
      await request(
        '/api/merchants/merchant-north',
        'PATCH',
        { version: 1, status: 'suspended' },
        owner,
      )
    ).result.merchant.version,
    2,
  );
  assert.equal((await request('/api/me', 'GET', null, merchant)).status, 401);
  assert.equal((await request('/api/me', 'GET', null, user)).status, 401);
  assert.equal(
    (
      await request(
        '/api/merchants/merchant-north',
        'PATCH',
        { version: 1, status: 'active' },
        owner,
      )
    ).status,
    409,
  );
  assert.equal(
    (
      await request(
        '/api/merchants/merchant-north',
        'PATCH',
        { version: 2, status: 'active' },
        owner,
      )
    ).result.merchant.version,
    3,
  );
  assert.equal(
    (
      await request(
        '/api/merchants/merchant-north/withdraw',
        'POST',
        { version: 3, permission: 'payments.read' },
        owner,
      )
    ).result.merchant.version,
    4,
  );
  assert.equal(
    (
      await request(
        '/api/merchants/merchant-north/withdraw',
        'POST',
        { version: 4, permission: 'payments.read' },
        owner,
      )
    ).status,
    409,
  );
  await login(merchant, { role: 'merchant', merchantId: 'merchant-north' });
  const team = (await request('/api/team', 'GET', null, merchant)).result;
  assert.equal(team.ceiling.includes('payments.read'), false);
  assert.equal(team.users[0].permissions.includes('payments.read'), false);
  assert.equal(
    (
      await request(
        '/api/team/user-analyst',
        'PATCH',
        {
          version: team.users[0].version,
          permissions: ['payments.read'],
          terminals: ['terminal-web'],
          status: 'active',
        },
        merchant,
      )
    ).status,
    403,
  );
});
test('local origin, CSRF, static allowlist, no real payment API and no-store', async (t) => {
  const { request, login, actor, origin } = await fixture(t),
    owner = actor();
  const home = await fetch(origin);
  assert.equal(home.status, 200);
  assert.match(await home.text(), /SIMULATED/);
  assert.equal(home.headers.get('cache-control'), 'no-store');
  assert.match(home.headers.get('content-security-policy'), /connect-src 'self'/);
  assert.equal((await fetch(origin + '/scripts/server.mjs')).status, 404);
  assert.equal((await fetch(origin + '/.env')).status, 404);
  assert.equal(
    (
      await request('/demo/login', 'POST', { role: 'owner' }, owner, {
        Origin: 'https://example.com',
      })
    ).status,
    403,
  );
  const invalidHost = await new Promise((resolve, reject) => {
    const r = http.get(
      origin + '/demo/catalog',
      { headers: { Host: 'evil.example:4175' } },
      (response) => {
        response.resume();
        resolve(response.statusCode);
      },
    );
    r.on('error', reject);
  });
  assert.equal(invalidHost, 403);
  assert.equal((await request('/api/merchants', 'GET')).status, 401);
  await login(owner, { role: 'owner' });
  assert.equal(
    (
      await request('/api/merchants', 'POST', { name: 'Should not create' }, owner, {
        'X-Demo-CSRF': 'invalid',
      })
    ).status,
    403,
  );
  assert.equal((await request('/payments', 'POST', { amount: 1 }, owner)).status, 404);
  assert.equal((await request('/api/merchants', 'DELETE', null, owner)).status, 405);
});
test('pagination and reset discard synthetic state', async (t) => {
  const { request, login, actor } = await fixture(t),
    merchant = actor();
  await login(merchant, { role: 'merchant', merchantId: 'merchant-north' });
  const page1 = (await request('/api/payments', 'GET', null, merchant)).result;
  const page2 = (await request('/api/payments?offset=10', 'GET', null, merchant)).result;
  assert.equal(page1.payments.length, 10);
  assert.equal(page2.payments.length, 10);
  assert.equal(new Set([...page1.payments, ...page2.payments].map((p) => p.id)).size, 20);
  assert.equal((await request('/api/payments?offset=1', 'GET', null, merchant)).status, 400);
  assert.equal(
    (await request('/api/payments?operatorId=merchant-orbit', 'GET', null, merchant)).status,
    400,
  );
  assert.equal((await request('/demo/reset', 'POST', {}, merchant)).status, 200);
  assert.equal((await request('/api/me', 'GET', null, merchant)).status, 401);
});
