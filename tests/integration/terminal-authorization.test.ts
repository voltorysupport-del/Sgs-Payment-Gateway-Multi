import { ReadUnavailable } from '../../src/db/read-client.js';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Pool } from 'pg';
import request from 'supertest';
import { beforeAll, afterAll, beforeEach, afterEach, expect, it } from 'vitest';
import { createApp } from '../../src/app.js';
import { runMigrations } from '../../src/db/migrate.js';
import { createMerchantInvitation } from '../../src/management/merchant-domain.js';
import {
  beginEnrollment,
  finishEnrollment,
  issueSyntheticInvitationToken,
  beginAuthentication,
  finishAuthentication,
} from '../../src/enrollment/service.js';
import { generateOperatorApiKey } from '../../src/db/operator-keys.js';
import { createPayment, getPayment } from '../../src/db/payments.js';
import { withTerminalAuthorization } from '../../src/payments/terminal-authorization.js';
import { signReadRestriction, type TerminalReadScope } from '../../src/payments/internal-read.js';
import { touchDashboardSession } from '../../src/dashboard/sessions.js';
import {
  createMerchantBrowserFixture,
  cleanupMerchantBrowserFixture,
} from '../merchant-browser-fixture.js';
import {
  policyTransaction,
  policyQuery,
  insertViewerSession,
  lockPolicyRows,
} from '../viewer-policy-fixtures.js';
import { syntheticAuthenticator } from '../webauthn-authenticator.js';
import { openTestDatabase } from '../test-database.js';
import { testConfig, captureLogger } from '../helpers.js';

const origin = 'https://terminal.example.invalid';
const digest = (raw: string) => createHash('sha256').update(raw).digest('hex');
let pool: Pool, fixture: Awaited<ReturnType<typeof createMerchantBrowserFixture>>;
let terminal: string,
  unassigned: string,
  username: string,
  member: string,
  user: string,
  cookie: string,
  key: string;
let scope: TerminalReadScope, payments: string[];
const logs = captureLogger();
function config(enabled = true, port = 3000) {
  return testConfig({
    DASHBOARD_ENABLED: 'true',
    DASHBOARD_BFF_ENABLED: 'true',
    MERCHANT_MANAGEMENT_ENABLED: 'true',
    TERMINAL_SCOPED_READS_ENABLED: String(enabled),
    DASHBOARD_PUBLIC_ORIGIN: origin,
    DASHBOARD_OPERATOR_ID: fixture.operator,
    DASHBOARD_READ_ONLY_API_KEY: key,
    PORT: String(port),
  });
}
function app(enabled = true) {
  return createApp({ pool, config: config(enabled), logger: logs.logger });
}
function read(path: string, selected = scope, enabled = true) {
  return request(app(enabled))
    .get(path)
    .set('Authorization', 'Bearer ' + key)
    .set(signReadRestriction(path, key, fixture.operator, selected));
}
async function refreshedScope(token: string) {
  const identity = await touchDashboardSession(pool, digest(token), 'client.payments.read', true);
  expect(identity?.permissionAllowed).toBe(true);
  return identity!.terminalScope!;
}
beforeAll(async () => {
  pool = await openTestDatabase();
  await runMigrations(pool);
});
beforeEach(async () => {
  fixture = await createMerchantBrowserFixture(pool);
  terminal = (
    await pool.query('SELECT id FROM public.merchant_terminals WHERE operator_id=$1', [
      fixture.operator,
    ])
  ).rows[0].id;
  unassigned = randomUUID();
  await pool.query(
    "INSERT INTO public.merchant_terminals(id,operator_id,code,name) VALUES($1,$2,'unassigned','Synthetic unassigned')",
    [unassigned, fixture.operator],
  );
  username = 'terminal_user_' + randomUUID();
  const invitation = await policyTransaction(pool, fixture.operator, (c) =>
    createMerchantInvitation(c, {
      operatorId: fixture.operator,
      sponsorMembershipId: fixture.member,
      username,
      kind: 'submerchant',
      permissions: ['client.payments.read', 'client.status.read'],
      terminalIds: [terminal],
    }),
  );
  const token = await issueSyntheticInvitationToken(pool, invitation.invitationId),
    preauth = randomBytes(32).toString('hex'),
    authenticator = syntheticAuthenticator();
  await pool.query('INSERT INTO public.dashboard_sessions(token_hash,csrf_hash) VALUES($1,$1)', [
    digest(preauth),
  ]);
  const options = await beginEnrollment(
    pool,
    digest(preauth),
    token,
    'Synthetic terminal enrollment password!',
    origin,
  );
  await finishEnrollment(
    pool,
    digest(preauth),
    authenticator.registration(options.challenge, origin),
    origin,
  );
  const identity = (
    await pool.query(
      'SELECT u.id,m.id AS membership FROM public.dashboard_users u JOIN public.dashboard_memberships m ON m.user_id=u.id WHERE u.username=$1',
      [username],
    )
  ).rows[0];
  user = identity.id;
  member = identity.membership;
  const passwordSession = randomBytes(32).toString('hex');
  await insertViewerSession(pool, user, digest(passwordSession), digest(passwordSession));
  // Verify actual signed WebAuthn assertion, not a client-side assurance flag.
  const challenge = await beginAuthentication(pool, digest(passwordSession), origin);
  const authenticated = await finishAuthentication(
    pool,
    digest(passwordSession),
    authenticator.assertion(challenge.challenge, origin, user),
    origin,
  );
  cookie = authenticated.token;
  scope = await refreshedScope(cookie);
  const credential = generateOperatorApiKey();
  key = credential.apiKey;
  await pool.query(
    "INSERT INTO public.operator_api_keys(id,operator_id,name,key_hash,permission) VALUES($1,$2,'Synthetic terminal reader',$3,'read_only')",
    [randomUUID(), fixture.operator, credential.keyHash],
  );
  payments = [];
  for (const associated of [terminal, terminal, unassigned, undefined])
    payments.push(
      (await createPayment(pool, fixture.operator, randomUUID(), 100, 'EUR', associated)).payment
        .id,
    );
  await pool.query(
    "UPDATE public.payments SET created_at='2026-01-01T00:00:00Z' WHERE operator_id=$1",
    [fixture.operator],
  );
});
afterEach(async () => {
  await pool.query('DELETE FROM public.payments WHERE operator_id=$1', [fixture.operator]);
  await pool.query('DELETE FROM public.operator_api_keys WHERE operator_id=$1', [fixture.operator]);
  await cleanupMerchantBrowserFixture(pool, fixture);
  await pool.query('DELETE FROM public.dashboard_sessions WHERE user_id IS NULL');
});
afterAll(async () => {
  await pool?.end();
});

it('derives canonical immutable assignments from consumed invitation, with durable audit and no default access', async () => {
  const assignments = await pool.query(
    'SELECT * FROM public.merchant_terminal_assignments WHERE membership_id=$1',
    [member],
  );
  expect(assignments.rowCount).toBe(1);
  expect(assignments.rows[0]).toMatchObject({
    operator_id: fixture.operator,
    terminal_id: terminal,
    revoked_at: null,
  });
  expect(
    (
      await pool.query(
        'SELECT action FROM public.merchant_terminal_assignment_audit WHERE assignment_id=$1',
        [assignments.rows[0].id],
      )
    ).rows,
  ).toEqual([{ action: 'assigned' }]);
  expect((await read('/payments', scope, false)).status).toBe(403);
  expect(
    (
      await request(app(false))
        .get('/dashboard-api/payments')
        .set('Cookie', '__Host-vaultx_session=' + cookie)
    ).status,
  ).toBe(403);
  await expect(
    policyQuery(
      pool,
      fixture.operator,
      'UPDATE public.merchant_terminal_assignments SET terminal_id=$2 WHERE membership_id=$1',
      [member, unassigned],
    ),
  ).rejects.toMatchObject({ code: '42501' });
  await expect(
    pool.query('UPDATE public.merchant_terminal_assignment_audit SET reason=reason'),
  ).rejects.toThrow();
});

it('SQL scopes detail, ordering, final-page metadata and filters before pagination; NULL/unassigned/guessed IDs are indistinguishable', async () => {
  const ordered = [payments[0]!, payments[1]!].sort().reverse();
  for (const [offset, id] of ordered.entries()) {
    const page = await read('/payments?limit=1&offset=' + offset);
    expect(page.status).toBe(200);
    expect((page.body.payments as { id: string }[]).map((p) => p.id)).toEqual([id]);
    expect(page.body.pagination).toEqual({ limit: 1, offset, hasMore: offset === 0 });
  }
  expect((await read('/payments?offset=2')).body.payments).toEqual([]);
  expect((await read('/payments?currency=USD')).body.payments).toEqual([]);
  expect((await read('/payments?status=succeeded')).body.payments).toEqual([]);
  expect((await read('/payments/' + payments[0])).status).toBe(200);
  for (const id of [payments[2], payments[3], randomUUID()]) {
    const response = await read('/payments/' + id);
    expect(response.status).toBe(404);
    expect(response.body.error.message).toBe('The payment was not found.');
  }
  expect((await read('/payments?terminalId=' + unassigned)).status).toBe(400);
  expect((await read('/payments?limit=101')).status).toBe(400);
  expect(
    (
      await request(app())
        .get('/payments')
        .set('Cookie', '__Host-vaultx_session=' + cookie)
    ).status,
  ).toBe(401);
});

it('rejects signed scope widening, principal substitution, tampering, foreign tenants and unsigned human requests', async () => {
  expect(
    (await read('/payments', { ...scope, terminalIds: [...scope.terminalIds, unassigned].sort() }))
      .status,
  ).toBe(503);
  expect((await read('/payments', { ...scope, userId: randomUUID() })).status).toBe(503);
  expect((await read('/payments', { ...scope, membershipId: fixture.child })).status).toBe(503);
  const headers = signReadRestriction('/payments', key, fixture.operator, scope);
  headers['x-vaultx-read-scope'] = Buffer.from(
    JSON.stringify({ ...scope, terminalIds: [unassigned] }),
  ).toString('base64url');
  expect(
    (
      await request(app())
        .get('/payments')
        .set('Authorization', 'Bearer ' + key)
        .set(headers)
    ).status,
  ).toBe(403);
  expect(
    (
      await request(app())
        .get('/payments')
        .set(signReadRestriction('/payments', key, fixture.operator, scope))
    ).status,
  ).toBe(403);
  const foreign = await createMerchantBrowserFixture(pool);
  try {
    const id = (await createPayment(pool, foreign.operator, randomUUID(), 100, 'EUR')).payment.id;
    expect((await read('/payments/' + id)).status).toBe(404);
    expect(
      (
        await request(app())
          .get('/payments')
          .set('Authorization', 'Bearer ' + key)
          .set(signReadRestriction('/payments', key, foreign.operator, scope))
      ).status,
    ).toBe(401);
  } finally {
    await pool.query('DELETE FROM public.payments WHERE operator_id=$1', [foreign.operator]);
    await cleanupMerchantBrowserFixture(pool, foreign);
  }
  expect(logs.output()).not.toContain(key);
  expect(logs.output()).not.toContain(cookie);
  expect(logs.output()).not.toContain(scope.sessionHash);
});

it('suspension permanently revokes assignments and invalidates sessions; reactivation does not resurrect visibility', async () => {
  const before = (
    await pool.query('SELECT authorization_version FROM public.dashboard_memberships WHERE id=$1', [
      member,
    ])
  ).rows[0].authorization_version;
  await policyQuery(
    pool,
    fixture.operator,
    "UPDATE public.merchant_terminals SET status='suspended' WHERE id=$1",
    [terminal],
  );
  expect(
    (
      await pool.query('SELECT token_hash FROM public.dashboard_sessions WHERE token_hash=$1', [
        digest(cookie),
      ])
    ).rowCount,
  ).toBe(0);
  expect(
    (
      await pool.query(
        'SELECT authorization_version FROM public.dashboard_memberships WHERE id=$1',
        [member],
      )
    ).rows[0].authorization_version,
  ).toBeGreaterThan(before);
  expect((await read('/payments')).status).toBe(503);
  expect((await read('/health')).status).toBe(503);
  await policyQuery(
    pool,
    fixture.operator,
    "UPDATE public.merchant_terminals SET status='active' WHERE id=$1",
    [terminal],
  );
  expect((await read('/payments')).status).toBe(503);
  await expect(
    policyQuery(
      pool,
      fixture.operator,
      'UPDATE public.merchant_terminal_assignments SET revoked_at=NULL,revocation_reason=NULL WHERE membership_id=$1',
      [member],
    ),
  ).rejects.toMatchObject({ code: '42501' });
  expect(
    (
      await pool.query(
        'SELECT action FROM public.merchant_terminal_assignment_audit WHERE operator_id=$1 ORDER BY id',
        [fixture.operator],
      )
    ).rows,
  ).toEqual([{ action: 'assigned' }, { action: 'revoked' }]);
});

it('requires current WebAuthn/session, live permission ceilings and unrevoked read-only machine key', async () => {
  await pool.query(
    'UPDATE public.dashboard_sessions SET webauthn_verified_at=NULL,webauthn_credential_id=NULL WHERE token_hash=$1',
    [scope.sessionHash],
  );
  expect((await read('/payments')).status).toBe(503);
});

it('grant withdrawal is permanent and stale signed handoffs cannot retain visibility', async () => {
  await policyQuery(
    pool,
    fixture.operator,
    `UPDATE public.membership_permission_grants SET revoked_at=statement_timestamp(),revocation_reason='withdrawn',revocation_policy_version=(SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=$2) WHERE membership_id=$1 AND permission_code='client.payments.read' AND revoked_at IS NULL`,
    [member, fixture.operator],
  );
  expect((await read('/payments')).status).toBe(503);
  expect(
    (
      await pool.query(
        'SELECT revoked_at FROM public.merchant_terminal_assignments WHERE membership_id=$1',
        [member],
      )
    ).rows[0].revoked_at,
  ).not.toBeNull();
});

function barrier() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
async function waitBlocked(pid: number) {
  const until = Date.now() + 5000;
  while (Date.now() < until) {
    if (
      (await pool.query('SELECT cardinality(pg_blocking_pids($1))>0 AS blocked', [pid])).rows[0]
        .blocked
    )
      return;
    await new Promise<void>((r) => setImmediate(r));
  }
  throw new Error('Expected policy lock wait');
}
it('read materialization linearizes before revocation; revocation waits on policy gate and no later read survives', async () => {
  const entered = barrier(),
    release = barrier(),
    writer = await pool.connect();
  let pending: Promise<unknown> | undefined;
  const pid = (await writer.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
  const readPromise = withTerminalAuthorization(
    pool,
    key,
    fixture.operator,
    scope,
    'client.payments.read',
    async (client, ids) => {
      entered.resolve();
      await release.promise;
      return client.query(
        'SELECT id FROM public.payments WHERE operator_id=$1 AND terminal_id=ANY($2::uuid[])',
        [fixture.operator, ids],
      );
    },
  );
  try {
    await entered.promise;
    await writer.query('BEGIN');
    pending = (async () => {
      await lockPolicyRows(writer, fixture.operator);
      await writer.query("UPDATE public.merchant_terminals SET status='suspended' WHERE id=$1", [
        terminal,
      ]);
      await writer.query('COMMIT');
    })();
    await waitBlocked(pid);
    release.resolve();
    expect((await readPromise).rowCount).toBe(2);
    await pending;
    await expect(
      getPayment(pool, fixture.operator, payments[0]!, {
        apiKey: key,
        restriction: {
          operatorId: fixture.operator,
          permission: 'read_only',
          terminalScope: scope,
        },
      }),
    ).rejects.toThrow();
  } finally {
    release.resolve();
    await readPromise.catch(() => undefined);
    await pending?.catch(() => undefined);
    await writer.query('ROLLBACK');
    writer.release();
  }
});

it.each(['terminal', 'assignment', 'membership', 'key-permission'] as const)(
  'BFF principal binding fails closed for concurrent %s change between admission and upstream authentication',
  async (change) => {
    const entered = barrier(),
      release = barrier();
    let pause = false;
    const gatewayApp = app();
    const gateway = http.createServer((req, res) => {
      void (async () => {
        if (pause) {
          entered.resolve();
          await release.promise;
        }
        gatewayApp(req, res);
      })();
    });
    await new Promise<void>((r) => gateway.listen(0, '127.0.0.1', r));
    const bff = createApp({
      pool,
      config: config(true, (gateway.address() as AddressInfo).port),
      logger: logs.logger,
    });
    let pending: Promise<request.Response> | undefined;
    try {
      const ok = await request(bff)
        .get('/dashboard-api/payments')
        .set('Cookie', '__Host-vaultx_session=' + cookie);
      expect(ok.status).toBe(200);
      expect(ok.body.payments).toHaveLength(2);
      expect(ok.headers['cache-control']).toBe('no-store');
      expect(
        (
          await request(bff)
            .get('/dashboard-api/status')
            .set('Cookie', '__Host-vaultx_session=' + cookie)
        ).status,
      ).toBe(200);
      const admin = await request(bff)
        .get('/dashboard-api/payments')
        .set('Cookie', '__Host-vaultx_session=' + fixture.token);
      expect(admin.status).toBe(200);
      expect(admin.body.payments).toHaveLength(4);
      expect(
        (
          await request(bff)
            .get('/dashboard-api/payments')
            .set('Cookie', '__Host-vaultx_session=' + cookie)
            .set('x-vaultx-read-scope', 'forged')
        ).status,
      ).toBe(403);
      pause = true;
      pending = request(bff)
        .get('/dashboard-api/payments')
        .set('Cookie', '__Host-vaultx_session=' + cookie)
        .then((r) => r);
      await entered.promise;
      if (change === 'terminal')
        await policyQuery(
          pool,
          fixture.operator,
          "UPDATE public.merchant_terminals SET status='suspended' WHERE id=$1",
          [terminal],
        );
      if (change === 'assignment')
        await policyQuery(
          pool,
          fixture.operator,
          "UPDATE public.merchant_terminal_assignments SET revoked_at=statement_timestamp(),revocation_reason='withdrawn' WHERE membership_id=$1",
          [member],
        );
      if (change === 'membership')
        await policyQuery(
          pool,
          fixture.operator,
          "UPDATE public.dashboard_memberships SET status='disabled' WHERE id=$1",
          [member],
        );
      if (change === 'key-permission')
        await pool.query(
          "UPDATE public.operator_api_keys SET permission='read_write' WHERE key_hash=$1",
          [digest(key)],
        );
      release.resolve();
      const refused = await pending;
      expect(refused.status).toBe(change === 'key-permission' ? 503 : 502);
      expect(JSON.stringify(refused.body)).not.toContain(payments[0]);
    } finally {
      release.resolve();
      await pending?.catch(() => undefined);
      await new Promise<void>((resolve, reject) =>
        gateway.close((e) => (e ? reject(e) : resolve())),
      );
    }
  },
);

it.each([
  'disabled-user',
  'disabled-member',
  'suspended-operator',
  'withdrawn-ceiling',
  'revoked-key',
  'write-key',
  'expired-session',
  'stale-version',
] as const)('fails closed for %s at the final boundary', async (change) => {
  if (change === 'disabled-user')
    await policyQuery(
      pool,
      fixture.operator,
      "UPDATE public.dashboard_users SET status='disabled' WHERE id=$1",
      [user],
    );
  if (change === 'disabled-member')
    await policyQuery(
      pool,
      fixture.operator,
      "UPDATE public.dashboard_memberships SET status='disabled' WHERE id=$1",
      [member],
    );
  if (change === 'suspended-operator')
    await policyQuery(
      pool,
      fixture.operator,
      "UPDATE public.operators SET status='suspended' WHERE id=$1",
      [fixture.operator],
    );
  if (change === 'withdrawn-ceiling')
    await policyQuery(
      pool,
      fixture.operator,
      "UPDATE public.operator_permission_entitlements SET enabled=false WHERE operator_id=$1 AND permission_code='client.payments.read'",
      [fixture.operator],
    );
  if (change === 'revoked-key')
    await pool.query(
      'UPDATE public.operator_api_keys SET revoked_at=clock_timestamp() WHERE key_hash=$1',
      [digest(key)],
    );
  if (change === 'write-key')
    await pool.query(
      "UPDATE public.operator_api_keys SET permission='read_write' WHERE key_hash=$1",
      [digest(key)],
    );
  if (change === 'expired-session')
    await pool.query(
      "UPDATE public.dashboard_sessions SET last_seen_at=clock_timestamp()-interval '31 minutes' WHERE token_hash=$1",
      [scope.sessionHash],
    );
  if (change === 'stale-version')
    await pool.query(
      'UPDATE public.dashboard_sessions SET membership_authz_version=membership_authz_version+1 WHERE token_hash=$1',
      [scope.sessionHash],
    );
  const response = await read('/payments');
  expect(response.status).toBe(
    ['suspended-operator', 'revoked-key', 'write-key'].includes(change) ? 401 : 503,
  );
  expect(JSON.stringify(response.body)).not.toContain(payments[0]);
  expect(JSON.stringify(response.body)).not.toContain(scope.sessionHash);
});

it('refuses out-of-intent assignments, ungated mutations, terminal reassignment and every payment write', async () => {
  const intent = (
    await pool.query(
      'SELECT invitation_id FROM public.merchant_terminal_assignments WHERE membership_id=$1',
      [member],
    )
  ).rows[0].invitation_id;
  await expect(
    policyQuery(
      pool,
      fixture.operator,
      'INSERT INTO public.merchant_terminal_assignments(id,operator_id,membership_id,terminal_id,invitation_id) VALUES($1,$2,$3,$4,$5)',
      [randomUUID(), fixture.operator, member, unassigned, intent],
    ),
  ).rejects.toMatchObject({ code: '42501' });
  await expect(
    pool.query(
      "UPDATE public.merchant_terminal_assignments SET revoked_at=statement_timestamp(),revocation_reason='withdrawn' WHERE membership_id=$1",
      [member],
    ),
  ).rejects.toMatchObject({ code: '42501' });
  await expect(
    pool.query("UPDATE public.merchant_terminals SET status='suspended' WHERE id=$1", [terminal]),
  ).rejects.toMatchObject({ code: '42501' });
  await expect(
    policyQuery(pool, fixture.operator, 'UPDATE public.merchant_terminals SET id=$2 WHERE id=$1', [
      terminal,
      randomUUID(),
    ]),
  ).rejects.toMatchObject({ code: '42501' });
  for (const method of ['post', 'patch', 'delete', 'options', 'head'] as const) {
    const response = await request(app())
      [method]('/payments')
      .set('Authorization', 'Bearer ' + key)
      .set(signReadRestriction('/payments', key, fixture.operator, scope));
    expect(response.status).toBe(403);
  }
});

it('assignment withdrawal is one-way, invalidates sessions, records committed versions and cannot be reinserted', async () => {
  await policyQuery(
    pool,
    fixture.operator,
    "UPDATE public.merchant_terminal_assignments SET revoked_at=statement_timestamp(),revocation_reason='withdrawn' WHERE membership_id=$1",
    [member],
  );
  expect((await read('/payments')).status).toBe(503);
  const audit = (
    await pool.query(
      "SELECT membership_version FROM public.merchant_terminal_assignment_audit WHERE operator_id=$1 AND action='revoked'",
      [fixture.operator],
    )
  ).rows[0];
  expect(audit.membership_version).toBe(
    (
      await pool.query(
        'SELECT authorization_version FROM public.dashboard_memberships WHERE id=$1',
        [member],
      )
    ).rows[0].authorization_version,
  );
  for (const sql of [
    'UPDATE public.merchant_terminal_assignments SET revoked_at=NULL,revocation_reason=NULL WHERE membership_id=$1',
    "UPDATE public.merchant_terminal_assignments SET revoked_at=statement_timestamp(),revocation_reason='withdrawn' WHERE membership_id=$1",
  ])
    await expect(policyQuery(pool, fixture.operator, sql, [member])).rejects.toMatchObject({
      code: '42501',
    });
  const assignment = (
    await pool.query(
      'SELECT invitation_id FROM public.merchant_terminal_assignments WHERE membership_id=$1',
      [member],
    )
  ).rows[0];
  await expect(
    policyQuery(
      pool,
      fixture.operator,
      'INSERT INTO public.merchant_terminal_assignments(id,operator_id,membership_id,terminal_id,invitation_id) VALUES($1,$2,$3,$4,$5)',
      [randomUUID(), fixture.operator, member, terminal, assignment.invitation_id],
    ),
  ).rejects.toMatchObject({ code: '23505' });
});

it('mandatory audit failure rolls back revocation, versions and session invalidation', async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await lockPolicyRows(client, fixture.operator);
    await client.query(
      "CREATE FUNCTION public.synthetic_terminal_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'Synthetic audit fault'; END;$$",
    );
    await client.query(
      'CREATE TRIGGER synthetic_terminal_audit_fault BEFORE INSERT ON public.merchant_terminal_assignment_audit FOR EACH ROW EXECUTE FUNCTION public.synthetic_terminal_audit_fault()',
    );
    await expect(
      client.query(
        "UPDATE public.merchant_terminal_assignments SET revoked_at=statement_timestamp(),revocation_reason='withdrawn' WHERE membership_id=$1",
        [member],
      ),
    ).rejects.toThrow('Synthetic audit fault');
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
  expect((await read('/payments')).status).toBe(200);
  expect(
    (
      await pool.query(
        'SELECT authorization_version FROM public.dashboard_memberships WHERE id=$1',
        [member],
      )
    ).rows[0].authorization_version,
  ).toBe(scope.membershipVersion);
});

it.each(['disabled-sponsor', 'withdrawn-sponsor-delegation', 'revoked-factor'] as const)(
  'rejects %s without trusting invitation snapshots',
  async (change) => {
    if (change === 'disabled-sponsor')
      await policyQuery(
        pool,
        fixture.operator,
        "UPDATE public.dashboard_memberships SET status='disabled' WHERE id=$1",
        [fixture.member],
      );
    if (change === 'withdrawn-sponsor-delegation')
      await policyQuery(
        pool,
        fixture.operator,
        `UPDATE public.membership_permission_grants SET revoked_at=statement_timestamp(),revocation_reason='withdrawn',revocation_policy_version=(SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=$1) WHERE membership_id=$2 AND permission_code='client.permissions.delegate' AND revoked_at IS NULL`,
        [fixture.operator, fixture.member],
      );
    if (change === 'revoked-factor')
      await policyQuery(
        pool,
        fixture.operator,
        'UPDATE public.dashboard_passkeys SET revoked_at=statement_timestamp() WHERE user_id=$1',
        [user],
      );
    expect((await read('/payments')).status).toBe(503);
  },
);

it('row-lock-only runtime privileges do not confer terminal or assignment mutation authority', async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await lockPolicyRows(client, fixture.operator);
    await client.query('GRANT USAGE ON SCHEMA public TO vaultx_terminal_runtime');
    await client.query(
      'GRANT SELECT,UPDATE(id) ON public.merchant_terminals,public.merchant_terminal_assignments TO vaultx_terminal_runtime',
    );
    await client.query('SET LOCAL ROLE vaultx_terminal_runtime');
    expect(
      (
        await client.query(
          'SELECT id FROM public.merchant_terminal_assignments WHERE membership_id=$1 FOR SHARE',
          [member],
        )
      ).rowCount,
    ).toBe(1);
    expect(
      (
        await client.query('SELECT id FROM public.merchant_terminals WHERE id=$1 FOR SHARE', [
          terminal,
        ])
      ).rowCount,
    ).toBe(1);
    for (const sql of [
      'UPDATE public.merchant_terminals SET id=$2 WHERE id=$1',
      'UPDATE public.merchant_terminal_assignments SET id=$2 WHERE membership_id=$1',
    ]) {
      await client.query('SAVEPOINT denied');
      await expect(
        client.query(sql, [
          sql.includes('merchant_terminal_assignments') ? member : terminal,
          randomUUID(),
        ]),
      ).rejects.toMatchObject({ code: '42501' });
      await client.query('ROLLBACK TO SAVEPOINT denied');
    }
    await client.query('SAVEPOINT no_policy_write');
    await expect(
      client.query(
        "UPDATE public.merchant_terminal_assignments SET revoked_at=statement_timestamp(),revocation_reason='withdrawn' WHERE membership_id=$1",
        [member],
      ),
    ).rejects.toMatchObject({ code: '42501' });
    await client.query('ROLLBACK TO SAVEPOINT no_policy_write');
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
});

it('assignment-audit failure rolls back the entire invitation acceptance without activating a partial identity', async () => {
  const username = 'audit_rollback_' + randomUUID(),
    authenticator = syntheticAuthenticator(),
    session = randomBytes(32).toString('hex');
  const invitation = await policyTransaction(pool, fixture.operator, (c) =>
    createMerchantInvitation(c, {
      operatorId: fixture.operator,
      sponsorMembershipId: fixture.member,
      username,
      kind: 'submerchant',
      permissions: ['client.payments.read'],
      terminalIds: [terminal],
    }),
  );
  const token = await issueSyntheticInvitationToken(pool, invitation.invitationId);
  await pool.query('INSERT INTO public.dashboard_sessions(token_hash,csrf_hash) VALUES($1,$1)', [
    digest(session),
  ]);
  const options = await beginEnrollment(
    pool,
    digest(session),
    token,
    'Synthetic rollback enrollment password!',
    origin,
  );
  await pool.query('CREATE SEQUENCE public.synthetic_activation_fault_seen');
  await pool.query(
    "CREATE FUNCTION public.synthetic_activation_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM nextval('public.synthetic_activation_fault_seen'); RAISE EXCEPTION 'Synthetic activation audit fault'; END;$$",
  );
  await pool.query(
    'CREATE TRIGGER synthetic_activation_audit_fault BEFORE INSERT ON public.merchant_terminal_assignment_audit FOR EACH ROW EXECUTE FUNCTION public.synthetic_activation_audit_fault()',
  );
  try {
    await expect(
      finishEnrollment(
        pool,
        digest(session),
        authenticator.registration(options.challenge, origin),
        origin,
      ),
    ).rejects.toBeInstanceOf(ReadUnavailable);
    expect(
      (await pool.query('SELECT is_called FROM public.synthetic_activation_fault_seen')).rows[0]
        .is_called,
    ).toBe(true);
    expect(
      (await pool.query('SELECT id FROM public.dashboard_users WHERE username=$1', [username]))
        .rowCount,
    ).toBe(0);
    expect(
      (
        await pool.query(
          'SELECT consumed_at FROM public.merchant_invitation_tokens WHERE invitation_id=$1',
          [invitation.invitationId],
        )
      ).rows[0].consumed_at,
    ).toBeNull();
    expect(
      (
        await pool.query(
          "SELECT id FROM public.merchant_enrollment_audit WHERE invitation_id=$1 AND action='invitation.accepted'",
          [invitation.invitationId],
        )
      ).rowCount,
    ).toBe(0);
    expect(
      (
        await pool.query(
          'SELECT id FROM public.merchant_terminal_assignments WHERE invitation_id=$1',
          [invitation.invitationId],
        )
      ).rowCount,
    ).toBe(0);
  } finally {
    await pool.query(
      'DROP TRIGGER synthetic_activation_audit_fault ON public.merchant_terminal_assignment_audit',
    );
    await pool.query('DROP FUNCTION public.synthetic_activation_audit_fault()');
    await pool.query('DROP SEQUENCE public.synthetic_activation_fault_seen');
  }
});
