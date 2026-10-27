import { randomBytes, randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { beforeAll, afterAll, beforeEach, afterEach, it, expect } from 'vitest';
import request from 'supertest';
import { runMigrations } from '../../src/db/migrate.js';
import { createMerchantInvitation } from '../../src/management/merchant-domain.js';
import { executeMerchantCommand } from '../../src/management/merchant-session.js';
import { touchDashboardSession } from '../../src/dashboard/sessions.js';
import { createApp } from '../../src/app.js';
import {
  issueSyntheticInvitationToken,
  beginEnrollment,
  finishEnrollment,
  beginAuthentication,
  finishAuthentication,
  revokeInvitationToken,
  digest,
} from '../../src/enrollment/service.js';
import { openTestDatabase } from '../test-database.js';
import { policyTransaction, insertViewerSession } from '../viewer-policy-fixtures.js';
import {
  createMerchantBrowserFixture,
  cleanupMerchantBrowserFixture,
} from '../merchant-browser-fixture.js';
import { syntheticAuthenticator } from '../webauthn-authenticator.js';
import { testConfig, captureLogger } from '../helpers.js';
let pool: Pool, fixture: Awaited<ReturnType<typeof createMerchantBrowserFixture>>;
const origin = 'https://dashboard.example.invalid',
  password = 'Synthetic only enrollment password!';
beforeAll(async () => {
  pool = await openTestDatabase();
  await runMigrations(pool);
});
afterAll(async () => {
  await pool.end();
});
beforeEach(async () => {
  fixture = await createMerchantBrowserFixture(pool);
});
afterEach(async () => {
  await cleanupMerchantBrowserFixture(pool, fixture);
  await pool.query('DELETE FROM public.dashboard_sessions WHERE user_id IS NULL');
  await pool.query('DELETE FROM public.dashboard_login_limits');
});
async function intent(
  kind: 'merchant_admin' | 'submerchant' = 'merchant_admin',
  terminals: string[] = [],
) {
  return policyTransaction(pool, fixture.operator, (c) =>
    createMerchantInvitation(c, {
      operatorId: fixture.operator,
      username: 'invited_' + randomUUID(),
      kind,
      permissions:
        kind === 'merchant_admin'
          ? [
              'client.users.read',
              'client.users.manage_subaccounts',
              'client.permissions.delegate',
              'client.status.read',
            ]
          : ['client.status.read'],
      terminalIds: terminals,
      ...(kind === 'merchant_admin'
        ? { ownerId: fixture.owner.id }
        : { sponsorMembershipId: fixture.member }),
    }),
  );
}
async function preauth() {
  const session = randomBytes(32).toString('hex');
  await pool.query('INSERT INTO dashboard_sessions(token_hash,csrf_hash) VALUES($1,$2)', [
    digest(session),
    digest(session),
  ]);
  return digest(session);
}
async function started(kind: 'merchant_admin' | 'submerchant' = 'merchant_admin') {
  const invitation = await intent(kind),
    raw = await issueSyntheticInvitationToken(pool, invitation.invitationId),
    session = await preauth(),
    key = syntheticAuthenticator();
  const options = await beginEnrollment(pool, session, raw, password, origin);
  return {
    invitation,
    raw,
    session,
    key,
    options,
    response: key.registration(options.challenge, origin),
  };
}
async function accepted(kind: 'merchant_admin' | 'submerchant' = 'merchant_admin') {
  const a = await started(kind);
  await finishEnrollment(pool, a.session, a.response, origin);
  const user = (
    await pool.query<{ id: string }>(
      'SELECT user_id AS id FROM dashboard_passkeys WHERE credential_id=$1',
      [a.key.id],
    )
  ).rows[0]!.id;
  const session = randomBytes(32).toString('hex');
  await insertViewerSession(pool, user, digest(session), digest(session));
  return { ...a, user, login: digest(session) };
}
it('creates no identity before verified registration; registration grants no session; password-only privilege denied', async () => {
  const a = await started();
  expect(
    (await pool.query('SELECT user_id FROM dashboard_passkeys WHERE credential_id=$1', [a.key.id]))
      .rowCount,
  ).toBe(0);
  await finishEnrollment(pool, a.session, a.response, origin);
  expect(
    (await pool.query('SELECT token_hash FROM dashboard_sessions WHERE token_hash=$1', [a.session]))
      .rowCount,
  ).toBe(0);
  const user = (
    await pool.query('SELECT user_id FROM dashboard_passkeys WHERE credential_id=$1', [a.key.id])
  ).rows[0].user_id;
  const hash = digest(randomUUID());
  await insertViewerSession(pool, user, hash, hash);
  expect(await executeMerchantCommand(pool, hash, { action: 'identity' })).toEqual({
    ok: false,
    error: 'unauthorized',
  });
  expect((await touchDashboardSession(pool, hash, 'client.status.read'))?.permissionAllowed).toBe(
    false,
  );
  await expect(finishEnrollment(pool, a.session, a.response, origin)).rejects.toThrow();
});
it('verifies signed UV authentication, rotates session, consumes challenge, and preserves subject/operator', async () => {
  const a = await accepted(),
    options = await beginAuthentication(pool, a.login, origin);
  const response = a.key.assertion(options.challenge, origin, a.user);
  const result = await finishAuthentication(pool, a.login, response, origin);
  expect(
    (await touchDashboardSession(pool, digest(result.token), 'client.status.read'))
      ?.permissionAllowed,
  ).toBe(true);
  expect(
    (await executeMerchantCommand(pool, digest(result.token), { action: 'identity' })).ok,
  ).toBe(true);
  expect(await touchDashboardSession(pool, a.login)).toBeUndefined();
  await expect(finishAuthentication(pool, a.login, response, origin)).rejects.toThrow();
  expect(
    (
      await pool.query<{ action: string }>(
        'SELECT action FROM merchant_enrollment_audit WHERE operator_id=$1 ORDER BY occurred_at',
        [fixture.operator],
      )
    ).rows.map((r) => r.action),
  ).toEqual(['token.issued', 'invitation.accepted', 'passkey.authenticated']);
});
it.each(['origin', 'rp', 'uv', 'challenge'] as const)(
  'rejects registration with incorrect %s without creating identity',
  async (mode) => {
    const a = await started();
    const response = a.key.registration(
      mode === 'challenge' ? 'unissued' : a.options.challenge,
      mode === 'origin' ? 'https://other.invalid' : origin,
      mode === 'rp' ? 'other.invalid' : new URL(origin).hostname,
      mode !== 'uv',
    );
    await expect(finishEnrollment(pool, a.session, response, origin)).rejects.toThrow();
    expect(
      (
        await pool.query('SELECT credential_id FROM dashboard_passkeys WHERE credential_id=$1', [
          a.key.id,
        ])
      ).rowCount,
    ).toBe(0);
  },
);
it.each(['origin', 'rp', 'uv', 'ownership'] as const)(
  'rejects signed authentication with incorrect %s',
  async (mode) => {
    const a = await accepted(),
      options = await beginAuthentication(pool, a.login, origin);
    const response = a.key.assertion(
      options.challenge,
      mode === 'origin' ? 'https://other.invalid' : origin,
      mode === 'ownership' ? randomUUID() : a.user,
      1,
      mode === 'rp' ? 'other.invalid' : new URL(origin).hostname,
      mode !== 'uv',
    );
    await expect(finishAuthentication(pool, a.login, response, origin)).rejects.toThrow();
    expect(
      (await touchDashboardSession(pool, a.login, 'client.status.read'))?.permissionAllowed,
    ).toBe(false);
  },
);
it('allows exactly one concurrent acceptance and one concurrent authentication', async () => {
  const a = await started();
  const outcomes = await Promise.allSettled([
    finishEnrollment(pool, a.session, a.response, origin),
    finishEnrollment(pool, a.session, a.response, origin),
  ]);
  expect(outcomes.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  const user = (
      await pool.query('SELECT user_id FROM dashboard_passkeys WHERE credential_id=$1', [a.key.id])
    ).rows[0].user_id,
    session = digest(randomUUID());
  await insertViewerSession(pool, user, session, session);
  const options = await beginAuthentication(pool, session, origin),
    response = a.key.assertion(options.challenge, origin, user);
  const auth = await Promise.allSettled([
    finishAuthentication(pool, session, response, origin),
    finishAuthentication(pool, session, response, origin),
  ]);
  expect(auth.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
});
it('revocation is permanent and prevents acceptance without changing immutable intent', async () => {
  const a = await started();
  await revokeInvitationToken(pool, digest(a.raw));
  await expect(finishEnrollment(pool, a.session, a.response, origin)).rejects.toThrow();
  await expect(
    policyTransaction(pool, fixture.operator, (c) =>
      c.query('UPDATE merchant_invitation_tokens SET revoked_at=NULL WHERE token_hash=$1', [
        digest(a.raw),
      ]),
    ),
  ).rejects.toThrow();
  expect(
    (
      await pool.query('SELECT status FROM merchant_invitations WHERE id=$1', [
        a.invitation.invitationId,
      ])
    ).rows[0].status,
  ).toBe('pending');
});
it('expired tokens and expired challenges cannot activate users', async () => {
  const invitation = await intent(),
    raw = randomBytes(32).toString('hex');
  await policyTransaction(pool, fixture.operator, (c) =>
    c.query(
      `INSERT INTO merchant_invitation_tokens(token_hash,invitation_id,policy_version,issuer_version,created_at,expires_at) VALUES($1,$2,(SELECT authorization_version FROM operator_access_policies WHERE operator_id=$3),(SELECT authorization_version FROM owner_principals WHERE id=$4),statement_timestamp()-interval '16 minutes',statement_timestamp()-interval '1 minute')`,
      [digest(raw), invitation.invitationId, fixture.operator, fixture.owner.id],
    ),
  );
  await expect(beginEnrollment(pool, await preauth(), raw, password, origin)).rejects.toThrow();
  const a = await started();
  await pool.query(
    "UPDATE dashboard_webauthn_challenges SET created_at=clock_timestamp()-interval '6 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE session_hash=$1",
    [a.session],
  );
  await expect(finishEnrollment(pool, a.session, a.response, origin)).rejects.toThrow();
});
it('rechecks live sponsor authority and never restores an invitation after revoked grants are replaced', async () => {
  const a = await started('submerchant');
  await policyTransaction(pool, fixture.operator, (c) =>
    c.query(
      "UPDATE membership_permission_grants SET revoked_at=statement_timestamp(),revocation_reason='withdrawn',revocation_policy_version=(SELECT authorization_version FROM operator_access_policies WHERE operator_id=$1) WHERE membership_id=$2 AND permission_code='client.status.read' AND revoked_at IS NULL",
      [fixture.operator, fixture.member],
    ),
  );
  await policyTransaction(pool, fixture.operator, (c) =>
    c.query(
      "INSERT INTO membership_permission_grants(id,membership_id,operator_id,permission_code,source,issuer_owner_id) VALUES($1,$2,$3,'client.status.read','owner_bootstrap',$4)",
      [randomUUID(), fixture.member, fixture.operator, fixture.owner.id],
    ),
  );
  await expect(finishEnrollment(pool, a.session, a.response, origin)).rejects.toThrow();
});
it('factor revocation invalidates authenticated and password-only sessions and pending assertions', async () => {
  const a = await accepted(),
    options = await beginAuthentication(pool, a.login, origin);
  const result = await finishAuthentication(
    pool,
    a.login,
    a.key.assertion(options.challenge, origin, a.user),
    origin,
  );
  await policyTransaction(pool, fixture.operator, (c) =>
    c.query(
      'UPDATE dashboard_passkeys SET revoked_at=statement_timestamp() WHERE credential_id=$1',
      [a.key.id],
    ),
  );
  expect(await touchDashboardSession(pool, digest(result.token))).toBeUndefined();
  await expect(beginAuthentication(pool, digest(result.token), origin)).rejects.toThrow();
  expect(
    (
      await pool.query(
        'SELECT challenge_hash FROM dashboard_webauthn_challenges WHERE user_id=$1',
        [a.user],
      )
    ).rowCount,
  ).toBe(0);
});
it('binds enrollment to its preauth session; preserves submerchant payment denial', async () => {
  const a = await started('submerchant');
  await expect(finishEnrollment(pool, await preauth(), a.response, origin)).rejects.toThrow();
  await finishEnrollment(pool, a.session, a.response, origin);
  const user = (
      await pool.query('SELECT user_id FROM dashboard_passkeys WHERE credential_id=$1', [a.key.id])
    ).rows[0].user_id,
    session = digest(randomUUID());
  await insertViewerSession(pool, user, session, session);
  const options = await beginAuthentication(pool, session, origin),
    result = await finishAuthentication(
      pool,
      session,
      a.key.assertion(options.challenge, origin, user),
      origin,
    );
  expect(
    (await touchDashboardSession(pool, digest(result.token), 'client.payments.read'))
      ?.permissionAllowed,
  ).toBe(false);
});
it('refuses browser tenant/RP authority and wrong Origin with generic secret-free errors', async () => {
  const logs = captureLogger(),
    app = createApp({
      pool,
      logger: logs.logger,
      config: testConfig({
        DASHBOARD_ENABLED: 'true',
        MERCHANT_MANAGEMENT_ENABLED: 'true',
        PHASE3_ENROLLMENT_ENABLED: 'true',
        DASHBOARD_PUBLIC_ORIGIN: origin,
      }),
    });
  const bad = await request(app)
    .post('/dashboard-api/auth/passkeys/enrollment/options')
    .set('Origin', 'https://other.invalid')
    .send({ operatorId: fixture.operator, invitationToken: 'PRIVATE_SENTINEL' });
  expect(bad.status).toBe(403);
  expect(JSON.stringify(bad.body)).not.toMatch(/PRIVATE_SENTINEL|operator|invitationToken/);
});

it('refuses owner disablement and permanent ceiling withdrawal', async () => {
  const a = await started('submerchant');
  await policyTransaction(pool, fixture.operator, (c) =>
    c.query(
      "UPDATE operator_permission_entitlements SET enabled=false WHERE operator_id=$1 AND permission_code='client.status.read'",
      [fixture.operator],
    ),
  );
  await policyTransaction(pool, fixture.operator, (c) =>
    c.query(
      "UPDATE operator_permission_entitlements SET enabled=true WHERE operator_id=$1 AND permission_code='client.status.read'",
      [fixture.operator],
    ),
  );
  await expect(finishEnrollment(pool, a.session, a.response, origin)).rejects.toThrow();
  const own = await started();
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    await c.query("SELECT pg_advisory_xact_lock(hashtextextended('vaultx.owner.policy',0))");
    await c.query("UPDATE owner_principals SET status='disabled' WHERE id=$1", [fixture.owner.id]);
    await c.query('COMMIT');
  } finally {
    c.release();
  }
  await expect(finishEnrollment(pool, own.session, own.response, origin)).rejects.toThrow();
});
it('rejects foreign-terminal intent and terminal-restricted administrator activation; rechecks terminal suspension', async () => {
  await expect(intent('submerchant', [randomUUID()])).rejects.toThrow();
  const terminal = (
    await pool.query<{ id: string }>('SELECT id FROM merchant_terminals WHERE operator_id=$1', [
      fixture.operator,
    ])
  ).rows[0]!.id;
  const admin = await intent('merchant_admin', [terminal]);
  await expect(issueSyntheticInvitationToken(pool, admin.invitationId)).rejects.toThrow();
  const child = await intent('submerchant', [terminal]),
    raw = await issueSyntheticInvitationToken(pool, child.invitationId),
    session = await preauth(),
    key = syntheticAuthenticator();
  const options = await beginEnrollment(pool, session, raw, password, origin);
  await policyTransaction(pool, fixture.operator, (c) =>
    c.query("UPDATE merchant_terminals SET status='suspended' WHERE id=$1", [terminal]),
  );
  await expect(
    finishEnrollment(pool, session, key.registration(options.challenge, origin), origin),
  ).rejects.toThrow();
});
it('blocks a stale in-flight assertion after privilege withdrawal and factor addition', async () => {
  const a = await accepted(),
    options = await beginAuthentication(pool, a.login, origin),
    response = a.key.assertion(options.challenge, origin, a.user);
  const added = syntheticAuthenticator();
  await policyTransaction(pool, fixture.operator, (c) =>
    c.query(
      'INSERT INTO dashboard_passkeys(credential_id,user_id,public_key,counter) VALUES($1,$2,$3,0)',
      [added.id, a.user, added.publicKey],
    ),
  );
  await expect(finishAuthentication(pool, a.login, response, origin)).rejects.toThrow();
  expect(await touchDashboardSession(pool, a.login)).toBeUndefined();
});
it('exposes no account or tenant details through invalid invitation HTTP responses or logs', async () => {
  const logs = captureLogger(),
    app = createApp({
      pool,
      logger: logs.logger,
      config: testConfig({
        DASHBOARD_ENABLED: 'true',
        MERCHANT_MANAGEMENT_ENABLED: 'true',
        PHASE3_ENROLLMENT_ENABLED: 'true',
        DASHBOARD_PUBLIC_ORIGIN: origin,
      }),
    });
  const pre = await request(app).get('/dashboard-api/auth/csrf').set('Origin', origin);
  const cookie = (pre.headers['set-cookie'] as unknown as string[])[0]!.split(';')[0]!;
  const raw = randomBytes(32).toString('hex');
  const result = await request(app)
    .post('/dashboard-api/auth/passkeys/enrollment/options')
    .set('Cookie', cookie)
    .set('Origin', origin)
    .set('x-csrf-token', pre.body.csrfToken as string)
    .send({ invitationToken: raw, password });
  expect(result.status).toBe(400);
  expect(result.body).toMatchObject({
    error: { code: 'invalid_request', message: 'Unable to complete authentication.' },
  });
  expect(logs.output()).not.toContain(raw);
  expect(JSON.stringify(result.body)).not.toContain(fixture.operator);
});

/** Observe PostgreSQL's actual wait state; no arbitrary sleep determines order. */
async function waitForTenantWaiters(count: number) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const result = await pool.query<{ count: string }>(
      `SELECT count(*) FROM pg_catalog.pg_locks WHERE locktype='advisory' AND NOT granted AND objsubid=1
      AND classid=((hashtextextended('vaultx.viewer.policy:' || $1::text,0)>>32)&4294967295)::oid
      AND objid=(hashtextextended('vaultx.viewer.policy:' || $1::text,0)&4294967295)::oid`,
      [fixture.operator],
    );
    if (Number(result.rows[0]!.count) === count) return;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error('Expected policy lock barrier was not reached.');
}
it('serializes two acceptors at an explicit policy barrier and commits exactly once', async () => {
  const a = await started(),
    blocker = await pool.connect();
  let outcomes: Promise<PromiseSettledResult<void>[]> | undefined;
  try {
    await blocker.query('BEGIN');
    await blocker.query(
      "SELECT pg_advisory_xact_lock(hashtextextended('vaultx.viewer.policy:' || $1::text,0))",
      [fixture.operator],
    );
    outcomes = Promise.allSettled([
      finishEnrollment(pool, a.session, a.response, origin),
      finishEnrollment(pool, a.session, a.response, origin),
    ]);
    await waitForTenantWaiters(2);
    await blocker.query('COMMIT');
    expect((await outcomes).filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  } finally {
    await blocker.query('ROLLBACK');
    blocker.release();
    await outcomes;
  }
  expect(
    (
      await pool.query(
        "SELECT id FROM merchant_enrollment_audit WHERE invitation_id=$1 AND action='invitation.accepted'",
        [a.invitation.invitationId],
      )
    ).rowCount,
  ).toBe(1);
});
it('withdrawal at the policy barrier wins over an already verified registration', async () => {
  const a = await started('submerchant'),
    blocker = await pool.connect();
  let outcome: Promise<PromiseSettledResult<void>[]> | undefined;
  try {
    await blocker.query('BEGIN');
    await blocker.query(
      "SELECT pg_advisory_xact_lock(hashtextextended('vaultx.viewer.policy:' || $1::text,0))",
      [fixture.operator],
    );
    outcome = Promise.allSettled([finishEnrollment(pool, a.session, a.response, origin)]);
    await waitForTenantWaiters(1);
    await blocker.query(
      "UPDATE membership_permission_grants SET revoked_at=statement_timestamp(),revocation_reason='withdrawn',revocation_policy_version=(SELECT authorization_version FROM operator_access_policies WHERE operator_id=$1) WHERE membership_id=$2 AND permission_code='client.status.read' AND revoked_at IS NULL",
      [fixture.operator, fixture.member],
    );
    await blocker.query('COMMIT');
    expect((await outcome)[0]!.status).toBe('rejected');
  } finally {
    await blocker.query('ROLLBACK');
    blocker.release();
    await outcome;
  }
  expect(
    (await pool.query('SELECT user_id FROM dashboard_passkeys WHERE credential_id=$1', [a.key.id]))
      .rowCount,
  ).toBe(0);
});
it('tenant suspension prevents activation and existing privileged session use', async () => {
  const a = await started();
  await policyTransaction(pool, fixture.operator, (c) =>
    c.query("UPDATE operators SET status='suspended' WHERE id=$1", [fixture.operator]),
  );
  await expect(finishEnrollment(pool, a.session, a.response, origin)).rejects.toThrow();
  expect(
    (await executeMerchantCommand(pool, digest(fixture.token), { action: 'identity' })).ok,
  ).toBe(false);
});
it('restricted viewer roles cannot mint, consume or revoke enrollment authority or rewrite audit', async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET LOCAL ROLE vaultx_viewer_runtime');
    for (const table of [
      'merchant_invitation_tokens',
      'dashboard_passkeys',
      'dashboard_webauthn_challenges',
      'merchant_enrollment_audit',
    ]) {
      await client.query('SAVEPOINT denied');
      await expect(client.query(`DELETE FROM public.${table}`)).rejects.toMatchObject({
        code: '42501',
      });
      await client.query('ROLLBACK TO SAVEPOINT denied');
    }
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
});
it('cannot use an authenticated foreign-tenant session to consume an enrollment ceremony', async () => {
  const a = await started(),
    foreign = await createMerchantBrowserFixture(pool);
  try {
    await expect(
      finishEnrollment(pool, digest(foreign.token), a.response, origin),
    ).rejects.toThrow();
    expect(
      (
        await pool.query('SELECT credential_id FROM dashboard_passkeys WHERE credential_id=$1', [
          a.key.id,
        ])
      ).rowCount,
    ).toBe(0);
    expect(
      (
        await pool.query('SELECT consumed_at FROM merchant_invitation_tokens WHERE token_hash=$1', [
          digest(a.raw),
        ])
      ).rows[0].consumed_at,
    ).toBeNull();
    await finishEnrollment(pool, a.session, a.response, origin);
    const row = (
      await pool.query<{ operator_id: string }>(
        `SELECT m.operator_id FROM dashboard_passkeys k JOIN dashboard_memberships m ON m.user_id=k.user_id WHERE k.credential_id=$1`,
        [a.key.id],
      )
    ).rows[0]!;
    expect(row.operator_id).toBe(fixture.operator);
    expect(row.operator_id).not.toBe(foreign.operator);
  } finally {
    await cleanupMerchantBrowserFixture(pool, foreign);
  }
});
