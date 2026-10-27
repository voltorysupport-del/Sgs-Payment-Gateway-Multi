import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import { withReadClient } from '../db/read-client.js';
import { hashDashboardPassword } from '../dashboard/passwords.js';
import { lockViewerIdentity } from '../dashboard/permissions.js';
import { lockIntent, unavailable } from './policy.js';

export const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const random = () => randomBytes(32).toString('hex');
const transaction = <T>(pool: Pool, run: (client: PoolClient) => Promise<T>) =>
  withReadClient(pool, run, {
    readOnly: false,
    readCommitted: true,
    statementMs: 4000,
    lockMs: 1000,
    totalMs: 6000,
  });
function relyingParty(origin: string) {
  const u = new URL(origin);
  if (u.protocol !== 'https:' || u.origin !== origin || u.username || u.password)
    throw unavailable();
  return u.hostname; // Exact configured hostname; never a browser-selected RP or parent domain.
}
async function audit(
  client: PoolClient,
  operator: string,
  action: string,
  invitation: string | null,
  user: string | null,
) {
  await client.query(
    'INSERT INTO public.merchant_enrollment_audit(id,operator_id,action,invitation_id,user_id) VALUES($1,$2,$3,$4,$5)',
    [randomUUID(), operator, action, invitation, user],
  );
}
async function preauth(client: PoolClient, session: string) {
  if (
    !(
      await client.query(
        "SELECT token_hash FROM public.dashboard_sessions WHERE token_hash=$1 AND user_id IS NULL AND created_at>clock_timestamp()-interval '10 minutes' FOR UPDATE",
        [session],
      )
    ).rowCount
  )
    throw unavailable();
}
/** Deliberately no HTTP/CLI delivery surface. Independently guarded disposable
 * fixtures only; setting NODE_ENV alone cannot authorize enrollment issuance. */
export async function issueSyntheticInvitationToken(pool: Pool, invitation: string) {
  const raw = random();
  await transaction(pool, async (client) => {
    if (process.env.NODE_ENV !== 'test' || !process.env.TEST_DATABASE_TOKEN) throw unavailable();
    const guard = await client.query<{ safe: boolean }>(
      "SELECT current_database()='vaultx_pay_test' AND session_user='vaultx_test' AND EXISTS(SELECT 1 FROM vaultx_test_guard.identity WHERE token=$1) AS safe",
      [process.env.TEST_DATABASE_TOKEN],
    );
    if (!guard.rows[0]?.safe) throw unavailable();
    const policy = await lockIntent(client, invitation);
    await client.query(
      `INSERT INTO public.merchant_invitation_tokens(token_hash,invitation_id,policy_version,issuer_version,sponsor_grant_ids,expires_at)
      SELECT $1,id,$3,$4,$5,LEAST(expires_at,statement_timestamp()+interval '15 minutes') FROM public.merchant_invitations WHERE id=$2`,
      [digest(raw), invitation, policy.policyVersion, policy.issuerVersion, policy.grantIds],
    );
    await audit(client, policy.intent.operator_id, 'token.issued', invitation, null);
  });
  return raw; // Trusted synthetic caller only; never log, email or put into a URL.
}
interface TokenRow {
  invitation_id: string;
  policy_version: number;
  issuer_version: number;
  sponsor_grant_ids: string[];
}
async function liveToken(client: PoolClient, hash: string) {
  const row = (
    await client.query<TokenRow>(
      'SELECT * FROM public.merchant_invitation_tokens WHERE token_hash=$1',
      [hash],
    )
  ).rows[0];
  if (!row) throw unavailable();
  const policy = await lockIntent(client, row.invitation_id);
  const live = await client.query(
    `SELECT token_hash FROM public.merchant_invitation_tokens WHERE token_hash=$1 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE`,
    [hash],
  );
  if (
    !live.rowCount ||
    row.policy_version !== policy.policyVersion ||
    row.issuer_version !== policy.issuerVersion ||
    JSON.stringify(row.sponsor_grant_ids) !== JSON.stringify(policy.grantIds)
  )
    throw unavailable();
  return policy;
}
export async function revokeInvitationToken(pool: Pool, hash: string) {
  // Internal primitive only, not a caller-authorized management entry point.
  return transaction(pool, async (client) => {
    const policy = await liveToken(client, hash);
    await client.query(
      'UPDATE public.merchant_invitation_tokens SET revoked_at=statement_timestamp() WHERE token_hash=$1',
      [hash],
    );
    await audit(client, policy.intent.operator_id, 'token.revoked', policy.intent.id, null);
  });
}
export async function beginEnrollment(
  pool: Pool,
  session: string,
  raw: string,
  password: string,
  origin: string,
) {
  const rpID = relyingParty(origin),
    user = randomUUID();
  const options = await generateRegistrationOptions({
    rpName: 'VaultX Pay',
    rpID,
    userName: 'Invited VaultX Pay user',
    userID: Buffer.from(user),
    attestationType: 'none',
    supportedAlgorithmIDs: [-7],
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    timeout: 300000,
  });
  // Argon2 is outside policy locks and bounded by HTTP admission.
  const passwordHash = await hashDashboardPassword(password);
  await transaction(pool, async (client) => {
    await liveToken(client, digest(raw));
    await preauth(client, session);
    await client.query(
      `INSERT INTO public.dashboard_webauthn_challenges(challenge_hash,session_hash,invitation_token_hash,user_id,password_hash)
      VALUES($1,$2,$3,$4,$5)`,
      [digest(options.challenge), session, digest(raw), user, passwordHash],
    );
  });
  return options;
}
function responseChallenge(response: RegistrationResponseJSON | AuthenticationResponseJSON) {
  try {
    const decoded: unknown = JSON.parse(
      Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8'),
    );
    if (
      !decoded ||
      typeof decoded !== 'object' ||
      !('challenge' in decoded) ||
      typeof decoded.challenge !== 'string' ||
      decoded.challenge.length > 256 ||
      ('crossOrigin' in decoded && decoded.crossOrigin !== false) ||
      'topOrigin' in decoded
    )
      throw unavailable();
    return decoded.challenge;
  } catch {
    throw unavailable();
  }
}
export async function finishEnrollment(
  pool: Pool,
  session: string,
  response: RegistrationResponseJSON,
  origin: string,
) {
  const challenge = digest(responseChallenge(response));
  const registration = await verifyRegistrationResponse({
    response,
    expectedChallenge: (c) => digest(c) === challenge,
    expectedOrigin: origin,
    expectedRPID: relyingParty(origin),
    requireUserVerification: true,
    supportedAlgorithmIDs: [-7],
  });
  if (!registration.verified || !registration.registrationInfo?.userVerified) throw unavailable();
  const credential = registration.registrationInfo.credential;
  await transaction(pool, async (client) => {
    const candidate = (
      await client.query<{ invitation_token_hash: string }>(
        'SELECT invitation_token_hash FROM public.dashboard_webauthn_challenges WHERE challenge_hash=$1 AND session_hash=$2',
        [challenge, session],
      )
    ).rows[0];
    if (!candidate?.invitation_token_hash) throw unavailable();
    const { intent, memberCount } = await liveToken(client, candidate.invitation_token_hash);
    // Preserve the existing 1,000-member management bound. The exclusive tenant
    // gate makes this reservation atomic with all other acceptance transactions.
    if (memberCount >= 1000) throw unavailable();
    await preauth(client, session);
    const ceremony = (
      await client.query<{ user_id: string; password_hash: string }>(
        `DELETE FROM public.dashboard_webauthn_challenges WHERE challenge_hash=$1 AND session_hash=$2 AND expires_at>clock_timestamp() RETURNING user_id,password_hash`,
        [challenge, session],
      )
    ).rows[0];
    if (!ceremony) throw unavailable();
    const member = randomUUID();
    await client.query(
      'INSERT INTO public.dashboard_users(id,username,password_hash) VALUES($1,$2,$3)',
      [ceremony.user_id, intent.username, ceremony.password_hash],
    );
    await client.query(
      'INSERT INTO public.dashboard_memberships(id,user_id,operator_id) VALUES($1,$2,$3)',
      [member, ceremony.user_id, intent.operator_id],
    );
    await client.query(
      'INSERT INTO public.merchant_member_profiles(membership_id,operator_id,kind,owner_issuer_id,sponsor_membership_id) VALUES($1,$2,$3,$4,$5)',
      [
        member,
        intent.operator_id,
        intent.kind,
        intent.owner_issuer_id,
        intent.sponsor_membership_id,
      ],
    );
    for (const permission of intent.permissions) {
      const sponsor = intent.sponsor_membership_id
        ? (
            await client.query<{ id: string }>(
              'SELECT id FROM public.membership_permission_grants WHERE membership_id=$1 AND operator_id=$2 AND permission_code=$3 AND revoked_at IS NULL',
              [intent.sponsor_membership_id, intent.operator_id, permission],
            )
          ).rows[0]?.id
        : null;
      await client.query(
        'INSERT INTO public.membership_permission_grants(id,membership_id,operator_id,permission_code,source,issuer_owner_id,sponsor_grant_id) VALUES($1,$2,$3,$4,$5,$6,$7)',
        [
          randomUUID(),
          member,
          intent.operator_id,
          permission,
          intent.kind === 'merchant_admin' ? 'owner_bootstrap' : 'merchant_delegation',
          intent.owner_issuer_id,
          sponsor,
        ],
      );
    }
    await client.query(
      'INSERT INTO public.dashboard_passkeys(credential_id,user_id,public_key,counter) VALUES($1,$2,$3,$4)',
      [credential.id, ceremony.user_id, Buffer.from(credential.publicKey), credential.counter],
    );
    // No session is issued from registration. Password + fresh UV assertion is
    // required through existing login and the authentication endpoints below.
    await client.query(
      'UPDATE public.merchant_invitation_tokens SET consumed_at=statement_timestamp() WHERE token_hash=$1',
      [candidate.invitation_token_hash],
    );
    await client.query('DELETE FROM public.dashboard_sessions WHERE token_hash=$1', [session]);
    await audit(client, intent.operator_id, 'invitation.accepted', intent.id, ceremony.user_id);
  });
}
interface SessionIdentity {
  user_id: string;
  membership_id: string;
  operator_id: string;
  auth_version: number;
}
async function lockPasswordSession(client: PoolClient, session: string) {
  const candidate = (
    await client.query<SessionIdentity>(
      'SELECT s.user_id,s.membership_id,m.operator_id,s.auth_version FROM public.dashboard_sessions s JOIN public.dashboard_memberships m ON m.id=s.membership_id AND m.user_id=s.user_id WHERE s.token_hash=$1',
      [session],
    )
  ).rows[0];
  if (!candidate) throw unavailable();
  // Exclusive gate prevents a factor/user/grant mutation from committing while
  // checking and updating a passkey counter + rotating the session.
  await client.query(
    "SELECT pg_advisory_xact_lock(hashtextextended('vaultx.viewer.policy:' || $1::text,0))",
    [candidate.operator_id],
  );
  const identity = await lockViewerIdentity(
    client,
    candidate.user_id,
    candidate.membership_id,
    candidate.operator_id,
  );
  if (!identity) throw unavailable();
  // User lock comes before membership/session locks. Factor changes must follow
  // the same tenant gate, so the shared identity locks do not race factor mutation.
  const live = await client.query(
    `SELECT token_hash FROM public.dashboard_sessions WHERE token_hash=$1 AND auth_version=$2 AND auth_version=$3 AND membership_authz_version=$4 AND operator_authz_version=$5
    AND created_at<=clock_timestamp() AND last_seen_at<=clock_timestamp()
    AND created_at>clock_timestamp()-interval '8 hours' AND last_seen_at>clock_timestamp()-interval '30 minutes' FOR UPDATE`,
    [
      session,
      candidate.auth_version,
      identity.user.auth_version,
      identity.membershipVersion,
      identity.operatorVersion,
    ],
  );
  if (!live.rowCount) throw unavailable();
  return candidate;
}
export async function beginAuthentication(pool: Pool, session: string, origin: string) {
  const rpID = relyingParty(origin);
  return transaction(pool, async (client) => {
    const user = await lockPasswordSession(client, session);
    const keys = await client.query<{ credential_id: string }>(
      'SELECT credential_id FROM public.dashboard_passkeys WHERE user_id=$1 AND revoked_at IS NULL ORDER BY credential_id LIMIT 10',
      [user.user_id],
    );
    if (!keys.rowCount) throw unavailable();
    const options = await generateAuthenticationOptions({
      rpID,
      timeout: 300000,
      userVerification: 'required',
      allowCredentials: keys.rows.map((k) => ({ id: k.credential_id })),
    });
    await client.query(
      'INSERT INTO public.dashboard_webauthn_challenges(challenge_hash,session_hash,user_id,auth_version) VALUES($1,$2,$3,$4)',
      [digest(options.challenge), session, user.user_id, user.auth_version],
    );
    return options;
  });
}
export async function finishAuthentication(
  pool: Pool,
  session: string,
  response: AuthenticationResponseJSON,
  origin: string,
) {
  const challenge = digest(responseChallenge(response));
  // Verify bounded crypto outside locks against the session-bound owned key.
  const key = (
    await withReadClient(pool, (client) =>
      client.query<{ user_id: string; public_key: Buffer; counter: string }>(
        `SELECT k.user_id,k.public_key,k.counter FROM public.dashboard_passkeys k
    JOIN public.dashboard_sessions s ON s.user_id=k.user_id JOIN public.dashboard_webauthn_challenges c ON c.session_hash=s.token_hash AND c.user_id=k.user_id
    WHERE s.token_hash=$1 AND c.challenge_hash=$2 AND c.invitation_token_hash IS NULL AND c.expires_at>clock_timestamp() AND k.credential_id=$3 AND k.revoked_at IS NULL`,
        [session, challenge, response.id],
      ),
    )
  ).rows[0];
  if (
    !key ||
    (response.response.userHandle &&
      response.response.userHandle !== Buffer.from(key.user_id).toString('base64url'))
  )
    throw unavailable();
  const verified = await verifyAuthenticationResponse({
    response,
    expectedChallenge: (c) => digest(c) === challenge,
    expectedOrigin: origin,
    expectedRPID: relyingParty(origin),
    requireUserVerification: true,
    credential: {
      id: response.id,
      publicKey: new Uint8Array(key.public_key),
      counter: Number(key.counter),
    },
  });
  if (!verified.verified || !verified.authenticationInfo.userVerified) throw unavailable();
  const token = random(),
    csrf = random();
  await transaction(pool, async (client) => {
    const user = await lockPasswordSession(client, session);
    const consumed = await client.query(
      `DELETE FROM public.dashboard_webauthn_challenges WHERE challenge_hash=$1 AND session_hash=$2 AND user_id=$3 AND auth_version=$4 AND invitation_token_hash IS NULL AND expires_at>clock_timestamp() RETURNING challenge_hash`,
      [challenge, session, user.user_id, user.auth_version],
    );
    if (!consumed.rowCount || user.user_id !== key.user_id) throw unavailable();
    const updated = await client.query(
      'UPDATE public.dashboard_passkeys SET counter=$4 WHERE credential_id=$1 AND user_id=$2 AND revoked_at IS NULL AND counter=$3 RETURNING credential_id',
      [response.id, user.user_id, key.counter, verified.authenticationInfo.newCounter],
    );
    if (!updated.rowCount) throw unavailable();
    // Preserve original password login absolute deadline: MFA never extends it.
    await client.query(
      `INSERT INTO public.dashboard_sessions(token_hash,csrf_hash,user_id,membership_id,auth_version,membership_authz_version,operator_authz_version,created_at,webauthn_credential_id,webauthn_verified_at)
      SELECT $2,$3,user_id,membership_id,auth_version,membership_authz_version,operator_authz_version,created_at,$4,clock_timestamp() FROM public.dashboard_sessions WHERE token_hash=$1`,
      [session, digest(token), digest(csrf), response.id],
    );
    await client.query('DELETE FROM public.dashboard_sessions WHERE token_hash=$1', [session]);
    await audit(client, user.operator_id, 'passkey.authenticated', null, user.user_id);
  });
  return { token, csrf };
}
