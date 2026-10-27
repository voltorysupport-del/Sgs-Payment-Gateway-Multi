-- Additive, default-off synthetic enrollment. Existing intent/history is untouched.
CREATE TABLE public.merchant_invitation_tokens (
 token_hash CHAR(64) PRIMARY KEY CHECK(token_hash ~ '^[a-f0-9]{64}$'),
 invitation_id UUID NOT NULL UNIQUE REFERENCES public.merchant_invitations(id) ON DELETE RESTRICT,
 policy_version INTEGER NOT NULL CHECK(policy_version>0),
 issuer_version INTEGER NOT NULL CHECK(issuer_version>0),
 sponsor_grant_ids UUID[] NOT NULL DEFAULT '{}',
 created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp()+interval '15 minutes',
 consumed_at TIMESTAMPTZ,
 revoked_at TIMESTAMPTZ,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '15 minutes'),
 CHECK(consumed_at IS NULL OR revoked_at IS NULL)
);
CREATE FUNCTION public.guard_invitation_token() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE tenant UUID;
BEGIN
 SELECT operator_id INTO tenant FROM public.merchant_invitations WHERE id=NEW.invitation_id;
 PERFORM public.require_viewer_policy_gate(tenant);
 IF TG_OP='UPDATE' AND ((NEW.token_hash,NEW.invitation_id,NEW.policy_version,NEW.issuer_version,NEW.sponsor_grant_ids,NEW.created_at,NEW.expires_at)
 IS DISTINCT FROM (OLD.token_hash,OLD.invitation_id,OLD.policy_version,OLD.issuer_version,OLD.sponsor_grant_ids,OLD.created_at,OLD.expires_at)
 OR OLD.consumed_at IS NOT NULL OR OLD.revoked_at IS NOT NULL
 OR NOT ((NEW.consumed_at IS NOT NULL AND NEW.consumed_at=statement_timestamp() AND NEW.revoked_at IS NULL)
      OR (NEW.revoked_at IS NOT NULL AND NEW.revoked_at=statement_timestamp() AND NEW.consumed_at IS NULL)))
 THEN RAISE EXCEPTION 'Invitation transition refused' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER invitation_token_guard BEFORE INSERT OR UPDATE ON public.merchant_invitation_tokens FOR EACH ROW EXECUTE FUNCTION public.guard_invitation_token();
CREATE TRIGGER invitation_token_history BEFORE DELETE OR TRUNCATE ON public.merchant_invitation_tokens FOR EACH STATEMENT EXECUTE FUNCTION public.reject_merchant_history_delete();

CREATE TABLE public.dashboard_passkeys (
 credential_id TEXT PRIMARY KEY CHECK(length(credential_id) BETWEEN 1 AND 1400 AND credential_id ~ '^[A-Za-z0-9_-]+$'),
 user_id UUID NOT NULL REFERENCES public.dashboard_users(id) ON DELETE RESTRICT,
 public_key BYTEA NOT NULL CHECK(octet_length(public_key) BETWEEN 32 AND 4096),
 counter BIGINT NOT NULL CHECK(counter>=0 AND counter<=4294967295),
 created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
 revoked_at TIMESTAMPTZ
);
CREATE INDEX dashboard_passkey_user ON public.dashboard_passkeys(user_id);
ALTER TABLE public.dashboard_sessions ADD COLUMN webauthn_credential_id TEXT REFERENCES public.dashboard_passkeys(credential_id) ON DELETE RESTRICT,
 ADD COLUMN webauthn_verified_at TIMESTAMPTZ,
 ADD CHECK((webauthn_credential_id IS NULL)=(webauthn_verified_at IS NULL)),
 ADD CHECK(webauthn_verified_at IS NULL OR (user_id IS NOT NULL AND webauthn_verified_at>=created_at));
-- Assurance is attached only after verification, with the user's existing auth_version.
-- A factor insertion/revocation advances that same version and invalidates sessions.
CREATE FUNCTION public.guard_dashboard_passkey() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE tenant UUID;
BEGIN
 SELECT operator_id INTO tenant FROM public.dashboard_memberships WHERE user_id=NEW.user_id;
 IF tenant IS NULL THEN RAISE EXCEPTION 'Passkey subject refused'; END IF;
 PERFORM public.require_viewer_policy_gate(tenant);
 IF TG_OP='UPDATE' THEN
  IF (NEW.credential_id,NEW.user_id,NEW.public_key,NEW.created_at) IS DISTINCT FROM (OLD.credential_id,OLD.user_id,OLD.public_key,OLD.created_at)
   OR OLD.revoked_at IS NOT NULL OR NEW.counter<OLD.counter
   OR (NEW.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM statement_timestamp() OR NEW.counter<>OLD.counter))
  THEN RAISE EXCEPTION 'Passkey transition refused' USING ERRCODE='42501'; END IF;
 END IF;
 IF TG_OP='INSERT' OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
  UPDATE public.dashboard_users SET auth_version=auth_version+1 WHERE id=NEW.user_id;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER dashboard_passkey_guard BEFORE INSERT OR UPDATE ON public.dashboard_passkeys FOR EACH ROW EXECUTE FUNCTION public.guard_dashboard_passkey();
CREATE TRIGGER dashboard_passkey_history BEFORE DELETE OR TRUNCATE ON public.dashboard_passkeys FOR EACH STATEMENT EXECUTE FUNCTION public.reject_merchant_history_delete();
CREATE FUNCTION public.dashboard_session_has_webauthn(s public.dashboard_sessions) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT s.webauthn_verified_at IS NOT NULL AND s.webauthn_verified_at>=s.created_at
 AND s.webauthn_verified_at<=clock_timestamp() AND EXISTS(
 SELECT 1 FROM public.dashboard_passkeys k JOIN public.dashboard_users u ON u.id=k.user_id
 WHERE k.credential_id=s.webauthn_credential_id AND k.user_id=s.user_id AND k.revoked_at IS NULL AND u.auth_version=s.auth_version)
$$;
CREATE TABLE public.dashboard_webauthn_challenges (
 challenge_hash CHAR(64) PRIMARY KEY CHECK(challenge_hash ~ '^[a-f0-9]{64}$'),
 session_hash CHAR(64) NOT NULL UNIQUE REFERENCES public.dashboard_sessions(token_hash) ON DELETE CASCADE,
 invitation_token_hash CHAR(64) REFERENCES public.merchant_invitation_tokens(token_hash) ON DELETE RESTRICT,
 user_id UUID NOT NULL,
 password_hash TEXT,
 auth_version INTEGER,
 created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp()+interval '5 minutes',
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
 CHECK((invitation_token_hash IS NOT NULL AND password_hash IS NOT NULL AND auth_version IS NULL)
 OR(invitation_token_hash IS NULL AND password_hash IS NULL AND auth_version IS NOT NULL))
);
CREATE INDEX dashboard_challenge_expiry ON public.dashboard_webauthn_challenges(expires_at);
CREATE TABLE public.merchant_enrollment_audit (
 id UUID PRIMARY KEY,
 invitation_id UUID REFERENCES public.merchant_invitations(id) ON DELETE RESTRICT,
 operator_id UUID NOT NULL REFERENCES public.operators(id) ON DELETE RESTRICT,
 user_id UUID REFERENCES public.dashboard_users(id) ON DELETE RESTRICT,
 action TEXT NOT NULL CHECK(action IN('token.issued','token.revoked','invitation.accepted','passkey.authenticated')),
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp()
);
CREATE TRIGGER merchant_enrollment_audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON public.merchant_enrollment_audit FOR EACH STATEMENT EXECUTE FUNCTION public.reject_management_audit_rewrite();
REVOKE ALL ON public.merchant_invitation_tokens,public.dashboard_passkeys,public.dashboard_webauthn_challenges,public.merchant_enrollment_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION public.dashboard_session_has_webauthn(public.dashboard_sessions) FROM PUBLIC;
