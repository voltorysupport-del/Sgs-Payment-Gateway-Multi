-- Development/test management foundation only. No owner or client account is seeded.
-- Enrollment/MFA/recovery ceremonies and production runtime-role rollout remain unapproved.
ALTER TABLE public.operators ADD COLUMN management_version INTEGER NOT NULL DEFAULT 1 CHECK(management_version>0);
CREATE FUNCTION public.advance_operator_management_version() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE metadata_changed BOOLEAN;
BEGIN
 metadata_changed := (NEW.name,NEW.status) IS DISTINCT FROM (OLD.name,OLD.status);
 IF metadata_changed OR NEW.management_version IS DISTINCT FROM OLD.management_version THEN
  -- The trigger is the sole canonicalizer: proposals are validated, never added
  -- to NEW. Both implicit metadata edits and explicit revision reservations
  -- require the preowned tenant gate, then persist exactly OLD+1.
  PERFORM public.require_viewer_policy_gate(OLD.id);
  IF NEW.management_version IS DISTINCT FROM OLD.management_version
   AND (NEW.management_version IS NULL OR NEW.management_version <> OLD.management_version+1)
  THEN RAISE EXCEPTION 'Management version refused' USING ERRCODE='42501'; END IF;
  NEW.management_version := OLD.management_version+1;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER operator_management_version BEFORE UPDATE ON public.operators FOR EACH ROW EXECUTE FUNCTION public.advance_operator_management_version();
-- Every actual ceiling withdrawal, including controlled maintenance, consumes
-- one operator revision. The HTTP service must only re-read that revision.
CREATE FUNCTION public.advance_withdrawal_management_version() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.require_viewer_policy_gate(NEW.operator_id);
 UPDATE public.operators SET management_version=management_version+1 WHERE id=NEW.operator_id;
 RETURN NEW;
END; $$;
CREATE TRIGGER entitlement_management_version AFTER UPDATE ON public.operator_permission_entitlements
 FOR EACH ROW WHEN (OLD.enabled AND NOT NEW.enabled) EXECUTE FUNCTION public.advance_withdrawal_management_version();
CREATE TABLE public.management_policy (
 id TEXT PRIMARY KEY CHECK(id='platform'),
 authorization_version INTEGER NOT NULL DEFAULT 1 CHECK(authorization_version>0)
);
INSERT INTO public.management_policy(id) VALUES('platform');
CREATE TABLE public.owner_permission_catalog (
 code TEXT PRIMARY KEY CHECK(code IN('platform.clients.read','platform.clients.manage','platform.audit.read')),
 realm TEXT NOT NULL DEFAULT 'owner' CHECK(realm='owner')
);
INSERT INTO public.owner_permission_catalog(code) VALUES('platform.clients.read'),('platform.clients.manage'),('platform.audit.read');
CREATE TABLE public.owner_principals (
 id UUID PRIMARY KEY,
 username TEXT NOT NULL UNIQUE CHECK(username ~ '^[a-z0-9][a-z0-9_.-]{2,79}$'),
 status TEXT NOT NULL DEFAULT 'disabled' CHECK(status IN('active','disabled')),
 enrollment_verified BOOLEAN NOT NULL DEFAULT false,
 authorization_version INTEGER NOT NULL DEFAULT 1 CHECK(authorization_version>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp()
);
-- No password, enrollment, MFA or recovery issuer exists in this milestone.
-- These are verified realm records for the default-off foundation, not proof that
-- a production custody ceremony has been implemented or approved.
CREATE TABLE public.owner_permission_grants (
 id UUID PRIMARY KEY,
 owner_id UUID NOT NULL REFERENCES public.owner_principals(id) ON DELETE RESTRICT,
 permission TEXT NOT NULL REFERENCES public.owner_permission_catalog(code) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
 revoked_at TIMESTAMPTZ,
 CHECK(revoked_at IS NULL OR revoked_at>=created_at)
);
CREATE UNIQUE INDEX owner_live_permission ON public.owner_permission_grants(owner_id,permission) WHERE revoked_at IS NULL;
CREATE TABLE public.owner_sessions (
 token_hash CHAR(64) PRIMARY KEY CHECK(token_hash ~ '^[a-f0-9]{64}$'),
 csrf_hash CHAR(64) NOT NULL CHECK(csrf_hash ~ '^[a-f0-9]{64}$'),
 owner_id UUID NOT NULL REFERENCES public.owner_principals(id) ON DELETE RESTRICT,
 assurance TEXT NOT NULL CHECK(assurance='mfa'),
 authorization_version INTEGER NOT NULL CHECK(authorization_version>0),
 policy_version INTEGER NOT NULL CHECK(policy_version>0),
 mfa_verified_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
 last_seen_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp()
);
CREATE INDEX owner_session_subject ON public.owner_sessions(owner_id);
CREATE TABLE public.management_audit (
 id UUID PRIMARY KEY,
 actor_id UUID NOT NULL REFERENCES public.owner_principals(id) ON DELETE RESTRICT,
 action TEXT NOT NULL CHECK(action IN('operators.list','operators.detail','operators.update','members.list','members.detail','entitlements.withdraw','audit.list')),
 operator_id UUID REFERENCES public.operators(id) ON DELETE RESTRICT,
 actor_version INTEGER NOT NULL CHECK(actor_version>0),
 owner_policy_version INTEGER NOT NULL CHECK(owner_policy_version>0),
 mfa_verified_at TIMESTAMPTZ NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome='success'),
 request_id TEXT NOT NULL CHECK(request_id ~ '^[A-Za-z0-9._:-]{1,80}$'),
 target_version INTEGER CHECK(target_version>0),
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
 summary JSONB NOT NULL CHECK(jsonb_typeof(summary)='object' AND octet_length(summary::text)<=2048
  AND summary - ARRAY['limit','offset','returned','nameChanged','status','permission','version','policyVersion']::text[] = '{}'::jsonb)
);
CREATE INDEX management_audit_order ON public.management_audit(occurred_at DESC,id DESC);
CREATE INDEX management_audit_tenant ON public.management_audit(operator_id,occurred_at DESC,id DESC);
CREATE FUNCTION public.reject_management_audit_rewrite() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN RAISE EXCEPTION 'Administrative audit is immutable' USING ERRCODE='42501'; END; $$;
CREATE TRIGGER management_audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON public.management_audit FOR EACH STATEMENT EXECUTE FUNCTION public.reject_management_audit_rewrite();
CREATE FUNCTION public.require_owner_policy_gate() RETURNS VOID LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE key BIGINT:=pg_catalog.hashtextextended('vaultx.owner.policy',0);
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory' AND granted AND mode='ExclusiveLock' AND objsubid=1
  AND classid=((key >> 32) & 4294967295)::oid AND objid=(key & 4294967295)::oid)
 THEN RAISE EXCEPTION 'Owner policy mutation refused' USING ERRCODE='42501'; END IF;
END; $$;
CREATE FUNCTION public.invalidate_owner_identity() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.require_owner_policy_gate();
 IF (NEW.id,NEW.username,NEW.created_at) IS DISTINCT FROM(OLD.id,OLD.username,OLD.created_at)
  OR NEW.authorization_version<OLD.authorization_version THEN RAISE EXCEPTION 'Owner identity is immutable'; END IF;
 IF (NEW.status,NEW.enrollment_verified) IS DISTINCT FROM(OLD.status,OLD.enrollment_verified) THEN NEW.authorization_version:=OLD.authorization_version+1; END IF;
 IF NEW.authorization_version IS DISTINCT FROM OLD.authorization_version THEN DELETE FROM public.owner_sessions WHERE owner_id=OLD.id; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER owner_identity_invalidation BEFORE UPDATE ON public.owner_principals FOR EACH ROW EXECUTE FUNCTION public.invalidate_owner_identity();
CREATE FUNCTION public.invalidate_owner_grant() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.require_owner_policy_gate();
 IF (NEW.id,NEW.owner_id,NEW.permission,NEW.created_at) IS DISTINCT FROM(OLD.id,OLD.owner_id,OLD.permission,OLD.created_at)
  OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS DISTINCT FROM statement_timestamp()
 THEN RAISE EXCEPTION 'Owner grant revocation refused'; END IF;
 UPDATE public.owner_principals SET authorization_version=authorization_version+1 WHERE id=OLD.owner_id;
 RETURN NEW;
END; $$;
CREATE TRIGGER owner_grant_invalidation BEFORE UPDATE ON public.owner_permission_grants FOR EACH ROW EXECUTE FUNCTION public.invalidate_owner_grant();
CREATE FUNCTION public.guard_owner_policy_version() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.require_owner_policy_gate();
 IF NEW.id IS DISTINCT FROM OLD.id OR NEW.authorization_version<=OLD.authorization_version THEN RAISE EXCEPTION 'Owner policy version refused'; END IF;
 DELETE FROM public.owner_sessions;
 RETURN NEW;
END; $$;
CREATE TRIGGER owner_policy_version BEFORE UPDATE ON public.management_policy FOR EACH ROW EXECUTE FUNCTION public.guard_owner_policy_version();
REVOKE ALL ON public.management_policy,public.owner_permission_catalog,public.owner_principals,public.owner_permission_grants,public.owner_sessions,public.management_audit FROM PUBLIC;
-- FOR SHARE needs UPDATE privilege; restricted readers may receive only immutable
-- identity columns, whose actual UPDATE statements always fail, even id=id.
CREATE FUNCTION public.reject_management_identity_update() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN RAISE EXCEPTION 'Management identity column cannot be updated' USING ERRCODE='42501'; END; $$;
CREATE TRIGGER owner_identity_columns BEFORE UPDATE OF id,username,created_at ON public.owner_principals FOR EACH ROW EXECUTE FUNCTION public.reject_management_identity_update();
CREATE TRIGGER owner_policy_identity BEFORE UPDATE OF id ON public.management_policy FOR EACH ROW EXECUTE FUNCTION public.reject_management_identity_update();
