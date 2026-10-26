-- Viewer-only compatibility cutover. Apply with dashboard gates/ingress off.
CREATE TABLE public.access_permissions (
 code TEXT PRIMARY KEY CHECK (code IN ('client.account.self','client.payments.read','client.status.read')),
 realm TEXT NOT NULL CHECK (realm = 'client'),
 intrinsic BOOLEAN NOT NULL,
 UNIQUE(code, realm),
 CHECK (intrinsic = (code = 'client.account.self'))
);
INSERT INTO public.access_permissions VALUES
 ('client.account.self','client',true),('client.payments.read','client',false),('client.status.read','client',false);
CREATE TABLE public.operator_access_policies (
 operator_id UUID PRIMARY KEY REFERENCES public.operators(id) ON DELETE RESTRICT,
 authorization_version INTEGER NOT NULL DEFAULT 1 CHECK(authorization_version > 0),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE public.operator_permission_entitlements (
 operator_id UUID NOT NULL REFERENCES public.operator_access_policies(operator_id) ON DELETE RESTRICT,
 permission_code TEXT NOT NULL CHECK(permission_code IN ('client.payments.read','client.status.read')),
 realm TEXT NOT NULL DEFAULT 'client' CHECK(realm='client'),
 enabled BOOLEAN NOT NULL DEFAULT true,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(operator_id,permission_code),
 FOREIGN KEY(permission_code,realm) REFERENCES public.access_permissions(code,realm)
);
ALTER TABLE public.dashboard_memberships
 ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
 ADD COLUMN authorization_version INTEGER NOT NULL DEFAULT 1 CHECK(authorization_version > 0),
 ADD CONSTRAINT dashboard_membership_tenant UNIQUE(id,operator_id);
UPDATE public.dashboard_memberships m SET status='disabled'
 FROM public.dashboard_users u WHERE u.id=m.user_id AND u.status='disabled';
CREATE TABLE public.membership_permission_grants (
 id UUID PRIMARY KEY,
 membership_id UUID NOT NULL,
 operator_id UUID NOT NULL,
 permission_code TEXT NOT NULL CHECK(permission_code IN ('client.payments.read','client.status.read')),
 realm TEXT NOT NULL DEFAULT 'client' CHECK(realm='client'),
 source TEXT NOT NULL DEFAULT 'legacy_viewer' CHECK(source='legacy_viewer'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 revoked_at TIMESTAMPTZ,
 revocation_reason TEXT CHECK(revocation_reason IN ('cutover_ineligible','entitlement_withdrawn','membership_disabled','user_disabled','operator_suspended','withdrawn')),
 revocation_policy_version INTEGER CHECK(revocation_policy_version > 0),
 FOREIGN KEY(membership_id,operator_id) REFERENCES public.dashboard_memberships(id,operator_id) ON DELETE RESTRICT,
 FOREIGN KEY(permission_code,realm) REFERENCES public.access_permissions(code,realm),
 CHECK ((revoked_at IS NULL AND revocation_reason IS NULL AND revocation_policy_version IS NULL)
 OR (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL AND revocation_policy_version IS NOT NULL))
);
CREATE UNIQUE INDEX membership_active_permission ON public.membership_permission_grants(membership_id,permission_code) WHERE revoked_at IS NULL;
CREATE INDEX viewer_grants_operator ON public.membership_permission_grants(operator_id,membership_id);
INSERT INTO public.operator_access_policies(operator_id) SELECT id FROM public.operators;
INSERT INTO public.operator_permission_entitlements(operator_id,permission_code)
 SELECT o.id,p.code FROM public.operators o CROSS JOIN public.access_permissions p WHERE NOT p.intrinsic;
INSERT INTO public.membership_permission_grants(id,membership_id,operator_id,permission_code,revoked_at,revocation_reason,revocation_policy_version)
 SELECT pg_catalog.gen_random_uuid(),m.id,m.operator_id,p.code,
 CASE WHEN m.status='active' AND u.status='active' AND o.status='active' THEN NULL ELSE NOW() END,
 CASE WHEN m.status='active' AND u.status='active' AND o.status='active' THEN NULL ELSE 'cutover_ineligible' END,
 CASE WHEN m.status='active' AND u.status='active' AND o.status='active' THEN NULL ELSE 1 END
 FROM public.dashboard_memberships m JOIN public.dashboard_users u ON u.id=m.user_id
 JOIN public.operators o ON o.id=m.operator_id CROSS JOIN public.access_permissions p WHERE NOT p.intrinsic;
DELETE FROM public.dashboard_sessions WHERE user_id IS NOT NULL;
ALTER TABLE public.dashboard_sessions
 ADD COLUMN membership_authz_version INTEGER,
 ADD COLUMN operator_authz_version INTEGER,
 ADD CONSTRAINT dashboard_session_policy_shape CHECK(
 (user_id IS NULL AND membership_authz_version IS NULL AND operator_authz_version IS NULL) OR
 (user_id IS NOT NULL AND membership_authz_version IS NOT NULL AND membership_authz_version > 0
 AND operator_authz_version IS NOT NULL AND operator_authz_version > 0));

-- A transaction-scoped advisory pre-gate is observable by defensive triggers.
-- It supplements (does not replace) the tenant row gate. Triggers NEVER acquire
-- a gate after the UPDATE's target row lock. No caller-controlled GUC is trusted.
CREATE FUNCTION public.require_viewer_policy_gate(target UUID) RETURNS VOID LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE key BIGINT := pg_catalog.hashtextextended('vaultx.viewer.policy:' || target::text,0);
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_catalog.pg_backend_pid()
  AND locktype='advisory' AND granted AND mode='ExclusiveLock' AND objsubid=1
  AND classid=((key >> 32) & 4294967295)::oid AND objid=(key & 4294967295)::oid) THEN
  RAISE EXCEPTION 'Viewer policy mutation refused' USING ERRCODE='42501';
 END IF;
END; $$;
CREATE FUNCTION public.guard_viewer_grant() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.require_viewer_policy_gate(OLD.operator_id);
 IF (NEW.id,NEW.membership_id,NEW.operator_id,NEW.permission_code,NEW.realm,NEW.source,NEW.created_at)
  IS DISTINCT FROM (OLD.id,OLD.membership_id,OLD.operator_id,OLD.permission_code,OLD.realm,OLD.source,OLD.created_at)
  OR OLD.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'Viewer grant is immutable'; END IF;
 -- The sole UPDATE transition is complete, one-way revocation at this statement
 -- and the currently locked policy revision. No no-op or caller-chosen history.
 IF NEW.revoked_at IS DISTINCT FROM pg_catalog.statement_timestamp()
  OR NEW.revocation_reason IS NULL
  OR NEW.revocation_policy_version IS NULL
  OR NEW.revocation_policy_version IS DISTINCT FROM
   (SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=OLD.operator_id)
 THEN RAISE EXCEPTION 'Viewer revocation transition refused'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER viewer_grant_guard BEFORE UPDATE ON public.membership_permission_grants FOR EACH ROW EXECUTE FUNCTION public.guard_viewer_grant();
CREATE FUNCTION public.invalidate_viewer_grant() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
  UPDATE public.dashboard_memberships SET authorization_version=authorization_version+1 WHERE id=NEW.membership_id;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER viewer_grant_invalidation AFTER UPDATE ON public.membership_permission_grants FOR EACH ROW EXECUTE FUNCTION public.invalidate_viewer_grant();
CREATE OR REPLACE FUNCTION public.invalidate_dashboard_membership_sessions() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.require_viewer_policy_gate(OLD.operator_id);
 IF (NEW.id,NEW.user_id,NEW.operator_id,NEW.role) IS DISTINCT FROM (OLD.id,OLD.user_id,OLD.operator_id,OLD.role)
 THEN RAISE EXCEPTION 'Viewer membership identity is immutable'; END IF;
 IF NEW.authorization_version < OLD.authorization_version THEN RAISE EXCEPTION 'Viewer version cannot decrease'; END IF;
 IF NEW.status IS DISTINCT FROM OLD.status THEN
  NEW.authorization_version := OLD.authorization_version+1;
 END IF;
 DELETE FROM public.dashboard_sessions WHERE membership_id=OLD.id;
 RETURN NEW;
END; $$;
CREATE FUNCTION public.revoke_disabled_viewer_grants() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 UPDATE public.membership_permission_grants SET revoked_at=statement_timestamp(),revocation_reason='membership_disabled',
  revocation_policy_version=(SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=NEW.operator_id)
  WHERE membership_id=NEW.id AND revoked_at IS NULL;
 RETURN NEW;
END; $$;
CREATE TRIGGER viewer_membership_disable AFTER UPDATE ON public.dashboard_memberships FOR EACH ROW
 WHEN (NEW.status='disabled' AND OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION public.revoke_disabled_viewer_grants();
CREATE FUNCTION public.invalidate_viewer_entitlement() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE revision INTEGER;
BEGIN
 PERFORM public.require_viewer_policy_gate(OLD.operator_id);
 IF (NEW.operator_id,NEW.permission_code,NEW.realm) IS DISTINCT FROM (OLD.operator_id,OLD.permission_code,OLD.realm)
 THEN RAISE EXCEPTION 'Viewer entitlement identity is immutable'; END IF;
 IF NEW.enabled IS DISTINCT FROM OLD.enabled THEN
  UPDATE public.operator_access_policies SET authorization_version=authorization_version+1,updated_at=clock_timestamp()
   WHERE operator_id=OLD.operator_id RETURNING authorization_version INTO revision;
  IF revision IS NULL THEN RAISE EXCEPTION 'Viewer policy missing'; END IF;
  IF NOT NEW.enabled THEN
   UPDATE public.membership_permission_grants SET revoked_at=statement_timestamp(),revocation_reason='entitlement_withdrawn',revocation_policy_version=revision
    WHERE operator_id=OLD.operator_id AND permission_code=OLD.permission_code AND revoked_at IS NULL;
   UPDATE public.dashboard_memberships SET authorization_version=authorization_version+1 WHERE operator_id=OLD.operator_id;
  END IF;
  DELETE FROM public.dashboard_sessions WHERE membership_id IN(SELECT id FROM public.dashboard_memberships WHERE operator_id=OLD.operator_id);
  NEW.updated_at := clock_timestamp();
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER viewer_entitlement_invalidation BEFORE UPDATE ON public.operator_permission_entitlements FOR EACH ROW EXECUTE FUNCTION public.invalidate_viewer_entitlement();
CREATE OR REPLACE FUNCTION public.invalidate_dashboard_user_sessions() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE target UUID;
BEGIN
 IF (NEW.password_hash,NEW.status,NEW.auth_version) IS DISTINCT FROM (OLD.password_hash,OLD.status,OLD.auth_version) THEN
  SELECT operator_id INTO target FROM public.dashboard_memberships WHERE user_id=OLD.id;
  IF target IS NOT NULL THEN PERFORM public.require_viewer_policy_gate(target); END IF;
 END IF;
 IF NEW.auth_version < OLD.auth_version THEN RAISE EXCEPTION 'User version cannot decrease'; END IF;
 IF NEW.password_hash IS DISTINCT FROM OLD.password_hash OR NEW.status IS DISTINCT FROM OLD.status THEN
  NEW.auth_version := OLD.auth_version+1;
  IF NEW.status='disabled' THEN UPDATE public.dashboard_memberships SET status='disabled' WHERE user_id=OLD.id; END IF;
 END IF;
 IF NEW.auth_version IS DISTINCT FROM OLD.auth_version THEN DELETE FROM public.dashboard_sessions WHERE user_id=OLD.id; END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION public.invalidate_suspended_operator_sessions() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 -- Machine-only operators without human policy keep their existing lifecycle.
 IF NEW.status IS DISTINCT FROM OLD.status AND EXISTS(SELECT 1 FROM public.operator_access_policies WHERE operator_id=OLD.id) THEN
  PERFORM public.require_viewer_policy_gate(OLD.id);
  UPDATE public.operator_access_policies SET authorization_version=authorization_version+1,updated_at=clock_timestamp() WHERE operator_id=OLD.id;
  IF NEW.status='suspended' THEN
   UPDATE public.membership_permission_grants SET revoked_at=statement_timestamp(),revocation_reason='operator_suspended',
    revocation_policy_version=(SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=OLD.id)
    WHERE operator_id=OLD.id AND revoked_at IS NULL;
  END IF;
  DELETE FROM public.dashboard_sessions WHERE membership_id IN(SELECT id FROM public.dashboard_memberships WHERE operator_id=OLD.id);
 END IF;
 RETURN NEW;
END; $$;
-- No INSERT bootstrap triggers: later viewers/operators get no automatic rights.
REVOKE ALL ON public.access_permissions,public.operator_access_policies,public.operator_permission_entitlements,public.membership_permission_grants FROM PUBLIC;
-- PostgreSQL requires UPDATE privilege on a column for SELECT ... FOR SHARE.
-- A restricted reader can be granted UPDATE only on these immutable identity
-- columns: every actual UPDATE targeting them (including id=id) is rejected.
-- No runtime GRANT is installed here; restricted-role tests prove the recipe.
CREATE FUNCTION public.reject_viewer_identity_update() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'Viewer identity column cannot be updated' USING ERRCODE='42501';
END; $$;
CREATE TRIGGER viewer_user_identity BEFORE UPDATE OF id ON public.dashboard_users FOR EACH ROW EXECUTE FUNCTION public.reject_viewer_identity_update();
CREATE TRIGGER viewer_member_identity BEFORE UPDATE OF id,user_id,operator_id,role ON public.dashboard_memberships FOR EACH ROW EXECUTE FUNCTION public.reject_viewer_identity_update();
CREATE TRIGGER viewer_operator_identity BEFORE UPDATE OF id ON public.operators FOR EACH ROW EXECUTE FUNCTION public.reject_viewer_identity_update();
CREATE TRIGGER viewer_policy_identity BEFORE UPDATE OF operator_id ON public.operator_access_policies FOR EACH ROW EXECUTE FUNCTION public.reject_viewer_identity_update();
CREATE TRIGGER viewer_grant_identity BEFORE UPDATE OF id,membership_id,operator_id,permission_code,realm,source,created_at ON public.membership_permission_grants FOR EACH ROW EXECUTE FUNCTION public.reject_viewer_identity_update();
CREATE FUNCTION public.guard_viewer_policy_version() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.require_viewer_policy_gate(OLD.operator_id);
 IF NEW.authorization_version < OLD.authorization_version THEN RAISE EXCEPTION 'Viewer version cannot decrease'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER viewer_policy_version BEFORE UPDATE ON public.operator_access_policies FOR EACH ROW EXECUTE FUNCTION public.guard_viewer_policy_version();
