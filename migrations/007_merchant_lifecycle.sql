-- Additive lifecycle intent foundation. No account, session, API key or grant is
-- seeded; invitations cannot authenticate and have no delivery/activation issuer.
ALTER TABLE public.owner_permission_catalog DROP CONSTRAINT owner_permission_catalog_code_check;
ALTER TABLE public.owner_permission_catalog ADD CHECK(code IN
 ('platform.clients.read','platform.clients.manage','platform.audit.read','platform.clients.bootstrap_admin'));
INSERT INTO public.owner_permission_catalog(code) VALUES('platform.clients.bootstrap_admin');
CREATE TABLE public.merchant_member_profiles (
 membership_id UUID PRIMARY KEY,
 operator_id UUID NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('merchant_admin','submerchant')),
 owner_issuer_id UUID REFERENCES public.owner_principals(id) ON DELETE RESTRICT,
 sponsor_membership_id UUID,
 created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
 UNIQUE(membership_id,operator_id),
 FOREIGN KEY(membership_id,operator_id) REFERENCES public.dashboard_memberships(id,operator_id) ON DELETE RESTRICT,
 FOREIGN KEY(sponsor_membership_id,operator_id) REFERENCES public.merchant_member_profiles(membership_id,operator_id) ON DELETE RESTRICT,
 CHECK((kind='merchant_admin' AND owner_issuer_id IS NOT NULL AND sponsor_membership_id IS NULL)
    OR (kind='submerchant' AND owner_issuer_id IS NULL AND sponsor_membership_id IS NOT NULL)),
 CHECK(sponsor_membership_id IS DISTINCT FROM membership_id)
);
CREATE TABLE public.merchant_terminals (
 id UUID PRIMARY KEY,
 operator_id UUID NOT NULL REFERENCES public.operators(id) ON DELETE RESTRICT,
 code TEXT NOT NULL CHECK(code ~ '^[a-z0-9][a-z0-9_-]{2,63}$'),
 name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 120),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN('active','suspended')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
 UNIQUE(id,operator_id), UNIQUE(operator_id,code)
);
CREATE TABLE public.merchant_invitations (
 id UUID PRIMARY KEY,
 operator_id UUID NOT NULL REFERENCES public.operators(id) ON DELETE RESTRICT,
 username TEXT NOT NULL CHECK(username ~ '^[a-z0-9][a-z0-9_.-]{2,79}$'),
 kind TEXT NOT NULL CHECK(kind IN('merchant_admin','submerchant')),
 owner_issuer_id UUID REFERENCES public.owner_principals(id) ON DELETE RESTRICT,
 sponsor_membership_id UUID,
 permissions TEXT[] NOT NULL,
 terminal_ids UUID[] NOT NULL DEFAULT '{}',
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'),
 created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp()+interval '24 hours',
 revoked_at TIMESTAMPTZ,
 FOREIGN KEY(sponsor_membership_id,operator_id) REFERENCES public.merchant_member_profiles(membership_id,operator_id) ON DELETE RESTRICT,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '24 hours'),
 CHECK(revoked_at IS NULL OR revoked_at>=created_at),
 CHECK((kind='merchant_admin' AND owner_issuer_id IS NOT NULL AND sponsor_membership_id IS NULL
  AND permissions <@ ARRAY['client.users.read','client.users.manage_subaccounts','client.permissions.delegate','client.terminals.read','client.audit.read','client.payments.read','client.status.read']::text[])
 OR(kind='submerchant' AND owner_issuer_id IS NULL AND sponsor_membership_id IS NOT NULL
  AND permissions <@ ARRAY['client.payments.read','client.status.read']::text[])),
 CHECK(cardinality(permissions) BETWEEN 1 AND 10 AND cardinality(terminal_ids)<=100)
);
CREATE UNIQUE INDEX merchant_pending_invitation ON public.merchant_invitations(operator_id,username) WHERE revoked_at IS NULL;
-- These tables carry immutable authority intent, not a replacement session realm.
CREATE FUNCTION public.guard_merchant_authority() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE sponsor public.merchant_member_profiles;
BEGIN
 PERFORM public.require_viewer_policy_gate(NEW.operator_id);
 IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'Merchant authority is immutable' USING ERRCODE='42501'; END IF;
 IF TG_TABLE_NAME='merchant_invitations' THEN
  IF EXISTS(SELECT 1 FROM pg_catalog.unnest(NEW.permissions) permission WHERE NOT EXISTS(SELECT 1 FROM public.operator_permission_entitlements e JOIN public.operators o ON o.id=e.operator_id AND o.status='active' WHERE e.operator_id=NEW.operator_id AND e.permission_code=permission AND e.enabled))
   OR EXISTS(SELECT 1 FROM pg_catalog.unnest(NEW.terminal_ids) terminal WHERE NOT EXISTS(SELECT 1 FROM public.merchant_terminals t WHERE t.operator_id=NEW.operator_id AND t.id=terminal AND t.status='active'))
  THEN RAISE EXCEPTION 'Invitation ceiling refused' USING ERRCODE='42501'; END IF;
 END IF;
 IF NEW.sponsor_membership_id IS NOT NULL THEN
  SELECT p.* INTO sponsor FROM public.merchant_member_profiles p
   JOIN public.dashboard_memberships m ON m.id=p.membership_id AND m.operator_id=p.operator_id AND m.status='active'
   JOIN public.dashboard_users u ON u.id=m.user_id AND u.status='active'
   JOIN public.operators o ON o.id=m.operator_id AND o.status='active'
   WHERE p.membership_id=NEW.sponsor_membership_id AND p.operator_id=NEW.operator_id;
  IF sponsor.kind IS DISTINCT FROM 'merchant_admin' OR NOT EXISTS(SELECT 1 FROM public.membership_permission_grants g JOIN public.operator_permission_entitlements e ON e.operator_id=g.operator_id AND e.permission_code=g.permission_code AND e.enabled WHERE g.membership_id=NEW.sponsor_membership_id AND g.operator_id=NEW.operator_id AND g.permission_code='client.users.manage_subaccounts' AND g.revoked_at IS NULL)
  THEN RAISE EXCEPTION 'Merchant sponsor refused' USING ERRCODE='42501'; END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER merchant_profile_guard BEFORE INSERT OR UPDATE ON public.merchant_member_profiles FOR EACH ROW EXECUTE FUNCTION public.guard_merchant_authority();
CREATE TRIGGER merchant_invitation_guard BEFORE INSERT OR UPDATE ON public.merchant_invitations FOR EACH ROW EXECUTE FUNCTION public.guard_merchant_authority();
CREATE FUNCTION public.reject_merchant_history_delete() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN RAISE EXCEPTION 'Merchant history is immutable' USING ERRCODE='42501'; END; $$;
CREATE TRIGGER merchant_profile_history BEFORE DELETE OR TRUNCATE ON public.merchant_member_profiles FOR EACH STATEMENT EXECUTE FUNCTION public.reject_merchant_history_delete();
CREATE TRIGGER merchant_invitation_history BEFORE DELETE OR TRUNCATE ON public.merchant_invitations FOR EACH STATEMENT EXECUTE FUNCTION public.reject_merchant_history_delete();
REVOKE ALL ON public.merchant_member_profiles,public.merchant_terminals,public.merchant_invitations FROM PUBLIC;

-- Canonical client authority remains the existing catalog/entitlement/grant model.
ALTER TABLE public.access_permissions DROP CONSTRAINT access_permissions_code_check;
ALTER TABLE public.access_permissions ADD CHECK(code IN('client.account.self','client.payments.read','client.status.read','client.users.read','client.users.manage_subaccounts','client.permissions.delegate','client.audit.read','client.terminals.read'));
INSERT INTO public.access_permissions VALUES ('client.users.read','client',false),('client.users.manage_subaccounts','client',false),('client.permissions.delegate','client',false),('client.audit.read','client',false),('client.terminals.read','client',false);
ALTER TABLE public.operator_permission_entitlements DROP CONSTRAINT operator_permission_entitlements_permission_code_check;
ALTER TABLE public.operator_permission_entitlements ADD CHECK(permission_code IN('client.payments.read','client.status.read','client.users.read','client.users.manage_subaccounts','client.permissions.delegate','client.audit.read','client.terminals.read'));
ALTER TABLE public.membership_permission_grants DROP CONSTRAINT membership_permission_grants_permission_code_check;
ALTER TABLE public.membership_permission_grants ADD CHECK(permission_code IN('client.payments.read','client.status.read','client.users.read','client.users.manage_subaccounts','client.permissions.delegate','client.audit.read','client.terminals.read'));
ALTER TABLE public.membership_permission_grants DROP CONSTRAINT membership_permission_grants_source_check;
ALTER TABLE public.membership_permission_grants ADD COLUMN issuer_owner_id UUID REFERENCES public.owner_principals(id) ON DELETE RESTRICT,
 ADD COLUMN sponsor_grant_id UUID REFERENCES public.membership_permission_grants(id) ON DELETE RESTRICT,
 ADD CHECK((source='legacy_viewer' AND issuer_owner_id IS NULL AND sponsor_grant_id IS NULL)
 OR(source='owner_bootstrap' AND issuer_owner_id IS NOT NULL AND sponsor_grant_id IS NULL)
 OR(source='merchant_delegation' AND issuer_owner_id IS NULL AND sponsor_grant_id IS NOT NULL));
CREATE TRIGGER merchant_grant_provenance_identity BEFORE UPDATE OF issuer_owner_id,sponsor_grant_id ON public.membership_permission_grants FOR EACH ROW EXECUTE FUNCTION public.reject_viewer_identity_update();
CREATE FUNCTION public.guard_merchant_grant_insert() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE profile public.merchant_member_profiles; sponsor public.membership_permission_grants;
BEGIN
 -- Existing fixture/migration provenance remains compatible for exactly old read codes.
 -- Restricted runtime roles still have no INSERT privilege.
 IF NEW.source='legacy_viewer' THEN
  IF NEW.permission_code NOT IN('client.payments.read','client.status.read') THEN RAISE EXCEPTION 'Legacy privilege expansion refused' USING ERRCODE='42501'; END IF;
  RETURN NEW;
 END IF;
 PERFORM public.require_viewer_policy_gate(NEW.operator_id);
 SELECT * INTO profile FROM public.merchant_member_profiles WHERE membership_id=NEW.membership_id AND operator_id=NEW.operator_id;
 IF profile.membership_id IS NULL OR NOT EXISTS(SELECT 1 FROM public.operator_permission_entitlements WHERE operator_id=NEW.operator_id AND permission_code=NEW.permission_code AND enabled)
 THEN RAISE EXCEPTION 'Grant ceiling refused' USING ERRCODE='42501'; END IF;
 IF NEW.source='owner_bootstrap' THEN
  IF profile.kind<>'merchant_admin' OR profile.owner_issuer_id IS DISTINCT FROM NEW.issuer_owner_id
   OR NOT EXISTS(SELECT 1 FROM public.owner_principals p JOIN public.owner_permission_grants g ON g.owner_id=p.id
    WHERE p.id=NEW.issuer_owner_id AND p.status='active' AND p.enrollment_verified AND g.permission='platform.clients.bootstrap_admin' AND g.revoked_at IS NULL)
  THEN RAISE EXCEPTION 'Root provenance refused' USING ERRCODE='42501'; END IF;
 ELSE
  SELECT * INTO sponsor FROM public.membership_permission_grants WHERE id=NEW.sponsor_grant_id;
  IF profile.kind<>'submerchant' OR sponsor.membership_id IS DISTINCT FROM profile.sponsor_membership_id
    OR sponsor.operator_id IS DISTINCT FROM NEW.operator_id OR sponsor.permission_code IS DISTINCT FROM NEW.permission_code
    OR sponsor.revoked_at IS NOT NULL OR NEW.permission_code NOT IN('client.payments.read','client.status.read')
    OR NOT EXISTS(SELECT 1 FROM public.membership_permission_grants g WHERE g.membership_id=profile.sponsor_membership_id
      AND g.operator_id=NEW.operator_id AND g.permission_code='client.permissions.delegate' AND g.revoked_at IS NULL)
  THEN RAISE EXCEPTION 'Delegation ceiling refused' USING ERRCODE='42501'; END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER merchant_grant_insert BEFORE INSERT ON public.membership_permission_grants FOR EACH ROW EXECUTE FUNCTION public.guard_merchant_grant_insert();
CREATE FUNCTION public.revoke_merchant_dependents() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 UPDATE public.membership_permission_grants SET revoked_at=statement_timestamp(),revocation_reason='withdrawn',
  revocation_policy_version=(SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=NEW.operator_id)
  WHERE operator_id=NEW.operator_id AND revoked_at IS NULL AND
   (sponsor_grant_id=NEW.id OR (NEW.permission_code IN('client.permissions.delegate','client.users.manage_subaccounts')
    AND membership_id IN(SELECT membership_id FROM public.merchant_member_profiles WHERE sponsor_membership_id=NEW.membership_id AND operator_id=NEW.operator_id)));
 RETURN NEW;
END; $$;
CREATE TRIGGER merchant_dependent_revocation AFTER UPDATE ON public.membership_permission_grants FOR EACH ROW WHEN(OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL) EXECUTE FUNCTION public.revoke_merchant_dependents();
ALTER TABLE public.management_audit DROP CONSTRAINT management_audit_action_check;
ALTER TABLE public.management_audit ADD CHECK(action IN('operators.list','operators.detail','operators.update','members.list','members.detail','entitlements.withdraw','audit.list','operators.create','invitations.create_admin'));
CREATE TABLE public.merchant_audit (
 id UUID PRIMARY KEY,
 actor_membership_id UUID NOT NULL,
 operator_id UUID NOT NULL,
 action TEXT NOT NULL CHECK(action IN('members.list','terminals.list','audit.list','invitations.create','members.disable','grants.withdraw')),
 actor_version INTEGER NOT NULL CHECK(actor_version>0),
 request_id TEXT NOT NULL CHECK(request_id ~ '^[A-Za-z0-9._:-]{1,80}$'),
 target_membership_id UUID,
 target_version INTEGER CHECK(target_version>0),
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
 summary JSONB NOT NULL CHECK(jsonb_typeof(summary)='object' AND octet_length(summary::text)<=2048
  AND summary - ARRAY['returned','limit','offset','permission','revoked','kind','version']::text[] = '{}'::jsonb),
 FOREIGN KEY(actor_membership_id,operator_id) REFERENCES public.dashboard_memberships(id,operator_id) ON DELETE RESTRICT,
 FOREIGN KEY(target_membership_id,operator_id) REFERENCES public.dashboard_memberships(id,operator_id) ON DELETE RESTRICT
);
CREATE INDEX merchant_audit_order ON public.merchant_audit(operator_id,occurred_at DESC,id DESC);
CREATE TRIGGER merchant_audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON public.merchant_audit FOR EACH STATEMENT EXECUTE FUNCTION public.reject_management_audit_rewrite();
REVOKE ALL ON public.merchant_audit FROM PUBLIC;
CREATE FUNCTION public.invalidate_merchant_grant_issuance() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 UPDATE public.dashboard_memberships SET authorization_version=authorization_version+1 WHERE id=NEW.membership_id AND operator_id=NEW.operator_id;
 RETURN NEW;
END; $$;
CREATE TRIGGER merchant_grant_issuance AFTER INSERT ON public.membership_permission_grants FOR EACH ROW WHEN(NEW.source<>'legacy_viewer') EXECUTE FUNCTION public.invalidate_merchant_grant_issuance();
ALTER TABLE public.management_audit DROP CONSTRAINT management_audit_summary_check;
ALTER TABLE public.management_audit ADD CHECK(jsonb_typeof(summary)='object' AND octet_length(summary::text)<=2048
 AND summary - ARRAY['limit','offset','returned','nameChanged','status','permission','version','policyVersion','invitationId','kind']::text[] = '{}'::jsonb);
ALTER TABLE public.merchant_audit DROP CONSTRAINT merchant_audit_summary_check;
ALTER TABLE public.merchant_audit ADD CHECK(jsonb_typeof(summary)='object' AND octet_length(summary::text)<=2048
 AND summary - ARRAY['returned','limit','offset','permission','revoked','kind','version','invitationId']::text[] = '{}'::jsonb);
