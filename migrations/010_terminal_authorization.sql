SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='60s';
CREATE UNIQUE INDEX merchant_invitation_accepted_once ON public.merchant_enrollment_audit(invitation_id) WHERE action='invitation.accepted';
-- No inference/backfill: only a newly consumed, authorized invitation can assign.
CREATE TABLE public.merchant_terminal_assignments (
 id UUID PRIMARY KEY,
 operator_id UUID NOT NULL,
 membership_id UUID NOT NULL,
 terminal_id UUID NOT NULL,
 invitation_id UUID NOT NULL REFERENCES public.merchant_invitations(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
 revoked_at TIMESTAMPTZ,
 revocation_reason TEXT CHECK(revocation_reason IN('terminal_suspended','membership_disabled','grant_revoked','withdrawn')),
 UNIQUE(membership_id,terminal_id),
 FOREIGN KEY(membership_id,operator_id) REFERENCES public.merchant_member_profiles(membership_id,operator_id) ON DELETE RESTRICT,
 FOREIGN KEY(terminal_id,operator_id) REFERENCES public.merchant_terminals(id,operator_id) ON DELETE RESTRICT,
 CHECK((revoked_at IS NULL AND revocation_reason IS NULL) OR
       (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL AND revoked_at>=created_at))
);
CREATE INDEX merchant_terminal_assignment_scope ON public.merchant_terminal_assignments(operator_id,membership_id,terminal_id) WHERE revoked_at IS NULL;
CREATE TABLE public.merchant_terminal_assignment_audit (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 assignment_id UUID NOT NULL REFERENCES public.merchant_terminal_assignments(id) ON DELETE RESTRICT,
 operator_id UUID NOT NULL REFERENCES public.operators(id) ON DELETE RESTRICT,
 action TEXT NOT NULL CHECK(action IN('assigned','revoked')),
 reason TEXT,
 membership_version INTEGER NOT NULL CHECK(membership_version>0),
 policy_version INTEGER NOT NULL CHECK(policy_version>0),
 database_actor NAME NOT NULL DEFAULT session_user,
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp()
);
REVOKE ALL ON public.merchant_terminal_assignments,public.merchant_terminal_assignment_audit FROM PUBLIC;
CREATE TRIGGER terminal_assignment_audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON public.merchant_terminal_assignment_audit
 FOR EACH STATEMENT EXECUTE FUNCTION public.reject_management_audit_rewrite();
CREATE TRIGGER terminal_assignment_history BEFORE DELETE OR TRUNCATE ON public.merchant_terminal_assignments
 FOR EACH STATEMENT EXECUTE FUNCTION public.reject_merchant_history_delete();
CREATE FUNCTION public.guard_terminal_assignment() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.require_viewer_policy_gate(NEW.operator_id);
 IF TG_OP='UPDATE' THEN
  IF (NEW.id,NEW.operator_id,NEW.membership_id,NEW.terminal_id,NEW.invitation_id,NEW.created_at)
    IS DISTINCT FROM (OLD.id,OLD.operator_id,OLD.membership_id,OLD.terminal_id,OLD.invitation_id,OLD.created_at)
    OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS DISTINCT FROM statement_timestamp()
    OR NEW.revocation_reason IS NULL THEN
   RAISE EXCEPTION 'Assignment transition refused' USING ERRCODE='42501';
  END IF;
 ELSE
  IF NEW.revoked_at IS NOT NULL OR NEW.revocation_reason IS NOT NULL OR NEW.created_at IS DISTINCT FROM statement_timestamp()
   OR NOT EXISTS(SELECT 1 FROM public.merchant_invitations i
    JOIN public.merchant_member_profiles p ON p.operator_id=i.operator_id AND p.membership_id=NEW.membership_id AND p.kind='submerchant' AND p.sponsor_membership_id=i.sponsor_membership_id
    JOIN public.dashboard_memberships m ON m.id=p.membership_id AND m.operator_id=p.operator_id AND m.status='active'
    JOIN public.dashboard_users u ON u.id=m.user_id AND u.status='active' AND u.username=i.username
    JOIN public.operators o ON o.id=i.operator_id AND o.status='active'
    JOIN public.merchant_terminals t ON t.id=NEW.terminal_id AND t.operator_id=i.operator_id AND t.status='active'
    WHERE i.id=NEW.invitation_id AND i.operator_id=NEW.operator_id AND i.kind='submerchant' AND i.revoked_at IS NULL
     AND i.expires_at>clock_timestamp() AND NEW.terminal_id=ANY(i.terminal_ids)
     AND EXISTS(SELECT 1 FROM public.merchant_invitation_tokens token WHERE token.invitation_id=i.id AND token.consumed_at IS NOT NULL AND token.expires_at>clock_timestamp() AND token.policy_version=(SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=i.operator_id) AND token.issuer_version=(SELECT authorization_version FROM public.dashboard_memberships WHERE id=i.sponsor_membership_id))
     AND EXISTS(SELECT 1 FROM public.merchant_enrollment_audit accepted WHERE accepted.invitation_id=i.id AND accepted.operator_id=i.operator_id AND accepted.user_id=u.id AND accepted.action='invitation.accepted')
     AND EXISTS(SELECT 1 FROM public.merchant_member_profiles sp
      JOIN public.dashboard_memberships sm ON sm.id=sp.membership_id AND sm.operator_id=sp.operator_id AND sm.status='active'
      JOIN public.dashboard_users su ON su.id=sm.user_id AND su.status='active'
      WHERE sp.membership_id=i.sponsor_membership_id AND sp.operator_id=i.operator_id AND sp.kind='merchant_admin'
       AND NOT EXISTS(SELECT 1 FROM pg_catalog.unnest(i.permissions) needed(code) WHERE NOT EXISTS(
        SELECT 1 FROM public.membership_permission_grants g
        JOIN public.operator_permission_entitlements e ON e.operator_id=g.operator_id AND e.permission_code=g.permission_code AND e.enabled
        JOIN public.membership_permission_grants sg ON sg.id=g.sponsor_grant_id AND sg.membership_id=sp.membership_id AND sg.operator_id=g.operator_id AND sg.permission_code=g.permission_code
         AND sg.source='owner_bootstrap' AND sg.issuer_owner_id=sp.owner_issuer_id AND sg.revoked_at IS NULL
        WHERE g.membership_id=m.id AND g.operator_id=m.operator_id AND g.source='merchant_delegation' AND g.revoked_at IS NULL AND g.permission_code=needed.code))
       AND NOT EXISTS(SELECT 1 FROM (VALUES('client.permissions.delegate'),('client.users.manage_subaccounts')) needed(code) WHERE NOT EXISTS(
        SELECT 1 FROM public.membership_permission_grants sg
        JOIN public.operator_permission_entitlements e ON e.operator_id=sg.operator_id AND e.permission_code=sg.permission_code AND e.enabled
        WHERE sg.membership_id=sp.membership_id AND sg.operator_id=sp.operator_id AND sg.permission_code=needed.code AND sg.source='owner_bootstrap' AND sg.issuer_owner_id=sp.owner_issuer_id AND sg.revoked_at IS NULL))))
  THEN RAISE EXCEPTION 'Assignment authority refused' USING ERRCODE='42501'; END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER terminal_assignment_guard BEFORE INSERT OR UPDATE ON public.merchant_terminal_assignments FOR EACH ROW EXECUTE FUNCTION public.guard_terminal_assignment();
CREATE FUNCTION public.invalidate_terminal_assignment() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE revision INTEGER;
BEGIN
 UPDATE public.dashboard_memberships SET authorization_version=authorization_version+1 WHERE id=NEW.membership_id AND operator_id=NEW.operator_id RETURNING authorization_version INTO revision;
 INSERT INTO public.merchant_terminal_assignment_audit(assignment_id,operator_id,action,reason,membership_version,policy_version)
  VALUES(NEW.id,NEW.operator_id,CASE WHEN TG_OP='INSERT' THEN 'assigned' ELSE 'revoked' END,NEW.revocation_reason,revision,(SELECT authorization_version FROM public.operator_access_policies WHERE operator_id=NEW.operator_id));
 RETURN NEW;
END; $$;
CREATE TRIGGER terminal_assignment_invalidation AFTER INSERT OR UPDATE ON public.merchant_terminal_assignments FOR EACH ROW EXECUTE FUNCTION public.invalidate_terminal_assignment();
CREATE FUNCTION public.guard_terminal_lifecycle() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 -- Take the exclusive tenant gate BEFORE the UPDATE/DELETE; never acquire it
 -- from a row trigger (which would invert read lock ordering).
 IF TG_OP='DELETE' OR (NEW.id,NEW.operator_id,NEW.status) IS DISTINCT FROM (OLD.id,OLD.operator_id,OLD.status) THEN
  PERFORM public.require_viewer_policy_gate(OLD.operator_id);
 END IF;
 IF TG_OP='UPDATE' THEN
  IF (NEW.id,NEW.operator_id) IS DISTINCT FROM (OLD.id,OLD.operator_id) THEN
   RAISE EXCEPTION 'Terminal ownership is immutable' USING ERRCODE='42501';
  END IF;
  IF NEW.status='suspended' AND OLD.status IS DISTINCT FROM NEW.status THEN
   UPDATE public.merchant_terminal_assignments SET revoked_at=statement_timestamp(),revocation_reason='terminal_suspended'
    WHERE operator_id=OLD.operator_id AND terminal_id=OLD.id AND revoked_at IS NULL;
  END IF;
  RETURN NEW;
 END IF;
 RETURN OLD;
END; $$;
CREATE TRIGGER terminal_lifecycle_guard BEFORE UPDATE OR DELETE ON public.merchant_terminals FOR EACH ROW EXECUTE FUNCTION public.guard_terminal_lifecycle();
CREATE FUNCTION public.revoke_terminal_grant_assignments() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
 SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 UPDATE public.merchant_terminal_assignments SET revoked_at=statement_timestamp(),revocation_reason='grant_revoked'
  WHERE membership_id=NEW.membership_id AND operator_id=NEW.operator_id AND revoked_at IS NULL;
 RETURN NEW;
END; $$;
CREATE TRIGGER terminal_grant_revocation AFTER UPDATE ON public.membership_permission_grants FOR EACH ROW
 WHEN(OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND NEW.permission_code IN('client.payments.read','client.status.read'))
 EXECUTE FUNCTION public.revoke_terminal_grant_assignments();
