SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

-- Additive attribution only. No inference/backfill of historical ownership.
ALTER TABLE public.payments ADD COLUMN terminal_id UUID;
ALTER TABLE public.payments ADD CONSTRAINT payments_terminal_operator_fk
 FOREIGN KEY(terminal_id,operator_id) REFERENCES public.merchant_terminals(id,operator_id)
 ON UPDATE RESTRICT ON DELETE RESTRICT;
CREATE INDEX payments_terminal_created_idx
 ON public.payments(operator_id,terminal_id,created_at DESC,id DESC)
 WHERE terminal_id IS NOT NULL;

CREATE FUNCTION public.guard_payment_terminal() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  IF (NEW.operator_id,NEW.terminal_id) IS DISTINCT FROM (OLD.operator_id,OLD.terminal_id) THEN
   RAISE EXCEPTION 'Payment attribution is immutable' USING ERRCODE='42501';
  END IF;
 ELSIF NEW.terminal_id IS NOT NULL THEN
  -- SHARE conflicts with non-key status updates, unlike KEY SHARE. Hold until
  -- transaction end so either creation or suspension wins, never a stale check.
  PERFORM id FROM public.merchant_terminals
   WHERE id=NEW.terminal_id AND operator_id=NEW.operator_id AND status='active'
   FOR SHARE;
  IF NOT FOUND OR NEW.provider IS DISTINCT FROM 'simulator' THEN
   RAISE EXCEPTION 'Terminal unavailable' USING ERRCODE='VX001';
  END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER payment_terminal_guard BEFORE INSERT OR UPDATE ON public.payments
 FOR EACH ROW EXECUTE FUNCTION public.guard_payment_terminal();
