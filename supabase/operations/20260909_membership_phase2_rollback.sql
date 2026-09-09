-- INCIDENT USE ONLY. Restores pre-phase2 membership behavior, including its gaps.
-- Public client TRUNCATE privileges stay revoked. No customer rows or messages are changed.
-- This is not the normal next step after successful application.
BEGIN;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';
DO $rollback$
DECLARE item record;
BEGIN
  FOR item IN SELECT tablename,policyname FROM pg_policies
    WHERE schemaname='public' AND left(policyname,length('membership_v2_'))='membership_v2_'
  LOOP
    EXECUTE format('DROP POLICY %I ON public.%I',item.policyname,item.tablename);
  END LOOP;
END $rollback$;
CREATE OR REPLACE FUNCTION public.is_daycare()
RETURNS boolean AS $$
  SELECT EXISTS (
    SELECT 1 FROM user_roles 
    WHERE id = auth.uid() AND role = 'daycare'
  );
$$ LANGUAGE sql SECURITY DEFINER STABLE;
ALTER FUNCTION public.is_daycare() SET search_path = pg_catalog, public, extensions, pg_temp;
CREATE OR REPLACE FUNCTION public.guard_sensitive_profile_fields()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF public.is_active_admin() THEN
    RETURN NEW;
  END IF;

  IF TG_TABLE_NAME = 'daycares' THEN
    IF NEW.status IS DISTINCT FROM OLD.status
      OR NEW.approved_at IS DISTINCT FROM OLD.approved_at
      OR NEW.rejection_reason IS DISTINCT FROM OLD.rejection_reason
      OR NEW.email IS DISTINCT FROM OLD.email THEN
      RAISE EXCEPTION '관리자만 기관 승인 정보와 이메일을 변경할 수 있습니다.';
    END IF;
  ELSIF TG_TABLE_NAME = 'business_owners' THEN
    IF NEW.commission_rate IS DISTINCT FROM OLD.commission_rate
      OR NEW.status IS DISTINCT FROM OLD.status
      OR NEW.business_number IS DISTINCT FROM OLD.business_number
      OR NEW.email IS DISTINCT FROM OLD.email THEN
      RAISE EXCEPTION '관리자만 사업주 권한 및 정산 정보를 변경할 수 있습니다.';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS guard_daycare_privilege_fields ON public.daycares;
CREATE TRIGGER guard_daycare_privilege_fields BEFORE UPDATE ON public.daycares
  FOR EACH ROW EXECUTE FUNCTION public.guard_sensitive_profile_fields();
COMMIT;
