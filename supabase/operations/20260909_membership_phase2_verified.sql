-- Membership Phase 2 / Revision 2. Test on DAMDA development first.
-- Run this file alone. No customer rows, payment switches or messages are changed.
-- Keeps existing policies; restrictive policies add a mandatory membership check.
BEGIN;
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';

DO $preflight$
DECLARE item record; actual record; table_name text;
BEGIN
  FOR item IN SELECT * FROM (VALUES
    ('public.is_daycare()', ARRAY['60acdcb1193155dd264ebd48484ae41d', 'f76c0183b935ca5a9787a4fe8f52450c']),
    ('public.guard_sensitive_profile_fields()', ARRAY['3de937a6414190762b2e9deb71509440', '901b0a814d3dcb9851c6d433c18d423f']),
    ('public.is_active_admin()', ARRAY['1d33c72352a215911c531ee957c6759f']),
    ('public.current_business_owner_id()', ARRAY['c9626d704dd8038296c9e40540a234ad'])
  ) expected(identity, hashes)
  LOOP
    SELECT p.prosecdef, r.rolname, md5(replace(p.prosrc, chr(13), '')) AS body_hash
      INTO actual FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
      WHERE p.oid = to_regprocedure(item.identity);
    IF NOT FOUND OR actual.rolname <> 'postgres' OR NOT actual.prosecdef
      OR NOT actual.body_hash = ANY(item.hashes) THEN
      RAISE EXCEPTION 'MEMBERSHIP_REVIEW_REQUIRED: unreviewed function %', item.identity;
    END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname IN ('anon', 'authenticated')
    AND has_schema_privilege(r.oid, 'public', 'CREATE')) THEN
    RAISE EXCEPTION 'MEMBERSHIP_REVIEW_REQUIRED: client schema CREATE';
  END IF;
  FOREACH table_name IN ARRAY ARRAY[
    'daycares','products','product_images','product_options','product_unavailable_dates',
    'businesses','business_owners','business_place_profiles','business_place_images',
    'business_hours','business_closures','business_notices','reviews','review_images','review_replies',
    'carts','wishlists','recent_views','reservation_holds',
    'reservations','payments','payment_orders','refunds','reservation_options'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relname=table_name AND c.relkind='r'
        AND c.relrowsecurity AND c.relowner='postgres'::regrole) THEN
      RAISE EXCEPTION 'MEMBERSHIP_REVIEW_REQUIRED: missing/unexpected table %', table_name;
    END IF;
  END LOOP;
END $preflight$;

CREATE OR REPLACE FUNCTION public.is_daycare()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $membership$
  SELECT EXISTS (
    SELECT 1 FROM public.daycares d JOIN public.user_roles r ON r.id = d.id
    WHERE d.id = auth.uid() AND r.role = 'daycare'
      AND d.status = 'approved' AND d.deleted_at IS NULL
  );
$membership$;

-- Retain the reviewed business-owner protections; tighten daycare privileges.
-- A revision submission returns to 'requested', exactly as the existing UI does.
CREATE OR REPLACE FUNCTION public.guard_sensitive_profile_fields()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $membership$
BEGIN
  IF public.is_active_admin() OR auth.role() = 'service_role' THEN
    RETURN NEW;
  END IF;
  IF TG_TABLE_NAME = 'daycares' THEN
    IF NEW.id IS DISTINCT FROM auth.uid() THEN
      RAISE EXCEPTION 'Only the applicant can edit this profile' USING ERRCODE='42501';
    END IF;
    IF TG_OP = 'INSERT' THEN
      IF NEW.status IS DISTINCT FROM 'pending' OR NEW.approved_at IS NOT NULL
        OR NEW.rejection_reason IS NOT NULL OR NEW.revision_reason IS NOT NULL
        OR NEW.revision_requested_at IS NOT NULL OR NEW.deleted_at IS NOT NULL OR NEW.deleted_by IS NOT NULL THEN
        RAISE EXCEPTION 'Only an administrator can approve an application' USING ERRCODE='42501';
      END IF;
    ELSE
      IF NEW.id IS DISTINCT FROM OLD.id OR NEW.email IS DISTINCT FROM OLD.email
        OR NEW.approved_at IS DISTINCT FROM OLD.approved_at
        OR NEW.rejection_reason IS DISTINCT FROM OLD.rejection_reason
        OR NEW.revision_reason IS DISTINCT FROM OLD.revision_reason
        OR NEW.revision_requested_at IS DISTINCT FROM OLD.revision_requested_at
        OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at OR NEW.deleted_by IS DISTINCT FROM OLD.deleted_by
        OR (NEW.status IS DISTINCT FROM OLD.status AND NOT (
          OLD.status = 'revision_required' AND NEW.status = 'requested'
          AND NEW.revision_submitted_at IS NOT NULL
        )) THEN
        RAISE EXCEPTION 'Only an administrator can change approval information' USING ERRCODE='42501';
      END IF;
    END IF;
  ELSIF TG_TABLE_NAME = 'business_owners' THEN
    IF NEW.commission_rate IS DISTINCT FROM OLD.commission_rate
      OR NEW.status IS DISTINCT FROM OLD.status
      OR NEW.business_number IS DISTINCT FROM OLD.business_number
      OR NEW.email IS DISTINCT FROM OLD.email THEN
      RAISE EXCEPTION 'Only an administrator can change business privileges' USING ERRCODE='42501';
    END IF;
  END IF;
  RETURN NEW;
END;
$membership$;

DROP TRIGGER IF EXISTS guard_daycare_privilege_fields ON public.daycares;
CREATE TRIGGER guard_daycare_privilege_fields BEFORE INSERT OR UPDATE ON public.daycares
  FOR EACH ROW EXECUTE FUNCTION public.guard_sensitive_profile_fields();

-- Pending applicants need their own status and revision form, but cannot self-approve.
DROP POLICY IF EXISTS membership_v2_applicant_read ON public.daycares;
CREATE POLICY membership_v2_applicant_read ON public.daycares FOR SELECT TO authenticated
  USING (id=auth.uid() AND status <> 'deleted' AND deleted_at IS NULL);
DROP POLICY IF EXISTS membership_v2_applicant_update ON public.daycares;
CREATE POLICY membership_v2_applicant_update ON public.daycares FOR UPDATE TO authenticated
  USING (id=auth.uid() AND status <> 'deleted' AND deleted_at IS NULL)
  WITH CHECK (id=auth.uid() AND status <> 'deleted' AND deleted_at IS NULL);
DROP POLICY IF EXISTS membership_v2_profile_read ON public.daycares;
CREATE POLICY membership_v2_profile_read ON public.daycares AS RESTRICTIVE FOR SELECT TO authenticated
  USING (public.is_active_admin() OR (id=auth.uid() AND status <> 'deleted' AND deleted_at IS NULL));
DROP POLICY IF EXISTS membership_v2_profile_update ON public.daycares;
CREATE POLICY membership_v2_profile_update ON public.daycares AS RESTRICTIVE FOR UPDATE TO authenticated
  USING (public.is_active_admin() OR (id=auth.uid() AND status <> 'deleted' AND deleted_at IS NULL))
  WITH CHECK (public.is_active_admin() OR (id=auth.uid() AND status <> 'deleted' AND deleted_at IS NULL));
DROP POLICY IF EXISTS membership_v2_profile_insert ON public.daycares;
CREATE POLICY membership_v2_profile_insert ON public.daycares AS RESTRICTIVE FOR INSERT TO authenticated
  WITH CHECK (public.is_active_admin() OR (id=auth.uid() AND status='pending' AND approved_at IS NULL
    AND rejection_reason IS NULL AND revision_reason IS NULL AND revision_requested_at IS NULL
    AND deleted_at IS NULL AND deleted_by IS NULL));
DROP POLICY IF EXISTS membership_v2_profile_delete ON public.daycares;
CREATE POLICY membership_v2_profile_delete ON public.daycares AS RESTRICTIVE FOR DELETE TO authenticated
  USING (public.is_active_admin());

DO $policies$
DECLARE table_name text; predicate text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'daycares','products','product_images','product_options','product_unavailable_dates',
    'businesses','business_owners','business_place_profiles','business_place_images',
    'business_hours','business_closures','business_notices','reviews','review_images','review_replies',
    'carts','wishlists','recent_views','reservation_holds',
    'reservations','payments','payment_orders','refunds','reservation_options'
  ] LOOP
    EXECUTE format('DROP POLICY IF EXISTS membership_v2_no_anon ON public.%I',table_name);
    EXECUTE format('CREATE POLICY membership_v2_no_anon ON public.%I AS RESTRICTIVE TO anon USING (false) WITH CHECK (false)',table_name);
    IF table_name = 'daycares' THEN CONTINUE; END IF;
    predicate := CASE WHEN table_name = ANY(ARRAY['carts','wishlists','recent_views','reservation_holds'])
      THEN 'public.is_daycare()'
      ELSE '(public.is_daycare() OR public.is_active_admin() OR public.current_business_owner_id() IS NOT NULL)' END;
    EXECUTE format('DROP POLICY IF EXISTS membership_v2_approved_access ON public.%I',table_name);
    EXECUTE format('CREATE POLICY membership_v2_approved_access ON public.%I AS RESTRICTIVE TO authenticated USING (%s) WITH CHECK (%s)',table_name,predicate,predicate);
  END LOOP;
END $policies$;

-- TRUNCATE ignores row security. No browser feature needs whole-table removal.
-- Revoke it from public application tables. Supabase owns storage.objects/buckets
-- through supabase_storage_admin, so their platform-managed ACLs are only reported.
-- Preserve explicit service/backend grants; never perform TRUNCATE here.
DO $privileges$
DECLARE item record;
BEGIN
  FOR item IN SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind IN ('r','p') AND n.nspname='public'
  LOOP
    EXECUTE format('REVOKE TRUNCATE ON TABLE %I.%I FROM PUBLIC, anon, authenticated',item.nspname,item.relname);
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN pg_roles r
    WHERE c.relkind IN ('r','p') AND n.nspname='public'
      AND r.rolname IN ('anon','authenticated') AND has_table_privilege(r.oid,c.oid,'TRUNCATE')) THEN
    RAISE EXCEPTION 'MEMBERSHIP_REVIEW_REQUIRED: public client TRUNCATE remains';
  END IF;
END $privileges$;

-- Read-only authorization checks. Does not update profiles, create orders, or send notifications.

SET LOCAL statement_timeout='30s';
DO $verify$
DECLARE contexts jsonb; item jsonb; allowed boolean; product_count bigint; approved_count integer := 0;
BEGIN
  SELECT jsonb_agg(to_jsonb(c)) INTO contexts FROM (
    SELECT DISTINCT ON (d.status, d.deleted_at IS NOT NULL)
      d.id, d.status, d.deleted_at,
      (d.status='approved' AND d.deleted_at IS NULL AND EXISTS(SELECT FROM public.user_roles r WHERE r.id=d.id AND r.role='daycare')) AS expected
    FROM public.daycares d ORDER BY d.status,d.deleted_at IS NOT NULL,d.id
  ) c;
  FOR item IN SELECT value FROM jsonb_array_elements(coalesce(contexts,'[]')) LOOP
    PERFORM set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',item->>'id')::text,true);
    EXECUTE 'SET LOCAL ROLE authenticated';
    SELECT public.is_daycare() INTO allowed;
    IF allowed IS DISTINCT FROM (item->>'expected')::boolean THEN RAISE EXCEPTION 'Approval predicate mismatch'; END IF;
    SELECT count(*) INTO product_count FROM public.products;
    IF allowed THEN
      approved_count := approved_count+1;
      IF product_count=0 THEN RAISE EXCEPTION 'Approved caller cannot see any products'; END IF;
    ELSIF product_count<>0 THEN RAISE EXCEPTION 'Unapproved caller sees products';
    END IF;
    EXECUTE 'RESET ROLE';
  END LOOP;
  IF approved_count=0 THEN RAISE EXCEPTION 'No approved caller available for verification'; END IF;
  PERFORM set_config('request.jwt.claims','{"role":"anon"}',true);
  EXECUTE 'SET LOCAL ROLE anon';
  BEGIN
    SELECT count(*) INTO product_count FROM public.products;
    IF product_count<>0 THEN RAISE EXCEPTION 'Anonymous caller sees products'; END IF;
  EXCEPTION WHEN insufficient_privilege THEN
    -- Existing admin subqueries may reject anon before the restrictive false
    -- policy is evaluated. Both a permission error and zero rows deny access.
    NULL;
  END;
  EXECUTE 'RESET ROLE';
  PERFORM set_config('request.jwt.claims','{}',true);
  PERFORM public.assert_payment_boundary();
  IF NOT (SELECT boundary_activated AND approvals_enabled FROM payment_private.configuration) THEN
    RAISE EXCEPTION 'Payment boundary or approvals are not enabled';
  END IF;
END $verify$;
SELECT jsonb_build_object(
 'approval_and_catalog_checks_passed',true,
 'membership_policies',(SELECT count(*) FROM pg_policies WHERE schemaname='public' AND policyname LIKE 'membership_v2_%'),
 'public_client_truncate_grants',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN pg_roles r
  WHERE n.nspname='public' AND c.relkind IN ('r','p') AND r.rolname IN ('anon','authenticated') AND has_table_privilege(r.oid,c.oid,'TRUNCATE')),
 'payment_approvals_enabled',(SELECT approvals_enabled FROM payment_private.configuration),
 'alimtalk_server_allowed',has_function_privilege('service_role','public.send_alimtalk_http(text)','EXECUTE')
) AS membership_verification;


NOTIFY pgrst, 'reload schema';
COMMIT;
