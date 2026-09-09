-- Read-only authorization checks. Does not update profiles, create orders, or send notifications.
BEGIN;
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
ROLLBACK;
