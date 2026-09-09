BEGIN READ ONLY;
SET LOCAL statement_timeout='30s';
SELECT public.assert_payment_boundary();
DO $verify$
DECLARE c record; product_id uuid; count_seen integer:=0; result boolean;
BEGIN
 SELECT p.id INTO product_id FROM public.products p JOIN public.business_owners b ON b.id=p.business_owner_id WHERE p.is_visible AND b.status='active' LIMIT 1;
 IF product_id IS NULL THEN RAISE EXCEPTION 'No visible product available for read-only validation'; END IF;
 FOR c IN SELECT DISTINCT ON (d.status) d.id,d.status,coalesce(d.status='approved' AND d.deleted_at IS NULL AND EXISTS(SELECT FROM public.user_roles r WHERE r.id=d.id AND r.role='daycare'),false) AS approved FROM public.daycares d ORDER BY d.status,d.id LOOP
  PERFORM set_config('request.jwt.claims',jsonb_build_object('role','authenticated','sub',c.id)::text,true);
  EXECUTE 'SET LOCAL ROLE authenticated';
  IF c.approved THEN
   PERFORM public.get_unavailable_dates(product_id);
   PERFORM public.check_reservation_available(product_id,current_date+20);
  ELSE
   BEGIN PERFORM public.get_unavailable_dates(product_id); RAISE EXCEPTION 'Unapproved availability access'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   BEGIN PERFORM public.check_reservation_available(product_id,current_date+20); RAISE EXCEPTION 'Unapproved date access'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   BEGIN PERFORM public.cleanup_expired_holds(); RAISE EXCEPTION 'Unapproved cleanup access'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  END IF;
  EXECUTE 'RESET ROLE'; count_seen:=count_seen+1;
 END LOOP;
 IF count_seen=0 THEN RAISE EXCEPTION 'No membership contexts available'; END IF;
 PERFORM set_config('request.jwt.claims','{"role":"anon"}',true);
 EXECUTE 'SET LOCAL ROLE anon';
 SELECT public.validate_product_preview_token(product_id,'00000000-0000-0000-0000-000000000000') INTO result;
 IF result THEN RAISE EXCEPTION 'Invalid preview token accepted'; END IF;
 IF public.get_product_preview(product_id,'00000000-0000-0000-0000-000000000000') IS NOT NULL THEN RAISE EXCEPTION 'Invalid preview returned data'; END IF;
 EXECUTE 'RESET ROLE';
END $verify$;
SELECT jsonb_build_object('membership_and_invalid_preview_checks',true,
 'approvals_enabled',(SELECT approvals_enabled FROM payment_private.configuration),
 'server_notifications_allowed',has_function_privilege('service_role','public.send_alimtalk_http(text)','EXECUTE'),
 'anon_definer_execute',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prosecdef AND p.prokind='f' AND has_function_privilege('anon',p.oid,'EXECUTE')),
 'member_definer_execute',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prosecdef AND p.prokind='f' AND has_function_privilege('authenticated',p.oid,'EXECUTE'))
) AS rpc_review_verification;
ROLLBACK;
