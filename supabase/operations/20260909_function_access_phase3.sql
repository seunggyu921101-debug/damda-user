-- Reviewed client EXECUTE reduction. No function bodies, rows or job schedules are changed.
-- Keep authenticated access to guarded application RPCs; internal callers use explicit grants.
BEGIN;
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
CREATE TEMP TABLE function_access_targets ON COMMIT DROP AS
 SELECT * FROM jsonb_to_recordset($manifest$[{"identity":"add_daycare_role_on_approval()","hashes":["7342a9254814c88d72dfd14c524449b4","51e13ac320563737cce3fbb28264c759"],"member":false,"environments":["dev","prod"]},{"identity":"approve_business_owner_signup(uuid,uuid)","hashes":["a77f10e266d9d35ee5fe3b627261edf8"],"member":true,"environments":["dev","prod"]},{"identity":"approve_partner_onboarding(uuid)","hashes":["3f4722424b7e4199aff4bd509aefc9be","f6dcf3a37c05950d73c2951cfd8b6b3f"],"member":true,"environments":["dev","prod"]},{"identity":"attach_signup_business_details()","hashes":["f2ee2c2b727d1f8dfa90a9a5012a41d3"],"member":false,"environments":["prod"]},{"identity":"attach_signup_business_legal_name()","hashes":["06222a85e88166b1018f093cb305c10f","a77f98bc8c19ee0f95e47502b8d1641d"],"member":false,"environments":["dev","prod"]},{"identity":"auto_complete_reservations()","hashes":["31ad1c377c5e755a11db71b587e54bbb","2e4f569a01d1334338bbebbbca7800aa"],"member":false,"environments":["dev","prod"]},{"identity":"auto_confirm_email()","hashes":["19ea7ab708858a1bb15df93980d743d8","54e92098ca547009a3509555ddcda979"],"member":false,"environments":["dev","prod"]},{"identity":"change_admin_password(text,text)","hashes":["e805e0ca277488b913b0ca969e41585c"],"member":true,"environments":["dev","prod"]},{"identity":"check_reservation_available(uuid,date)","hashes":["1b05458183f39f3153b7ab038c8f4ea4","5ae5bc6abf08e0169bd33aa453269a18"],"member":true,"environments":["dev","prod"]},{"identity":"cleanup_expired_holds()","hashes":["ab8acb1f817f5adcd3da4b7dbda189bd"],"member":true,"environments":["dev","prod"]},{"identity":"create_admin_product_preview_token(uuid)","hashes":["81c39081b50764e6df4d5540755f7b42","ff6c911575b0357b2827a239ca267e7f"],"member":true,"environments":["dev","prod"]},{"identity":"create_business_owner_signup_request()","hashes":["a266c8d5c7be34d7b65077ea06b6a039","25f28f367cb7d43ca0e37e2fa2923e3d"],"member":false,"environments":["dev","prod"]},{"identity":"create_primary_business_for_owner()","hashes":["85c270a64a66f477ac63e0d1216d45e6"],"member":false,"environments":["dev","prod"]},{"identity":"create_secure_payment_order(jsonb,jsonb,text)","hashes":["2dd8988a4fed70d7ff649694da28086e"],"member":false,"environments":["dev","prod"]},{"identity":"delete_business_owner_safely(uuid,text)","hashes":["f082b3d908dca83d7196588cb56dde3f"],"member":true,"environments":["dev","prod"]},{"identity":"delete_business_safely(uuid,text)","hashes":["3aaf5cf5e95aa1c1ff5ba3cd512b50ca","1af89a3fbcfc749921fc7b8432b27284"],"member":true,"environments":["dev","prod"]},{"identity":"delete_daycare_safely(uuid,text)","hashes":["9d0571d7a2b8223370d88e52b22c4f68"],"member":true,"environments":["dev","prod"]},{"identity":"get_site_analytics(date,date)","hashes":["c32ae1f32b6bbcb9b69cde32834d4c68"],"member":true,"environments":["dev","prod"]},{"identity":"get_unavailable_dates(uuid)","hashes":["ce867129faa40d30beb2af41f81619b4","e162a80832c9211f26bb45410825dd20"],"member":true,"environments":["dev","prod"]},{"identity":"guard_sensitive_profile_fields()","hashes":["901b0a814d3dcb9851c6d433c18d423f"],"member":false,"environments":["dev","prod"]},{"identity":"log_partner_onboarding_change()","hashes":["8dfafd96a208c212fe4bfbf50ec8262e"],"member":false,"environments":["dev","prod"]},{"identity":"next_generated_document_number(text)","hashes":["f9273da5b5e0f21726aa5231f823f68f"],"member":false,"environments":["dev","prod"]},{"identity":"prepare_generated_document()","hashes":["28b128eddee38ecf50772c1a4869dc31"],"member":false,"environments":["dev","prod"]},{"identity":"renew_expiring_product_booking_windows()","hashes":["78730a61621a8ea7fda3981451918866"],"member":false,"environments":["prod"]},{"identity":"review_business_owner_signup(uuid,text,text,uuid)","hashes":["a4ccbcb8becf160a69831c801e6b7bb2"],"member":true,"environments":["dev","prod"]},{"identity":"sync_approved_business_names()","hashes":["c56343735b184d4192fe303f764f180b"],"member":false,"environments":["dev"]},{"identity":"sync_primary_business_status_from_owner()","hashes":["982a54109805a563e1b2293f8f2d9d88"],"member":false,"environments":["prod"]}]$manifest$::jsonb)
 AS t(identity text, hashes jsonb, member boolean, environments jsonb);
DO $review$
DECLARE t record; f record;
BEGIN
 FOR t IN SELECT * FROM function_access_targets LOOP
  SELECT p.*,pg_get_userbyid(p.proowner) AS owner_name INTO f FROM pg_proc p
   WHERE p.oid=to_regprocedure('public.'||t.identity);
  IF NOT FOUND THEN
   IF jsonb_array_length(t.environments)=2 THEN RAISE EXCEPTION 'FUNCTION_ACCESS_REVIEW_REQUIRED: missing %',t.identity; END IF;
   CONTINUE;
  END IF;
  IF f.owner_name<>'postgres' OR NOT f.prosecdef OR NOT (t.hashes ? md5(replace(f.prosrc,chr(13),''))) THEN
   RAISE EXCEPTION 'FUNCTION_ACCESS_REVIEW_REQUIRED: changed %',t.identity;
  END IF;
  IF NOT has_function_privilege('service_role',f.oid,'EXECUTE') THEN
   RAISE EXCEPTION 'FUNCTION_ACCESS_REVIEW_REQUIRED: unexpected server ACL %',t.identity;
  END IF;
 END LOOP;
 IF NOT has_function_privilege('authenticated','public.create_verified_payment_order(jsonb,jsonb,text)','EXECUTE') THEN
  RAISE EXCEPTION 'Verified checkout unavailable'; END IF;
END $review$;
-- The verified order wrapper executes its implementation as damda_payment_code.
GRANT EXECUTE ON FUNCTION public.create_secure_payment_order(jsonb,jsonb,text) TO damda_payment_code;
DO $apply$
DECLARE t record; f oid;
BEGIN
 FOR t IN SELECT * FROM function_access_targets LOOP
  f:=to_regprocedure('public.'||t.identity); IF f IS NULL THEN CONTINUE; END IF;
  EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role',f::regprocedure);
  EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon',f::regprocedure);
  IF t.member THEN
   EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO authenticated',f::regprocedure);
  ELSE
   EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM authenticated',f::regprocedure);
  END IF;
  IF has_function_privilege('anon',f,'EXECUTE')
   OR has_function_privilege('authenticated',f,'EXECUTE') IS DISTINCT FROM t.member
   OR NOT has_function_privilege('service_role',f,'EXECUTE') THEN
   RAISE EXCEPTION 'FUNCTION_ACCESS_REVIEW_REQUIRED: effective ACL mismatch %',t.identity;
  END IF;
 END LOOP;
 IF NOT has_function_privilege('damda_payment_code','public.create_secure_payment_order(jsonb,jsonb,text)','EXECUTE') THEN
  RAISE EXCEPTION 'Internal checkout implementation unavailable'; END IF;
 IF NOT has_function_privilege('service_role','public.send_alimtalk_http(text)','EXECUTE') THEN
  RAISE EXCEPTION 'Server notifications unavailable'; END IF;
 PERFORM public.assert_payment_boundary();
 IF NOT (SELECT boundary_activated AND approvals_enabled FROM payment_private.configuration) THEN
  RAISE EXCEPTION 'Payment approvals are not enabled'; END IF;
END $apply$;
SELECT jsonb_build_object(
 'phase','function-access-phase3',
 'restricted_functions',(SELECT count(*) FROM function_access_targets WHERE to_regprocedure('public.'||identity) IS NOT NULL),
 'anon_definer_executable',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prosecdef AND p.prokind='f' AND has_function_privilege('anon',p.oid,'EXECUTE')),
 'member_definer_executable',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prosecdef AND p.prokind='f' AND has_function_privilege('authenticated',p.oid,'EXECUTE')),
 'verified_checkout_member_allowed',has_function_privilege('authenticated','public.create_verified_payment_order(jsonb,jsonb,text)','EXECUTE'),
 'internal_order_allowed',has_function_privilege('damda_payment_code','public.create_secure_payment_order(jsonb,jsonb,text)','EXECUTE'),
 'alimtalk_server_allowed',has_function_privilege('service_role','public.send_alimtalk_http(text)','EXECUTE'),
 'payment_approvals_enabled',(SELECT approvals_enabled FROM payment_private.configuration)
) AS function_access_result;
COMMIT;
