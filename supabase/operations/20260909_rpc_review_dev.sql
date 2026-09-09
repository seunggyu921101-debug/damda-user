-- Reviewed function authorization and preview-output hardening.
BEGIN;
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.get_product_remaining(uuid,date)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('037ac109d315f001f90296d371029f94','b0e2ecfef82d344f3ab82b9c7276de1a')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: get_product_remaining'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.is_business_owner()'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('14255d46dfbb9c246b56487be4d13a45','d22a0c6f29cbc0bbb01cf74998e0aff0')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: is_business_owner'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.current_business_owner_id()'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('c9626d704dd8038296c9e40540a234ad','c9626d704dd8038296c9e40540a234ad')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: current_business_owner_id'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.approve_partner_onboarding(uuid)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('f6dcf3a37c05950d73c2951cfd8b6b3f','f6dcf3a37c05950d73c2951cfd8b6b3f')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: approve_partner_onboarding'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.is_current_business_owner(uuid)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('5509da320ca9f64eef2c4fe8bc835860','5509da320ca9f64eef2c4fe8bc835860')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: is_current_business_owner'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.is_active_admin()'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('1d33c72352a215911c531ee957c6759f','1d33c72352a215911c531ee957c6759f')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: is_active_admin'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.find_masked_daycare_email(text,text)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('0387a35591221efcbd2288581b1f2c96','f45740ac6df3d287217ed4e0c9ce1b65')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: find_masked_daycare_email'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.create_admin_product_preview_token(uuid)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('81c39081b50764e6df4d5540755f7b42','81c39081b50764e6df4d5540755f7b42')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: create_admin_product_preview_token'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.get_product_preview(uuid,uuid)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('58d5dc8744df29e20af0e67b4e9bef11','a81de4c757e8970adb0101ac56815a5d')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: get_product_preview'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.get_business_product_preview(uuid,uuid,uuid)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('5f6a755bf1133e54e48c0c58881d999e','4876e29f33078c82365b741c4ae741b2')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: get_business_product_preview'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.validate_product_preview_token(uuid,uuid)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('58e30a5a7dbc7090146579d770045bd5','a064f32fbdbb3ac369d1631af70521c7')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: validate_product_preview_token'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.track_site_analytics(text,uuid)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('f352a0935163ff4770f90ed94fac8e96','cc5a39453ab27e76af0fcafc3ce6b746')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: track_site_analytics'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.get_unavailable_dates(uuid)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('ce867129faa40d30beb2af41f81619b4','85e9a401cfcf893582694c3d87a42032')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: get_unavailable_dates'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.approve_business_owner_signup(uuid,uuid)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('a77f10e266d9d35ee5fe3b627261edf8','a77f10e266d9d35ee5fe3b627261edf8')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: approve_business_owner_signup'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.change_admin_password(text,text)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('e805e0ca277488b913b0ca969e41585c','18d9c4bf2900e274710d89d555406891')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: change_admin_password'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.check_reservation_available(uuid,date)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('1b05458183f39f3153b7ab038c8f4ea4','a261618da2291350e43580738a9ded1f')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: check_reservation_available'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.cleanup_expired_holds()'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('ab8acb1f817f5adcd3da4b7dbda189bd','55f42ea8fff8034fd76d30abcae47b7a')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: cleanup_expired_holds'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.delete_business_owner_safely(uuid,text)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('f082b3d908dca83d7196588cb56dde3f','f082b3d908dca83d7196588cb56dde3f')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: delete_business_owner_safely'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.delete_business_safely(uuid,text)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('1af89a3fbcfc749921fc7b8432b27284','1af89a3fbcfc749921fc7b8432b27284')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: delete_business_safely'; END IF; END$$;
DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_proc WHERE oid='public.review_business_owner_signup(uuid,text,text,uuid)'::regprocedure AND pg_get_userbyid(proowner)='postgres' AND prosecdef AND md5(replace(prosrc,chr(13),'')) IN ('a4ccbcb8becf160a69831c801e6b7bb2','5e5be2a4e4fafd97edb86b07f19fb430')) THEN RAISE EXCEPTION 'RPC_REVIEW_REQUIRED: review_business_owner_signup'; END IF; END$$;
CREATE OR REPLACE FUNCTION public.get_product_remaining(p_product_id uuid, p_date date)
 RETURNS integer
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
BEGIN
IF (public.is_active_admin()
 OR (public.is_daycare() AND EXISTS(SELECT 1 FROM public.products p JOIN public.business_owners bo ON bo.id=p.business_owner_id WHERE p.id=p_product_id AND p.is_visible AND bo.status='active'))
 OR EXISTS(SELECT 1 FROM public.products p WHERE p.id=p_product_id AND public.is_current_business_owner(p.business_owner_id))
 OR auth.role()='service_role') IS NOT TRUE THEN
 RAISE EXCEPTION 'APPROVED_PRODUCT_ACCESS_REQUIRED' USING ERRCODE='42501'; END IF;
RETURN (SELECT GREATEST(
    COALESCE(
      -- 그날만 정원 조정(capacity override) 우선
      (SELECT capacity_override FROM product_unavailable_dates
        WHERE product_id = p_product_id AND unavailable_date = p_date
          AND kind = 'capacity' AND capacity_override IS NOT NULL
        LIMIT 1),
      -- 없으면 요일 스케줄 정원
      (SELECT capacity FROM product_schedules
        WHERE product_id = p_product_id AND slot_time IS NULL AND is_active
          AND (day_of_week = EXTRACT(dow FROM p_date)::int OR day_of_week IS NULL)
        ORDER BY day_of_week NULLS LAST
        LIMIT 1),
      0
    )
    - COALESCE(
      (SELECT SUM(participant_count) FROM reservations
        WHERE product_id = p_product_id AND reserved_date = p_date
          AND status IN ('pending','paid','confirmed','completed')),
      0
    ),
    0
  )::integer);
END;
$function$;
CREATE OR REPLACE FUNCTION public.is_business_owner()
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
  SELECT EXISTS (
    SELECT 1 FROM user_roles 
    WHERE id = auth.uid() AND role = 'business_owner'
      AND public.current_business_owner_id() IS NOT NULL
  );
$function$;
CREATE OR REPLACE FUNCTION public.current_business_owner_id()
 RETURNS uuid
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
  SELECT id
  FROM public.business_owners
  WHERE auth_user_id = auth.uid()
    AND status = 'active'
  LIMIT 1;
$function$;
CREATE OR REPLACE FUNCTION public.approve_partner_onboarding(p_onboarding_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
DECLARE
  v_onboarding public.partner_onboardings%ROWTYPE;
  v_signup public.business_owner_signup_requests%ROWTYPE;
  v_owner_id uuid := gen_random_uuid();
  v_product record;
  v_product_id uuid;
  v_image text;
  v_option jsonb;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.admins WHERE id = auth.uid() AND is_active = true) THEN
    RAISE EXCEPTION '관리자만 입점을 승인할 수 있습니다.';
  END IF;

  SELECT * INTO v_onboarding
  FROM public.partner_onboardings
  WHERE id = p_onboarding_id
  FOR UPDATE;

  IF NOT FOUND THEN RAISE EXCEPTION '입점 신청을 찾을 수 없습니다.'; END IF;
  IF v_onboarding.status = 'approved' THEN
    RETURN jsonb_build_object('success', true, 'business_owner_id', v_onboarding.business_owner_id);
  END IF;
  IF v_onboarding.status <> 'ready_for_approval' THEN RAISE EXCEPTION '승인 대기 상태가 아닙니다.'; END IF;
  IF v_onboarding.contract_status <> 'completed' THEN RAISE EXCEPTION '계약이 완료되지 않았습니다.'; END IF;
  IF v_onboarding.signup_request_id IS NULL THEN RAISE EXCEPTION '사업주 콘솔 가입 계정이 연결되지 않았습니다.'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.partner_onboarding_documents
    WHERE onboarding_id = p_onboarding_id AND document_type = 'business_registration'
  ) OR NOT EXISTS (
    SELECT 1 FROM public.partner_onboarding_documents
    WHERE onboarding_id = p_onboarding_id AND document_type = 'bank_account'
  ) THEN RAISE EXCEPTION '필수 서류가 누락되었습니다.'; END IF;
  IF NOT EXISTS (SELECT 1 FROM public.partner_onboarding_products WHERE onboarding_id = p_onboarding_id) THEN
    RAISE EXCEPTION '등록할 상품이 없습니다.';
  END IF;
  IF (SELECT count(*) FROM public.partner_onboarding_products WHERE onboarding_id = p_onboarding_id) > 10 THEN
    RAISE EXCEPTION '사업주별 상품은 최대 10개까지 등록할 수 있습니다.';
  END IF;

  SELECT * INTO v_signup
  FROM public.business_owner_signup_requests
  WHERE id = v_onboarding.signup_request_id
  FOR UPDATE;

  IF NOT FOUND OR v_signup.status <> 'pending' THEN RAISE EXCEPTION '유효한 가입 신청이 아닙니다.'; END IF;
  IF regexp_replace(v_signup.business_number, '[^0-9]', '', 'g') <> v_onboarding.business_number THEN
    RAISE EXCEPTION '가입 신청과 입점 신청의 사업자번호가 일치하지 않습니다.';
  END IF;
  IF lower(btrim(v_signup.email)) <> lower(btrim(v_onboarding.email)) THEN
    RAISE EXCEPTION '가입 신청과 입점 신청의 이메일이 일치하지 않습니다.';
  END IF;
  IF EXISTS (SELECT 1 FROM public.business_owners WHERE business_number = v_onboarding.business_number) THEN
    RAISE EXCEPTION '이미 등록된 사업자번호입니다.';
  END IF;

  UPDATE public.partner_onboardings SET status = 'approving', updated_at = now()
  WHERE id = p_onboarding_id;

  INSERT INTO public.business_owners (
    id, auth_user_id, owner_code, email, name, business_number, representative,
    contact_name, contact_phone, address, address_detail, zipcode,
    bank_name, bank_account, bank_holder, tax_email, commission_rate, status
  ) VALUES (
    v_owner_id, v_signup.auth_user_id, v_onboarding.owner_code, v_signup.email, v_onboarding.business_name,
    v_onboarding.business_number, v_onboarding.representative, v_onboarding.contact_name,
    v_onboarding.contact_phone, v_onboarding.address, v_onboarding.address_detail,
    v_onboarding.zipcode, v_onboarding.bank_name, v_onboarding.bank_account,
    v_onboarding.bank_holder, v_onboarding.tax_email, v_onboarding.commission_rate, 'active'
  );

  INSERT INTO public.business_owner_documents (
    business_owner_id, document_type, file_name, file_url, file_size, mime_type,
    storage_bucket, storage_path, sort_order
  )
  SELECT v_owner_id, document_type, file_name, storage_path, file_size, mime_type,
         'partner-onboarding-documents', storage_path,
         CASE WHEN document_type = 'business_registration' THEN 0 ELSE 1 END
  FROM public.partner_onboarding_documents WHERE onboarding_id = p_onboarding_id;

  FOR v_product IN
    SELECT * FROM public.partner_onboarding_products
    WHERE onboarding_id = p_onboarding_id ORDER BY sort_order, created_at
  LOOP
    INSERT INTO public.products (
      business_owner_id, category_id, name, summary, description, thumbnail,
      original_price, sale_price, min_participants, max_participants,
      duration_minutes, address, address_detail, region, is_visible
    ) VALUES (
      v_owner_id, v_product.category_id, v_product.name, v_product.summary,
      v_product.description, v_product.thumbnail, v_product.original_price,
      v_product.sale_price, v_product.min_participants, v_product.max_participants,
      v_product.duration_minutes, v_product.address, v_product.address_detail,
      v_product.region, false
    ) RETURNING id INTO v_product_id;

    FOR v_image IN SELECT jsonb_array_elements_text(v_product.image_urls)
    LOOP
      INSERT INTO public.product_images (product_id, image_url, sort_order)
      VALUES (v_product_id, v_image, 0);
    END LOOP;
    FOR v_option IN SELECT value FROM jsonb_array_elements(v_product.options)
    LOOP
      INSERT INTO public.product_options (product_id, name, price, is_required, sort_order)
      VALUES (
        v_product_id,
        v_option->>'name',
        COALESCE((v_option->>'price')::integer, 0),
        COALESCE((v_option->>'is_required')::boolean, false),
        COALESCE((v_option->>'sort_order')::integer, 0)
      );
    END LOOP;
  END LOOP;

  INSERT INTO public.user_roles (id, role) VALUES (v_signup.auth_user_id, 'business_owner')
  ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role;

  UPDATE public.business_owner_signup_requests
  SET status = 'approved', matched_business_owner_id = v_owner_id,
      reviewed_by = auth.uid(), reviewed_at = now(), updated_at = now()
  WHERE id = v_signup.id;

  UPDATE public.partner_onboardings
  SET status = 'approved', business_owner_id = v_owner_id,
      approved_by = auth.uid(), approved_at = now(), updated_at = now()
  WHERE id = p_onboarding_id;

  RETURN jsonb_build_object('success', true, 'business_owner_id', v_owner_id);
END;
$function$;
CREATE OR REPLACE FUNCTION public.is_current_business_owner(p_business_owner_id uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
  SELECT EXISTS (
    SELECT 1 FROM public.business_owners
    WHERE id = p_business_owner_id AND auth_user_id = auth.uid() AND status = 'active'
  );
$function$;
CREATE OR REPLACE FUNCTION public.is_active_admin()
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.admins
    WHERE id = auth.uid()
      AND is_active = true
  );
$function$;
CREATE OR REPLACE FUNCTION public.find_masked_daycare_email(p_name text, p_phone text)
 RETURNS text
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
DECLARE
  v_email text;
  v_local text;
  v_domain text;
  v_phone text := regexp_replace(COALESCE(p_phone, ''), '[^0-9]', '', 'g');
BEGIN
  IF length(trim(COALESCE(p_name, ''))) NOT BETWEEN 1 AND 200 OR length(v_phone) NOT BETWEEN 10 AND 11 THEN
    RETURN NULL;
  END IF;
  SELECT email INTO v_email
  FROM public.daycares
  WHERE deleted_at IS NULL AND status<>'deleted' AND name = trim(p_name)
    AND regexp_replace(contact_phone, '[^0-9]', '', 'g') = v_phone
  LIMIT 1;
  IF v_email IS NULL OR position('@' IN v_email) = 0 THEN
    RETURN NULL;
  END IF;
  v_local := split_part(v_email, '@', 1);
  v_domain := split_part(v_email, '@', 2);
  RETURN CASE WHEN length(v_local) <= 2 THEN left(v_local, 1) || '*' ELSE left(v_local, 2) || repeat('*', length(v_local) - 2) END || '@' || v_domain;
END;
$function$;
CREATE OR REPLACE FUNCTION public.create_admin_product_preview_token(p_product_id uuid)
 RETURNS TABLE(token uuid, expires_at timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
DECLARE
  v_business_owner_id uuid;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.admins
    WHERE id = auth.uid() AND is_active = true
  ) THEN
    RAISE EXCEPTION 'ADMIN_REQUIRED';
  END IF;
  SELECT p.business_owner_id INTO v_business_owner_id
  FROM public.products p WHERE p.id = p_product_id;
  IF v_business_owner_id IS NULL THEN
    RAISE EXCEPTION 'PRODUCT_NOT_FOUND';
  END IF;
  DELETE FROM public.product_preview_tokens ppt
  WHERE ppt.product_id = p_product_id AND ppt.expires_at <= now();
  RETURN QUERY
  INSERT INTO public.product_preview_tokens(product_id, business_owner_id)
  VALUES (p_product_id, v_business_owner_id)
  RETURNING product_preview_tokens.token, product_preview_tokens.expires_at;
END;
$function$;
CREATE OR REPLACE FUNCTION public.get_product_preview(p_product_id uuid, p_token uuid)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
  SELECT (SELECT jsonb_object_agg(k,v) FROM jsonb_each(to_jsonb(p)) AS projected(k,v) WHERE k=ANY(ARRAY['id','business_owner_id','category_id','name','summary','description','thumbnail','original_price','sale_price','min_participants','max_participants','duration_minutes','address','latitude','longitude','region','available_time_slots','is_visible','is_sold_out','view_count','created_at','updated_at','address_detail','business_id','sale_type','minimum_age','recommended_age_min','recommended_age_max','booking_start_date','booking_end_date','booking_cutoff_hours','allow_same_day_booking','inclusions','exclusions','materials','usage_method','product_precautions','reservation_notice','refund_notice','other_notice','display_order','experience_environment','operates_in_rain','rain_alternative','bus_accessible','bus_parking_available','dropoff_space_available','meal_available','lunchbox_allowed','restroom_info','child_restroom_available','teacher_supplies','child_supplies','provided_supplies','accessibility_info','meeting_point','field_contact','teacher_notes','clothing_guidance','meal_guidance','transportation_guidance','guardian_notes','facility_services'])) || jsonb_build_object(
    'business_owner', jsonb_build_object(
      'id', coalesce(b.id, bo.id),
      'name', coalesce(b.name, bo.name),
      'logo_url', coalesce(b.logo_url, bo.logo_url)
    ),
    'category', CASE WHEN c.id IS NULL THEN NULL ELSE jsonb_build_object('id', c.id, 'name', c.name, 'parent_id', c.parent_id) END,
    'images', coalesce((SELECT jsonb_agg((SELECT jsonb_object_agg(k,v) FROM jsonb_each(to_jsonb(pi)) AS projected(k,v) WHERE k=ANY(ARRAY['id','product_id','image_url','sort_order','created_at'])) ORDER BY pi.sort_order) FROM public.product_images pi WHERE pi.product_id = p.id), '[]'::jsonb),
    'options', coalesce((SELECT jsonb_agg((SELECT jsonb_object_agg(k,v) FROM jsonb_each(to_jsonb(po)) AS projected(k,v) WHERE k=ANY(ARRAY['id','product_id','name','price','is_required','sort_order','created_at'])) ORDER BY po.sort_order) FROM public.product_options po WHERE po.product_id = p.id), '[]'::jsonb),
    'unavailable_dates', coalesce((SELECT jsonb_agg((SELECT jsonb_object_agg(k,v) FROM jsonb_each(to_jsonb(pud)) AS projected(k,v) WHERE k=ANY(ARRAY['id','product_id','unavailable_date','is_recurring','day_of_week','created_at','kind','slot_time','capacity_override'])) ORDER BY pud.unavailable_date) FROM public.product_unavailable_dates pud WHERE pud.product_id = p.id), '[]'::jsonb)
  )
  FROM public.product_preview_tokens ppt
  JOIN public.products p ON p.id = ppt.product_id
  JOIN public.business_owners bo ON bo.id = p.business_owner_id
  LEFT JOIN public.businesses b ON b.id = p.business_id
  LEFT JOIN public.categories c ON c.id = p.category_id
  WHERE ppt.business_owner_id = p.business_owner_id AND ppt.token = p_token
    AND ppt.product_id = p_product_id
    AND ppt.expires_at > now()
    AND bo.status = 'active';
$function$;
CREATE OR REPLACE FUNCTION public.get_business_product_preview(p_business_id uuid, p_product_id uuid, p_token uuid)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
  WITH preview_product AS (
    SELECT p.*
    FROM public.product_preview_tokens ppt
    JOIN public.products p ON p.id = ppt.product_id
    JOIN public.business_owners bo ON bo.id = p.business_owner_id
    WHERE ppt.business_owner_id = p.business_owner_id AND ppt.token = p_token
      AND ppt.product_id = p_product_id
      AND ppt.expires_at > now()
      AND p.business_id = p_business_id
      AND bo.status = 'active'
  )
  SELECT jsonb_build_object(
    'business', (SELECT jsonb_object_agg(k,v) FROM jsonb_each(to_jsonb(b)) AS projected(k,v) WHERE k=ANY(ARRAY['id','business_owner_id','name','address','address_detail','zipcode','latitude','longitude','region','thumbnail','intro','is_visible','created_at','updated_at','logo_url','introduction','status','is_primary','summary','parking_available','parking_notice','facilities','common_guide','common_precautions','category_id'])) || jsonb_build_object(
      'place_profile', (
        SELECT (SELECT jsonb_object_agg(k,v) FROM jsonb_each(to_jsonb(profile)) AS projected(k,v) WHERE k=ANY(ARRAY['business_owner_id','introduction','public_phone','website_url','directions','reservation_notice','created_at','updated_at','id','business_id']))
        FROM public.business_place_profiles profile
        WHERE profile.business_id = b.id
        LIMIT 1
      ),
      'images', coalesce((
        SELECT jsonb_agg((SELECT jsonb_object_agg(k,v) FROM jsonb_each(to_jsonb(image)) AS projected(k,v) WHERE k=ANY(ARRAY['id','business_owner_id','image_url','caption','is_primary','sort_order','created_at','business_id'])) ORDER BY image.is_primary DESC, image.sort_order ASC)
        FROM public.business_place_images image
        WHERE image.business_id = b.id
      ), '[]'::jsonb),
      'hours', coalesce((
        SELECT jsonb_agg((SELECT jsonb_object_agg(k,v) FROM jsonb_each(to_jsonb(hour)) AS projected(k,v) WHERE k=ANY(ARRAY['id','business_owner_id','day_of_week','is_closed','open_time','close_time','break_start','break_end','created_at','updated_at','business_id'])) ORDER BY hour.day_of_week ASC)
        FROM public.business_hours hour
        WHERE hour.business_id = b.id
      ), '[]'::jsonb)
    ),
    'products', coalesce((
      SELECT jsonb_agg(
        (SELECT jsonb_object_agg(k,v) FROM jsonb_each(to_jsonb(listed_product)) AS projected(k,v) WHERE k=ANY(ARRAY['id','business_owner_id','category_id','name','summary','description','thumbnail','original_price','sale_price','min_participants','max_participants','duration_minutes','address','latitude','longitude','region','available_time_slots','is_visible','is_sold_out','view_count','created_at','updated_at','address_detail','business_id','sale_type','minimum_age','recommended_age_min','recommended_age_max','booking_start_date','booking_end_date','booking_cutoff_hours','allow_same_day_booking','inclusions','exclusions','materials','usage_method','product_precautions','reservation_notice','refund_notice','other_notice','display_order','experience_environment','operates_in_rain','rain_alternative','bus_accessible','bus_parking_available','dropoff_space_available','meal_available','lunchbox_allowed','restroom_info','child_restroom_available','teacher_supplies','child_supplies','provided_supplies','accessibility_info','meeting_point','field_contact','teacher_notes','clothing_guidance','meal_guidance','transportation_guidance','guardian_notes','facility_services'])) || jsonb_build_object(
          'business_owner', jsonb_build_object('id', b.id, 'name', b.name, 'logo_url', b.logo_url),
          'business', jsonb_build_object('id', b.id, 'name', b.name, 'logo_url', b.logo_url),
          'category', CASE WHEN category.id IS NULL THEN NULL ELSE jsonb_build_object('id', category.id, 'name', category.name, 'parent_id', category.parent_id) END,
          'images', coalesce((
            SELECT jsonb_agg((SELECT jsonb_object_agg(k,v) FROM jsonb_each(to_jsonb(product_image)) AS projected(k,v) WHERE k=ANY(ARRAY['id','product_id','image_url','sort_order','created_at'])) ORDER BY product_image.sort_order ASC)
            FROM public.product_images product_image
            WHERE product_image.product_id = listed_product.id
          ), '[]'::jsonb),
          'review_count', (
            SELECT count(*) FROM public.reviews review
            WHERE review.product_id = listed_product.id AND review.is_visible = true
          ),
          'average_rating', coalesce((
            SELECT round(avg(review.rating)::numeric, 1) FROM public.reviews review
            WHERE review.product_id = listed_product.id AND review.is_visible = true
          ), 0)
        )
        ORDER BY CASE WHEN listed_product.id = p_product_id THEN 0 ELSE 1 END,
          listed_product.display_order ASC, listed_product.created_at DESC
      )
      FROM public.products listed_product
      LEFT JOIN public.categories category ON category.id = listed_product.category_id
      WHERE listed_product.business_id = b.id AND listed_product.business_owner_id = b.business_owner_id
        AND (listed_product.id = p_product_id OR (listed_product.is_visible = true AND listed_product.is_sold_out = false))
    ), '[]'::jsonb)
  )
  FROM preview_product target_product
  JOIN public.businesses b ON b.id = target_product.business_id;
$function$;
CREATE OR REPLACE FUNCTION public.validate_product_preview_token(p_product_id uuid, p_token uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  SELECT EXISTS (SELECT 1 FROM public.product_preview_tokens ppt JOIN public.products p ON p.id=ppt.product_id JOIN public.business_owners bo ON bo.id=p.business_owner_id WHERE ppt.business_owner_id=p.business_owner_id AND bo.status='active' AND ppt.product_id = p_product_id AND ppt.token = p_token AND ppt.expires_at > now());
$function$;
CREATE OR REPLACE FUNCTION public.track_site_analytics(p_metric_key text, p_visitor_id uuid DEFAULT NULL::uuid)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
  v_today date := (CURRENT_TIMESTAMP AT TIME ZONE 'Asia/Seoul')::date;
  v_inserted boolean := true;
BEGIN
  IF p_metric_key IS NULL OR p_metric_key NOT IN ('daily_visit', 'partner_cta_click', 'signup_cta_click') THEN
    RAISE EXCEPTION 'INVALID_ANALYTICS_METRIC';
  END IF;

  IF p_metric_key = 'daily_visit' THEN
    IF p_visitor_id IS NULL THEN
      RAISE EXCEPTION 'VISITOR_ID_REQUIRED';
    END IF;

    INSERT INTO public.site_daily_visitors(metric_date, visitor_hash)
    VALUES (
      v_today,
      encode(extensions.digest(p_visitor_id::text, 'sha256'), 'hex')
    )
    ON CONFLICT DO NOTHING;

    v_inserted := FOUND;
  END IF;

  IF v_inserted THEN
    INSERT INTO public.site_daily_metrics(metric_date, metric_key, metric_count)
    VALUES (v_today, p_metric_key, 1)
    ON CONFLICT (metric_date, metric_key)
    DO UPDATE SET
      metric_count = public.site_daily_metrics.metric_count + 1,
      updated_at = now();
  END IF;
END;
$function$;
CREATE OR REPLACE FUNCTION public.get_unavailable_dates(p_product_id uuid)
 RETURNS text[]
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
DECLARE
  result TEXT[];
BEGIN
  IF (public.is_active_admin()
 OR (public.is_daycare() AND EXISTS(SELECT 1 FROM public.products p JOIN public.business_owners bo ON bo.id=p.business_owner_id WHERE p.id=p_product_id AND p.is_visible AND bo.status='active'))
 OR EXISTS(SELECT 1 FROM public.products p WHERE p.id=p_product_id AND public.is_current_business_owner(p.business_owner_id))
 OR auth.role()='service_role') IS NOT TRUE THEN
 RAISE EXCEPTION 'APPROVED_PRODUCT_ACCESS_REQUIRED' USING ERRCODE='42501'; END IF;
  -- Availability reads never delete another customer's holds.
  SELECT ARRAY_AGG(DISTINCT reserved_date::TEXT)
  INTO result
  FROM (
    SELECT reserved_date
    FROM reservations
    WHERE product_id = p_product_id
      AND status IN ('pending', 'paid', 'confirmed')
    UNION
    SELECT reserved_date
    FROM reservation_holds
    WHERE product_id = p_product_id
      AND expires_at > now()
      AND daycare_id != COALESCE(auth.uid(), '00000000-0000-0000-0000-000000000000'::UUID)
  ) AS unavailable;
  RETURN COALESCE(result, ARRAY[]::TEXT[]);
END;
$function$;
CREATE OR REPLACE FUNCTION public.approve_business_owner_signup(p_request_id uuid, p_business_owner_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
DECLARE
  v_request public.business_owner_signup_requests%ROWTYPE;
  v_owner public.business_owners%ROWTYPE;
  v_previous_auth_user_id uuid;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.admins
    WHERE id = auth.uid() AND is_active = true
  ) THEN
    RAISE EXCEPTION 'ADMIN_REQUIRED';
  END IF;

  SELECT * INTO v_request
  FROM public.business_owner_signup_requests
  WHERE id = p_request_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'BUSINESS_SIGNUP_REQUEST_NOT_FOUND';
  END IF;
  IF v_request.status NOT IN ('pending', 'on_hold', 'rejected') THEN
    RAISE EXCEPTION 'BUSINESS_SIGNUP_REQUEST_ALREADY_PROCESSED';
  END IF;

  SELECT * INTO v_owner
  FROM public.business_owners
  WHERE id = p_business_owner_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'BUSINESS_OWNER_NOT_FOUND';
  END IF;
  IF lower(btrim(v_request.email)) <> lower(btrim(v_owner.email)) THEN
    RAISE EXCEPTION 'BUSINESS_OWNER_EMAIL_MISMATCH';
  END IF;

  v_previous_auth_user_id := v_owner.auth_user_id;

  UPDATE public.business_owners
  SET auth_user_id = v_request.auth_user_id,
      bank_name = COALESCE(NULLIF(btrim(v_request.bank_name), ''), bank_name),
      bank_holder = COALESCE(NULLIF(btrim(v_request.bank_holder), ''), bank_holder),
      bank_account = COALESCE(NULLIF(v_request.bank_account, ''), bank_account),
      status = 'active',
      updated_at = now()
  WHERE id = p_business_owner_id;

  IF v_request.business_registration_storage_path IS NOT NULL THEN
    DELETE FROM public.business_owner_documents
    WHERE business_owner_id = p_business_owner_id AND document_type = 'business_registration';

    INSERT INTO public.business_owner_documents (
      business_owner_id, document_type, file_name, file_url, file_size, mime_type,
      storage_bucket, storage_path, sort_order
    ) VALUES (
      p_business_owner_id,
      'business_registration',
      COALESCE(v_request.business_registration_file_name, '사업자등록증'),
      v_request.business_registration_storage_path,
      v_request.business_registration_file_size,
      v_request.business_registration_mime_type,
      COALESCE(v_request.business_registration_storage_bucket, 'business-signup-documents'),
      v_request.business_registration_storage_path,
      0
    );
  END IF;

  IF v_request.bank_account_copy_storage_path IS NOT NULL THEN
    DELETE FROM public.business_owner_documents
    WHERE business_owner_id = p_business_owner_id AND document_type = 'bank_account';

    INSERT INTO public.business_owner_documents (
      business_owner_id, document_type, file_name, file_url, file_size, mime_type,
      storage_bucket, storage_path, sort_order
    ) VALUES (
      p_business_owner_id,
      'bank_account',
      COALESCE(v_request.bank_account_copy_file_name, '통장사본'),
      v_request.bank_account_copy_storage_path,
      v_request.bank_account_copy_file_size,
      v_request.bank_account_copy_mime_type,
      COALESCE(v_request.bank_account_copy_storage_bucket, 'business-signup-documents'),
      v_request.bank_account_copy_storage_path,
      1
    );
  END IF;

  IF v_previous_auth_user_id IS NOT NULL
     AND v_previous_auth_user_id <> v_request.auth_user_id THEN
    DELETE FROM public.user_roles
    WHERE id = v_previous_auth_user_id AND role = 'business_owner';
  END IF;

  INSERT INTO public.user_roles (id, role)
  VALUES (v_request.auth_user_id, 'business_owner')
  ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role;

  UPDATE public.business_owner_signup_requests
  SET status = 'approved',
      matched_business_owner_id = p_business_owner_id,
      reviewed_by = auth.uid(),
      reviewed_at = now(),
      updated_at = now()
  WHERE id = p_request_id;

  RETURN jsonb_build_object(
    'success', true,
    'business_owner_id', p_business_owner_id,
    'auth_user_id', v_request.auth_user_id,
    'owner_code', v_owner.owner_code,
    'email', v_owner.email
  );
END;
$function$;
CREATE OR REPLACE FUNCTION public.change_admin_password(p_current_password text, p_new_password text)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
DECLARE
  v_admin public.admins%ROWTYPE;
  v_current_hash text;
  v_new_hash text;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'AUTH_REQUIRED';
  END IF;

  SELECT *
  INTO v_admin
  FROM public.admins
  WHERE id = auth.uid()
    AND is_active = true;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'ADMIN_NOT_FOUND';
  END IF;

  IF p_current_password IS NULL OR p_current_password='' THEN RAISE EXCEPTION 'CURRENT_PASSWORD_REQUIRED'; END IF;
  IF p_new_password IS NULL OR p_new_password='' THEN RAISE EXCEPTION 'PASSWORD_POLICY_VIOLATION'; END IF;
  v_current_hash := encode(
    extensions.digest(p_current_password || 'damda-salt-2024', 'sha256'),
    'hex'
  );

  IF v_current_hash IS DISTINCT FROM v_admin.password_hash THEN
    RAISE EXCEPTION 'CURRENT_PASSWORD_INVALID';
  END IF;

  IF p_new_password = p_current_password THEN
    RAISE EXCEPTION 'PASSWORD_REUSE_NOT_ALLOWED';
  END IF;

  IF length(p_new_password) < 8
    OR p_new_password !~ '[A-Za-z]'
    OR p_new_password !~ '[0-9]'
    OR p_new_password !~ '[^A-Za-z0-9]'
  THEN
    RAISE EXCEPTION 'PASSWORD_POLICY_VIOLATION';
  END IF;

  v_new_hash := encode(
    extensions.digest(p_new_password || 'damda-salt-2024', 'sha256'),
    'hex'
  );

  UPDATE public.admins
  SET password_hash = v_new_hash,
      updated_at = now()
  WHERE id = v_admin.id;

  INSERT INTO public.admin_logs (
    admin_id,
    action,
    target_type,
    target_id,
    before_data,
    after_data
  ) VALUES (
    v_admin.id,
    'update',
    'admin',
    v_admin.id,
    jsonb_build_object('password_changed', false),
    jsonb_build_object('password_changed', true)
  );

  RETURN true;
END;
$function$;
CREATE OR REPLACE FUNCTION public.check_reservation_available(p_product_id uuid, p_reserved_date date)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
DECLARE
  v_has_reservation BOOLEAN;
  v_has_hold BOOLEAN;
  v_hold_by_self BOOLEAN;
BEGIN
  IF (public.is_active_admin()
 OR (public.is_daycare() AND EXISTS(SELECT 1 FROM public.products p JOIN public.business_owners bo ON bo.id=p.business_owner_id WHERE p.id=p_product_id AND p.is_visible AND bo.status='active'))
 OR EXISTS(SELECT 1 FROM public.products p WHERE p.id=p_product_id AND public.is_current_business_owner(p.business_owner_id))
 OR auth.role()='service_role') IS NOT TRUE THEN
 RAISE EXCEPTION 'APPROVED_PRODUCT_ACCESS_REQUIRED' USING ERRCODE='42501'; END IF;
  -- Availability reads never delete another customer's holds.
  SELECT EXISTS (
    SELECT 1 FROM reservations
    WHERE product_id = p_product_id
      AND reserved_date = p_reserved_date
      AND status IN ('pending', 'paid', 'confirmed')
  ) INTO v_has_reservation;
  IF v_has_reservation THEN
    RETURN json_build_object('available', false, 'reason', 'already_reserved', 'message', '해당 날짜에 이미 예약이 있습니다.');
  END IF;
  SELECT 
    EXISTS (SELECT 1 FROM reservation_holds WHERE product_id = p_product_id AND reserved_date = p_reserved_date AND expires_at > now()),
    EXISTS (SELECT 1 FROM reservation_holds WHERE product_id = p_product_id AND reserved_date = p_reserved_date AND expires_at > now() AND daycare_id = auth.uid())
  INTO v_has_hold, v_hold_by_self;
  IF v_has_hold AND NOT v_hold_by_self THEN
    RETURN json_build_object('available', false, 'reason', 'hold_by_other', 'message', '다른 사용자가 결제를 진행 중입니다.');
  END IF;
  RETURN json_build_object('available', true, 'reason', null, 'message', null);
END;
$function$;
CREATE OR REPLACE FUNCTION public.cleanup_expired_holds()
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
BEGIN
 IF (public.is_daycare() OR public.is_active_admin() OR public.current_business_owner_id() IS NOT NULL OR auth.role()='service_role') IS NOT TRUE THEN
  RAISE EXCEPTION 'APPROVED_MEMBERSHIP_REQUIRED' USING ERRCODE='42501'; END IF;
 -- Expired holds must be reclaimed globally before a new customer can reserve
 -- the same product/date. The caller cannot select a customer or touch active holds.
 DELETE FROM public.reservation_holds WHERE expires_at < now();
END;
$function$;
CREATE OR REPLACE FUNCTION public.delete_business_owner_safely(p_business_owner_id uuid, p_confirmation_name text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
DECLARE
  v_owner public.business_owners%ROWTYPE;
  v_product_count integer;
  v_reservation_count integer;
  v_settlement_count integer;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.admins
    WHERE id = auth.uid() AND is_active = true
  ) THEN
    RAISE EXCEPTION 'ADMIN_REQUIRED';
  END IF;

  SELECT * INTO v_owner
  FROM public.business_owners
  WHERE id = p_business_owner_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'BUSINESS_OWNER_NOT_FOUND';
  END IF;
  IF btrim(COALESCE(p_confirmation_name, '')) <> v_owner.name THEN
    RAISE EXCEPTION 'CONFIRMATION_NAME_MISMATCH';
  END IF;

  SELECT count(*) INTO v_product_count FROM public.products
  WHERE business_owner_id = p_business_owner_id;
  SELECT count(*) INTO v_reservation_count FROM public.reservations
  WHERE business_owner_id = p_business_owner_id;
  SELECT count(*) INTO v_settlement_count FROM public.settlements
  WHERE business_owner_id = p_business_owner_id;

  IF v_product_count > 0 OR v_reservation_count > 0 OR v_settlement_count > 0 THEN
    RAISE EXCEPTION 'BUSINESS_OWNER_HAS_RELATED_DATA products=% reservations=% settlements=%',
      v_product_count, v_reservation_count, v_settlement_count;
  END IF;

  IF v_owner.auth_user_id IS NOT NULL THEN
    DELETE FROM public.user_roles
    WHERE id = v_owner.auth_user_id AND role = 'business_owner';
  END IF;

  DELETE FROM public.business_owners WHERE id = p_business_owner_id;

  RETURN jsonb_build_object(
    'success', true,
    'business_owner_id', p_business_owner_id,
    'name', v_owner.name
  );
END;
$function$;
CREATE OR REPLACE FUNCTION public.delete_business_safely(p_business_id uuid, p_confirmation_name text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
DECLARE v_business public.businesses%ROWTYPE; v_products integer; v_reservations integer;
BEGIN
  SELECT * INTO v_business FROM public.businesses WHERE id = p_business_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'BUSINESS_NOT_FOUND'; END IF;
  IF (v_business.business_owner_id = public.current_business_owner_id()
          OR EXISTS (SELECT 1 FROM public.admins WHERE id = auth.uid() AND is_active = true)) IS NOT TRUE THEN
    RAISE EXCEPTION 'BUSINESS_ACCESS_DENIED';
  END IF;
  IF btrim(COALESCE(p_confirmation_name, '')) <> v_business.name THEN
    RAISE EXCEPTION 'CONFIRMATION_NAME_MISMATCH';
  END IF;
  SELECT count(*) INTO v_products FROM public.products WHERE business_id = p_business_id;
  SELECT count(*) INTO v_reservations FROM public.reservations WHERE business_id = p_business_id;
  IF v_products > 0 OR v_reservations > 0 OR v_business.is_primary THEN
    RAISE EXCEPTION 'BUSINESS_HAS_RELATED_DATA_OR_IS_PRIMARY products=% reservations=%', v_products, v_reservations;
  END IF;
  DELETE FROM public.businesses WHERE id = p_business_id;
  RETURN jsonb_build_object('success', true, 'business_id', p_business_id);
END;
$function$;
CREATE OR REPLACE FUNCTION public.review_business_owner_signup(p_request_id uuid, p_status text, p_review_note text DEFAULT NULL::text, p_business_owner_id uuid DEFAULT NULL::uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
DECLARE
  v_request public.business_owner_signup_requests%ROWTYPE;
  v_business_owner_id uuid;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.admins
    WHERE id = auth.uid() AND is_active = true
  ) THEN
    RAISE EXCEPTION 'ADMIN_REQUIRED';
  END IF;

  IF p_status IS NULL OR p_status NOT IN ('approved','rejected','on_hold') THEN RAISE EXCEPTION 'INVALID_BUSINESS_SIGNUP_STATUS'; END IF;
  SELECT * INTO v_request
  FROM public.business_owner_signup_requests
  WHERE id = p_request_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'BUSINESS_SIGNUP_REQUEST_NOT_FOUND';
  END IF;

  IF p_status = 'approved' THEN
    IF v_request.status = 'approved' THEN
      UPDATE public.business_owner_signup_requests
      SET review_note = NULLIF(btrim(p_review_note), ''),
          reviewed_by = auth.uid(),
          reviewed_at = now(),
          updated_at = now()
      WHERE id = p_request_id;
      RETURN jsonb_build_object('success', true, 'status', 'approved');
    END IF;

    v_business_owner_id := COALESCE(
      v_request.matched_business_owner_id,
      p_business_owner_id
    );

    IF v_business_owner_id IS NOT NULL
       AND NOT EXISTS (
         SELECT 1 FROM public.business_owners
         WHERE id = v_business_owner_id
       ) THEN
      IF v_business_owner_id <> v_request.auth_user_id THEN
        RAISE EXCEPTION 'BUSINESS_OWNER_NOT_FOUND';
      END IF;
      v_business_owner_id := NULL;
    END IF;

    IF v_business_owner_id IS NULL THEN
      SELECT id INTO v_business_owner_id
      FROM public.business_owners
      WHERE auth_user_id = v_request.auth_user_id
      LIMIT 1
      FOR UPDATE;
    END IF;

    IF v_business_owner_id IS NULL THEN
      IF EXISTS (
        SELECT 1 FROM public.business_owners
        WHERE lower(btrim(email)) = lower(btrim(v_request.email))
           OR business_number = v_request.business_number
      ) THEN
        RAISE EXCEPTION 'BUSINESS_OWNER_SIGNUP_CONFLICT';
      END IF;

      INSERT INTO public.business_owners (
        id,
        auth_user_id,
        email,
        name,
        business_number,
        representative,
        contact_name,
        contact_phone,
        address,
        bank_name,
        bank_holder,
        bank_account,
        status
      ) VALUES (
        v_request.auth_user_id,
        v_request.auth_user_id,
        lower(btrim(v_request.email)),
        btrim(v_request.business_name),
        v_request.business_number,
        btrim(v_request.representative),
        btrim(v_request.contact_name),
        v_request.contact_phone,
        '',
        NULLIF(btrim(v_request.bank_name), ''),
        NULLIF(btrim(v_request.bank_holder), ''),
        NULLIF(v_request.bank_account, ''),
        'active'
      )
      RETURNING id INTO v_business_owner_id;
    END IF;

    PERFORM public.approve_business_owner_signup(
      p_request_id,
      v_business_owner_id
    );

    UPDATE public.business_owner_signup_requests
    SET review_note = NULLIF(btrim(p_review_note), ''),
        updated_at = now()
    WHERE id = p_request_id;

    RETURN jsonb_build_object(
      'success', true,
      'status', 'approved',
      'business_owner_id', v_business_owner_id
    );
  END IF;

  IF p_status NOT IN ('rejected', 'on_hold') THEN
    RAISE EXCEPTION 'INVALID_BUSINESS_SIGNUP_STATUS';
  END IF;

  IF v_request.status = 'approved'
     AND v_request.matched_business_owner_id IS NOT NULL THEN
    UPDATE public.business_owners
    SET status = 'inactive', updated_at = now()
    WHERE id = v_request.matched_business_owner_id;
  END IF;

  UPDATE public.business_owner_signup_requests
  SET status = p_status,
      review_note = NULLIF(btrim(p_review_note), ''),
      reviewed_by = auth.uid(),
      reviewed_at = now(),
      updated_at = now()
  WHERE id = p_request_id;

  RETURN jsonb_build_object('success', true, 'status', p_status);
END;
$function$;
REVOKE EXECUTE ON FUNCTION public.get_product_remaining(uuid,date) FROM PUBLIC,anon;
SELECT public.assert_payment_boundary();
DO $$BEGIN IF NOT (SELECT boundary_activated AND approvals_enabled FROM payment_private.configuration) THEN RAISE EXCEPTION 'Payment approvals disabled'; END IF; END$$;
SELECT jsonb_build_object('reviewed_callable_functions',25,'updated_functions',20,'payment_boundary_preserved',true) AS rpc_review_result;
COMMIT;
