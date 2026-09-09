-- INCIDENT RECOVERY ONLY. Restores prior reviewed definitions, including their weaker checks.
BEGIN;
SET LOCAL lock_timeout='3s';
CREATE OR REPLACE FUNCTION public.is_business_owner()
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
  SELECT EXISTS (
    SELECT 1 FROM user_roles 
    WHERE id = auth.uid() AND role = 'business_owner'
  );
$function$;
CREATE OR REPLACE FUNCTION public.is_active_admin()
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.admins
    WHERE id = auth.uid()
      AND is_active = true
  );
$function$;
CREATE OR REPLACE FUNCTION public.change_admin_password(p_current_password text, p_new_password text)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'extensions'
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

  v_current_hash := encode(
    extensions.digest(p_current_password || 'damda-salt-2024', 'sha256'),
    'hex'
  );

  IF v_current_hash <> v_admin.password_hash THEN
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
CREATE OR REPLACE FUNCTION public.current_business_owner_id()
 RETURNS uuid
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
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
 SET search_path TO 'public'
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
 SET search_path TO 'public'
AS $function$
  SELECT EXISTS (
    SELECT 1 FROM public.business_owners
    WHERE id = p_business_owner_id AND auth_user_id = auth.uid() AND status = 'active'
  );
$function$;
CREATE OR REPLACE FUNCTION public.approve_business_owner_signup(p_request_id uuid, p_business_owner_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
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
CREATE OR REPLACE FUNCTION public.review_business_owner_signup(p_request_id uuid, p_status text, p_review_note text DEFAULT NULL::text, p_business_owner_id uuid DEFAULT NULL::uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
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
CREATE OR REPLACE FUNCTION public.validate_product_preview_token(p_product_id uuid, p_token uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.product_preview_tokens ppt
    WHERE ppt.product_id = p_product_id
      AND ppt.token = p_token
      AND ppt.expires_at > now()
  );
$function$;
CREATE OR REPLACE FUNCTION public.get_product_preview(p_product_id uuid, p_token uuid)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  SELECT to_jsonb(p) || jsonb_build_object(
    'business_owner', jsonb_build_object(
      'id', coalesce(b.id, bo.id),
      'name', coalesce(b.name, bo.name),
      'logo_url', coalesce(b.logo_url, bo.logo_url)
    ),
    'category', CASE
      WHEN c.id IS NULL THEN NULL
      ELSE jsonb_build_object('id', c.id, 'name', c.name, 'parent_id', c.parent_id)
    END,
    'images', coalesce((
      SELECT jsonb_agg(to_jsonb(pi) ORDER BY pi.sort_order)
      FROM public.product_images pi
      WHERE pi.product_id = p.id
    ), '[]'::jsonb),
    'options', coalesce((
      SELECT jsonb_agg(to_jsonb(po) ORDER BY po.sort_order)
      FROM public.product_options po
      WHERE po.product_id = p.id
    ), '[]'::jsonb),
    'unavailable_dates', coalesce((
      SELECT jsonb_agg(to_jsonb(pud) ORDER BY pud.unavailable_date)
      FROM public.product_unavailable_dates pud
      WHERE pud.product_id = p.id
    ), '[]'::jsonb)
  )
  FROM public.product_preview_tokens ppt
  JOIN public.products p ON p.id = ppt.product_id
  JOIN public.business_owners bo ON bo.id = p.business_owner_id
  LEFT JOIN public.businesses b ON b.id = p.business_id
  LEFT JOIN public.categories c ON c.id = p.category_id
  WHERE ppt.token = p_token
    AND ppt.product_id = p_product_id
    AND ppt.expires_at > now()
    AND bo.status = 'active';
$function$;
CREATE OR REPLACE FUNCTION public.find_masked_daycare_email(p_name text, p_phone text)
 RETURNS text
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_email text;
  v_local text;
  v_domain text;
  v_phone text := regexp_replace(COALESCE(p_phone, ''), '[^0-9]', '', 'g');
BEGIN
  IF length(trim(COALESCE(p_name, ''))) < 1 OR length(v_phone) NOT BETWEEN 10 AND 11 THEN
    RETURN NULL;
  END IF;
  SELECT email INTO v_email
  FROM public.daycares
  WHERE name = trim(p_name)
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
 SET search_path TO 'public'
AS $function$
DECLARE
  v_business_owner_id uuid;
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM public.admins
    WHERE id = auth.uid() AND is_active = true
  ) THEN
    RAISE EXCEPTION 'ADMIN_REQUIRED';
  END IF;

  SELECT p.business_owner_id
  INTO v_business_owner_id
  FROM public.products p
  WHERE p.id = p_product_id;

  IF v_business_owner_id IS NULL THEN
    RAISE EXCEPTION 'PRODUCT_NOT_FOUND';
  END IF;

  DELETE FROM public.product_preview_tokens ppt
  WHERE ppt.product_id = p_product_id
    AND ppt.expires_at <= now();

  RETURN QUERY
  INSERT INTO public.product_preview_tokens(product_id, business_owner_id)
  VALUES (p_product_id, v_business_owner_id)
  RETURNING product_preview_tokens.token, product_preview_tokens.expires_at;
END;
$function$;
CREATE OR REPLACE FUNCTION public.get_business_product_preview(p_business_id uuid, p_product_id uuid, p_token uuid)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  WITH preview_product AS (
    SELECT p.*
    FROM public.product_preview_tokens ppt
    JOIN public.products p ON p.id = ppt.product_id
    JOIN public.business_owners bo ON bo.id = p.business_owner_id
    WHERE ppt.token = p_token
      AND ppt.product_id = p_product_id
      AND ppt.expires_at > now()
      AND p.business_id = p_business_id
      AND bo.status = 'active'
  )
  SELECT jsonb_build_object(
    'business', to_jsonb(b) || jsonb_build_object(
      'place_profile', (
        SELECT to_jsonb(profile)
        FROM public.business_place_profiles profile
        WHERE profile.business_id = b.id
        LIMIT 1
      ),
      'images', coalesce((
        SELECT jsonb_agg(to_jsonb(image) ORDER BY image.is_primary DESC, image.sort_order ASC)
        FROM public.business_place_images image
        WHERE image.business_id = b.id
      ), '[]'::jsonb),
      'hours', coalesce((
        SELECT jsonb_agg(to_jsonb(hour) ORDER BY hour.day_of_week ASC)
        FROM public.business_hours hour
        WHERE hour.business_id = b.id
      ), '[]'::jsonb)
    ),
    'products', coalesce((
      SELECT jsonb_agg(
        to_jsonb(listed_product) || jsonb_build_object(
          'business_owner', jsonb_build_object(
            'id', b.id,
            'name', b.name,
            'logo_url', b.logo_url
          ),
          'business', jsonb_build_object(
            'id', b.id,
            'name', b.name,
            'logo_url', b.logo_url
          ),
          'category', CASE
            WHEN category.id IS NULL THEN NULL
            ELSE jsonb_build_object(
              'id', category.id,
              'name', category.name,
              'parent_id', category.parent_id
            )
          END,
          'images', coalesce((
            SELECT jsonb_agg(to_jsonb(product_image) ORDER BY product_image.sort_order ASC)
            FROM public.product_images product_image
            WHERE product_image.product_id = listed_product.id
          ), '[]'::jsonb),
          'review_count', (
            SELECT count(*)
            FROM public.reviews review
            WHERE review.product_id = listed_product.id
              AND review.is_visible = true
          ),
          'average_rating', coalesce((
            SELECT round(avg(review.rating)::numeric, 1)
            FROM public.reviews review
            WHERE review.product_id = listed_product.id
              AND review.is_visible = true
          ), 0)
        )
        ORDER BY
          CASE WHEN listed_product.id = p_product_id THEN 0 ELSE 1 END,
          listed_product.display_order ASC,
          listed_product.created_at DESC
      )
      FROM public.products listed_product
      LEFT JOIN public.categories category ON category.id = listed_product.category_id
      WHERE listed_product.business_id = b.id
        AND (
          listed_product.id = p_product_id
          OR (listed_product.is_visible = true AND listed_product.is_sold_out = false)
        )
    ), '[]'::jsonb)
  )
  FROM preview_product target_product
  JOIN public.businesses b ON b.id = target_product.business_id;
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
  IF p_metric_key NOT IN ('daily_visit', 'partner_cta_click', 'signup_cta_click') THEN
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
CREATE OR REPLACE FUNCTION public.get_public_popular_businesses(p_limit integer DEFAULT 8)
 RETURNS TABLE(business_id uuid, business_name text, business_logo_url text, region text, featured_product_id uuid, featured_product_name text, featured_product_thumbnail text, discount_rate integer)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public'
AS $function$
  WITH ranked_products AS (
    SELECT
      b.id AS business_id,
      b.name AS business_name,
      b.logo_url AS business_logo_url,
      p.region,
      p.id AS product_id,
      p.name AS product_name,
      p.thumbnail AS product_thumbnail,
      p.view_count,
      p.created_at AS product_created_at,
      max(
        CASE
          WHEN p.original_price > p.sale_price AND p.original_price > 0
            THEN round(((p.original_price - p.sale_price)::numeric / p.original_price) * 100)::integer
          ELSE 0
        END
      ) OVER (PARTITION BY b.id) AS max_discount_rate,
      row_number() OVER (
        PARTITION BY b.id
        ORDER BY p.view_count DESC, p.created_at DESC, p.id
      ) AS product_rank
    FROM public.products p
    INNER JOIN public.businesses b
      ON b.id = p.business_id
      AND b.status = 'active'
      AND b.is_visible = true
    INNER JOIN public.business_owners bo
      ON bo.id = p.business_owner_id
      AND bo.status = 'active'
    WHERE p.is_visible = true
      AND p.is_sold_out = false
      AND p.name !~* '(test|테스트)'
      AND b.name !~* '(test|테스트)'
  )
  SELECT
    business_id,
    business_name,
    business_logo_url,
    region,
    product_id,
    product_name,
    product_thumbnail,
    max_discount_rate
  FROM ranked_products
  WHERE product_rank = 1
  ORDER BY view_count DESC, product_created_at DESC, business_id
  LIMIT least(greatest(coalesce(p_limit, 8), 1), 12);
$function$;
CREATE OR REPLACE FUNCTION public.delete_business_owner_safely(p_business_owner_id uuid, p_confirmation_name text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
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
CREATE OR REPLACE FUNCTION public.get_unavailable_dates(p_product_id uuid)
 RETURNS text[]
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
DECLARE
  result TEXT[];
BEGIN
  -- 만료된 홀드 정리
  DELETE FROM reservation_holds WHERE expires_at < now();
  
  -- 예약이 있는 날짜 + 홀드가 있는 날짜 조회
  SELECT ARRAY_AGG(DISTINCT reserved_date::TEXT)
  INTO result
  FROM (
    -- 예약이 있는 날짜
    SELECT reserved_date
    FROM reservations
    WHERE product_id = p_product_id
      AND status IN ('pending', 'paid', 'confirmed')
    
    UNION
    
    -- 홀드가 있는 날짜 (현재 사용자 제외)
    SELECT reserved_date
    FROM reservation_holds
    WHERE product_id = p_product_id
      AND expires_at > now()
      AND daycare_id != COALESCE(auth.uid(), '00000000-0000-0000-0000-000000000000'::UUID)
  ) AS unavailable;
  
  RETURN COALESCE(result, ARRAY[]::TEXT[]);
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
  -- 만료된 홀드 정리
  DELETE FROM reservation_holds WHERE expires_at < now();
  
  -- 1. 예약이 있는지 확인
  SELECT EXISTS (
    SELECT 1 FROM reservations
    WHERE product_id = p_product_id
      AND reserved_date = p_reserved_date
      AND status IN ('pending', 'paid', 'confirmed')
  ) INTO v_has_reservation;
  
  IF v_has_reservation THEN
    RETURN json_build_object(
      'available', false,
      'reason', 'already_reserved',
      'message', '해당 날짜에 이미 예약이 있습니다.'
    );
  END IF;
  
  -- 2. 다른 사용자의 홀드가 있는지 확인
  SELECT 
    EXISTS (
      SELECT 1 FROM reservation_holds
      WHERE product_id = p_product_id
        AND reserved_date = p_reserved_date
        AND expires_at > now()
    ),
    EXISTS (
      SELECT 1 FROM reservation_holds
      WHERE product_id = p_product_id
        AND reserved_date = p_reserved_date
        AND expires_at > now()
        AND daycare_id = auth.uid()
    )
  INTO v_has_hold, v_hold_by_self;
  
  IF v_has_hold AND NOT v_hold_by_self THEN
    RETURN json_build_object(
      'available', false,
      'reason', 'hold_by_other',
      'message', '다른 사용자가 결제를 진행 중입니다.'
    );
  END IF;
  
  RETURN json_build_object(
    'available', true,
    'reason', null,
    'message', null
  );
END;
$function$;
CREATE OR REPLACE FUNCTION public.cleanup_expired_holds()
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
AS $function$
BEGIN 
  DELETE FROM reservation_holds WHERE expires_at < now(); 
END;
$function$;
CREATE OR REPLACE FUNCTION public.delete_business_safely(p_business_id uuid, p_confirmation_name text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
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
SELECT public.assert_payment_boundary();
COMMIT;
