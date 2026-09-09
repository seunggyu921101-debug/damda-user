-- INCIDENT RECOVERY ONLY: restores the reviewed but weaker prior authorization checks.
BEGIN;
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
  IF NOT EXISTS (SELECT 1 FROM public.admins WHERE id = auth.uid()) THEN
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
  IF NOT (v_business.business_owner_id = public.current_business_owner_id()
          OR EXISTS (SELECT 1 FROM public.admins WHERE id = auth.uid() AND is_active = true)) THEN
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
COMMIT;
