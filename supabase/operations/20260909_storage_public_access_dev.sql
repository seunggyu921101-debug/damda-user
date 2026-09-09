-- Apply once against the reviewed dev policy snapshot. No objects or bucket publicity are changed.
BEGIN;
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
DO $review$
DECLARE expected jsonb:=$snapshot$[{"cmd":"DELETE","permissive":"PERMISSIVE","policyname":"Business owners delete own product images","qual":"((bucket_id = 'public'::text) AND ((storage.foldername(name))[1] = 'product-images'::text) AND (EXISTS ( SELECT 1\n   FROM business_owners owner\n  WHERE (((owner.id)::text = (storage.foldername((owner.name)::text))[2]) AND (owner.auth_user_id = auth.uid())))))","roles":["authenticated"],"schemaname":"storage","tablename":"objects","with_check":null},{"cmd":"INSERT","permissive":"PERMISSIVE","policyname":"Business owners upload own product images","qual":null,"roles":["authenticated"],"schemaname":"storage","tablename":"objects","with_check":"((bucket_id = 'public'::text) AND ((storage.foldername(name))[1] = 'product-images'::text) AND (EXISTS ( SELECT 1\n   FROM business_owners owner\n  WHERE (((owner.id)::text = (storage.foldername((owner.name)::text))[2]) AND (owner.auth_user_id = auth.uid()) AND ((owner.status)::text = 'active'::text)))))"}]$snapshot$::jsonb; actual jsonb;
BEGIN
 SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.policyname),'[]') INTO actual
 FROM pg_policies p WHERE schemaname='storage' AND tablename='objects' AND policyname=ANY(ARRAY['Public Access','Authenticated users can upload','Authenticated users can update','Authenticated users can delete','Business owners upload own product images','Business owners delete own product images']);
 IF actual IS DISTINCT FROM (SELECT jsonb_agg(value ORDER BY value->>'policyname') FROM jsonb_array_elements(expected)) THEN
  RAISE EXCEPTION 'STORAGE_ACCESS_REVIEW_REQUIRED: policies changed'; END IF;
END $review$;
DROP POLICY IF EXISTS "Public Access" ON storage.objects;
DROP POLICY IF EXISTS "Authenticated users can upload" ON storage.objects;
DROP POLICY IF EXISTS "Authenticated users can update" ON storage.objects;
DROP POLICY IF EXISTS "Authenticated users can delete" ON storage.objects;
DROP POLICY IF EXISTS "Business owners upload own product images" ON storage.objects;
DROP POLICY IF EXISTS "Business owners delete own product images" ON storage.objects;
CREATE POLICY "Public Access" ON storage.objects FOR SELECT TO authenticated
 USING ((bucket_id = 'public' AND (
 public.is_active_admin()
 OR ((storage.foldername(name))[1] = 'daycare-documents'
     AND (storage.foldername(name))[2] = auth.uid()::text
     AND EXISTS(SELECT 1 FROM public.daycares d WHERE d.id=auth.uid() AND d.deleted_at IS NULL))
 OR ((storage.foldername(name))[1] = 'reviews'
     AND (storage.foldername(name))[2] = auth.uid()::text AND public.is_daycare())
 OR ((storage.foldername(name))[1] = 'product-images'
     AND (storage.foldername(name))[2] = public.current_business_owner_id()::text)
)));
CREATE POLICY "Authenticated users can upload" ON storage.objects FOR INSERT TO authenticated
 WITH CHECK ((bucket_id = 'public' AND (
 public.is_active_admin()
 OR ((storage.foldername(name))[1] = 'daycare-documents'
     AND (storage.foldername(name))[2] = auth.uid()::text
     AND EXISTS(SELECT 1 FROM public.daycares d WHERE d.id=auth.uid() AND d.deleted_at IS NULL))
 OR ((storage.foldername(name))[1] = 'reviews'
     AND (storage.foldername(name))[2] = auth.uid()::text AND public.is_daycare())
 OR ((storage.foldername(name))[1] = 'product-images'
     AND (storage.foldername(name))[2] = public.current_business_owner_id()::text)
)));
CREATE POLICY "Authenticated users can update" ON storage.objects FOR UPDATE TO authenticated
 USING ((bucket_id = 'public' AND (
 public.is_active_admin()
 OR ((storage.foldername(name))[1] = 'daycare-documents'
     AND (storage.foldername(name))[2] = auth.uid()::text
     AND EXISTS(SELECT 1 FROM public.daycares d WHERE d.id=auth.uid() AND d.deleted_at IS NULL))
 OR ((storage.foldername(name))[1] = 'reviews'
     AND (storage.foldername(name))[2] = auth.uid()::text AND public.is_daycare())
 OR ((storage.foldername(name))[1] = 'product-images'
     AND (storage.foldername(name))[2] = public.current_business_owner_id()::text)
))) WITH CHECK ((bucket_id = 'public' AND (
 public.is_active_admin()
 OR ((storage.foldername(name))[1] = 'daycare-documents'
     AND (storage.foldername(name))[2] = auth.uid()::text
     AND EXISTS(SELECT 1 FROM public.daycares d WHERE d.id=auth.uid() AND d.deleted_at IS NULL))
 OR ((storage.foldername(name))[1] = 'reviews'
     AND (storage.foldername(name))[2] = auth.uid()::text AND public.is_daycare())
 OR ((storage.foldername(name))[1] = 'product-images'
     AND (storage.foldername(name))[2] = public.current_business_owner_id()::text)
)));
CREATE POLICY "Authenticated users can delete" ON storage.objects FOR DELETE TO authenticated
 USING ((bucket_id = 'public' AND (
 public.is_active_admin()
 OR ((storage.foldername(name))[1] = 'daycare-documents'
     AND (storage.foldername(name))[2] = auth.uid()::text
     AND EXISTS(SELECT 1 FROM public.daycares d WHERE d.id=auth.uid() AND d.deleted_at IS NULL))
 OR ((storage.foldername(name))[1] = 'reviews'
     AND (storage.foldername(name))[2] = auth.uid()::text AND public.is_daycare())
 OR ((storage.foldername(name))[1] = 'product-images'
     AND (storage.foldername(name))[2] = public.current_business_owner_id()::text)
)));
-- Business product uploads are covered by the correctly qualified folder predicate above.
SELECT public.assert_payment_boundary();
SELECT jsonb_build_object('phase','storage-public-access','anonymous_public_list_policy',false,
 'authenticated_paths_scoped',true,'public_bucket_unchanged',(SELECT public FROM storage.buckets WHERE id='public'),
 'scoped_policies',(SELECT count(*) FROM pg_policies WHERE schemaname='storage' AND tablename='objects' AND policyname=ANY(ARRAY['Public Access','Authenticated users can upload','Authenticated users can update','Authenticated users can delete']))) AS storage_access_result;
COMMIT;
