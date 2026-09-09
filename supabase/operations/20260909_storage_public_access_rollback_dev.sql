-- INCIDENT RECOVERY ONLY: restores prior broader storage permissions.
BEGIN;
SET LOCAL lock_timeout='3s';
DROP POLICY IF EXISTS "Public Access" ON storage.objects;
DROP POLICY IF EXISTS "Authenticated users can upload" ON storage.objects;
DROP POLICY IF EXISTS "Authenticated users can update" ON storage.objects;
DROP POLICY IF EXISTS "Authenticated users can delete" ON storage.objects;
DROP POLICY IF EXISTS "Business owners upload own product images" ON storage.objects;
DROP POLICY IF EXISTS "Business owners delete own product images" ON storage.objects;
CREATE POLICY "Business owners delete own product images" ON storage.objects AS PERMISSIVE FOR DELETE TO "authenticated" USING (((bucket_id = 'public'::text) AND ((storage.foldername(name))[1] = 'product-images'::text) AND (EXISTS ( SELECT 1
   FROM business_owners owner
  WHERE (((owner.id)::text = (storage.foldername((owner.name)::text))[2]) AND (owner.auth_user_id = auth.uid()))))));
CREATE POLICY "Business owners upload own product images" ON storage.objects AS PERMISSIVE FOR INSERT TO "authenticated" WITH CHECK (((bucket_id = 'public'::text) AND ((storage.foldername(name))[1] = 'product-images'::text) AND (EXISTS ( SELECT 1
   FROM business_owners owner
  WHERE (((owner.id)::text = (storage.foldername((owner.name)::text))[2]) AND (owner.auth_user_id = auth.uid()) AND ((owner.status)::text = 'active'::text))))));
COMMIT;
