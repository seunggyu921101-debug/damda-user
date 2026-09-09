-- Public partner inquiries remain available before membership approval.
-- Applicants may create only a new pending inquiry, never an admin review.
BEGIN;
SET LOCAL lock_timeout='3s';
DO $review$
BEGIN
 IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename='partner_inquiries'
  AND policyname='Anyone can insert partner inquiries' AND cmd='INSERT'
  AND roles=ARRAY['anon','authenticated']::name[] AND with_check='true')
 OR EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename='partner_inquiries'
  AND cmd IN ('INSERT','ALL') AND policyname<>'Anyone can insert partner inquiries'
  AND (roles<>ARRAY['authenticated']::name[] OR with_check IS DISTINCT FROM 'is_active_admin()')) THEN
  RAISE EXCEPTION 'INQUIRY_REVIEW_REQUIRED: unexpected submission policies';
 END IF;
END $review$;
ALTER POLICY "Anyone can insert partner inquiries" ON public.partner_inquiries
 WITH CHECK (
  status='pending' AND reviewed_by IS NULL AND reviewed_at IS NULL
  AND rejection_reason IS NULL AND memo IS NULL
  AND length(btrim(name))>=2 AND length(btrim(representative))>=2
  AND length(btrim(contact_name))>=2 AND length(btrim(business_number))>=10
  AND contact_phone ~ '^[0-9-]{10,}$'
  AND email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
  AND length(btrim(coalesce(program_types,'')))>=2
  AND length(btrim(coalesce(description,'')))>=10
 );
SELECT jsonb_build_object('phase','partner-inquiry-submission','pending_only',true,'review_fields_protected',true) AS inquiry_result;
COMMIT;
