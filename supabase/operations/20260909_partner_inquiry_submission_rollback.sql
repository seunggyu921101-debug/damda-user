-- INCIDENT RECOVERY ONLY: restores the previous unrestricted INSERT policy.
BEGIN;
SET LOCAL lock_timeout='3s';
ALTER POLICY "Anyone can insert partner inquiries" ON public.partner_inquiries WITH CHECK (true);
COMMIT;
