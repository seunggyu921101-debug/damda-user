# Security warning cleanup — 2026-09-09

Applied directly to the development (`tcdvvslgfapjhqlicadx`) and production (`eifpjjoawsgdmeeuzhin`) databases after local validation and rollback rehearsals. Application runtime files, payment approval switches, financial records and notification delivery were not changed.

## Rechecked outcome

| Security Advisor | Before | After |
| --- | ---: | ---: |
| Production errors | 0 | 0 |
| Production warnings | 80 | 37 |
| Development errors | 0 | 0 |
| Development warnings | 75 | 37 |

Rerun linter in both dashboards confirmed the final counts. Production retains 6 informational suggestions; development retains 2. The remaining 37 warnings are 12 anonymous and 25 authenticated SECURITY DEFINER execution warnings. They concern role helpers, preview/lookup/analytics endpoints and guarded member/admin operations. Their existence is not proof of a vulnerability, and their retention is not a blanket security clearance. Do not revoke all of them or switch SECURITY DEFINER off to hide the warnings.

## Applied changes

- `20260909_function_access_phase3.sql`: restricts 26 production / 24 development functions. Trigger-only functions, scheduled reservation completion/booking-window renewal, document numbering and the internal order implementation lose client execution. Member/admin RPCs lose anonymous execution. The verified checkout wrapper retains its authenticated grant, and its `damda_payment_code` owner receives an explicit grant to the internal implementation. Server grants and scheduled jobs remain available. Reviewed body hashes and ownership prevent applying this against an unreviewed function definition. This operation is idempotent.
- `20260909_storage_public_access_{dev,prod}.sql`: replaces broad public-bucket file listing/write policies with active-admin or own-folder checks. Signup/revision documents permit the current nondeleted daycare's own `daycare-documents/<id>/` folder even before approval; reviews require an approved daycare; business images require the current active business owner. Admin file management remains available. The broken legacy comparison to `business_owners.name` is removed. Existing file contents, public URLs and bucket publicity are unchanged. This is a one-time, snapshot-guarded operation; use the correct environment file.
- `20260909_partner_inquiry_submission.sql`: preserves public inquiry submission, but requires pending status, empty internal review fields and valid required form fields. Applicants cannot inject approved status, reviewer identity, review time, rejection reasons or internal memo. Admin review policies remain available. This is a one-time guarded operation. This is not a rate limiter or anti-spam service.
- `20260909_rpc_authorization_guards.sql`: fixes the NULL ownership comparison in `delete_business_safely`, using `IS NOT TRUE` to reject an unknown/absent owner. Also requires an active admin in `approve_partner_onboarding`. The original deletion bypass was reproduced only in a local fixture; no real business was deleted. This operation is idempotent.
- Supabase Auth → Email → **Prevent use of leaked passwords** enabled and saved in both projects, then reopened to confirm the switch remained enabled. No other email-provider switches or password-length settings were changed. This dashboard setting is separate from SQL and must also be configured when provisioning another environment.

## Verification

- Seven PGlite regression tests pass using reviewed function definitions and storage-policy snapshots: trigger execution after ACL reduction, scheduled completion, direct-call rejection, rollback/reapplication, changed-definition atomic failure, own-folder file operations and cross-user denial, normal public inquiries versus forged admin fields, NULL ownership rejection, active/inactive admin approval guard.
- Development checkout exercised the actual current DB functions after final changes with a simulated authenticated JWT: approved order creation and server-calculated amount succeeded; unapproved caller was rejected. The whole transaction was rolled back. Existing managed order count was 1, temporarily 2 during the test; no payment or reservation was created and no payment gateway was contacted.
- Production and development read-only checks: anonymous public object listing denied; unconditional inquiry INSERT count 0; payment approvals enabled; server Alimtalk execution retained; payment boundary assertion passed.
- Existing production product image returned HTTP 200 `image/jpeg`. Production `/` and `/login` returned 200; unauthenticated `/products`, `/cart`, `/checkout` returned 307 to login.
- Next.js webpack build, TypeScript and all 55 pages completed successfully. Existing middleware naming/cache-size notices remain unrelated to Supabase security warnings. There are no application runtime source changes in this cleanup.

## Recovery and follow-up

Corresponding `_rollback` files restore the reviewed previous behavior and can reopen the security weaknesses. They are incident recovery tools, not post-success steps. Restore only the affected operation, after checking intervening changes. Restoring the leaked-password switch is a separate dashboard action.

The retained function ACL warnings require per-function authorization/output review if further reduction is desired. In particular, client-called cleanup and date availability helpers still have member execution; preview tokens and public email lookup are intentionally reachable before login. The current checkout wrapper must remain callable by authenticated customers.

Separate document security work remains: historical daycare/vendor documents still use public URLs, and the private business-signup bucket uses a pre-login upload/cleanup flow that needs a scoped upload token and submitted-document ownership checks. Blocking public object listing does not make existing public document URLs private. These flows need coordinated user/business/admin application changes and file migration; they were not silently converted during this SQL cleanup. The old anonymous `licenses/` upload policy also remains pending that migration. Development notification-worker isolation remains separate from the warning cleanup.

References: [Supabase Storage access control](https://supabase.com/docs/guides/storage/security/access-control), [Supabase password security](https://supabase.com/docs/guides/auth/password-security), [PostgreSQL CREATE TRIGGER](https://www.postgresql.org/docs/current/sql-createtrigger.html).
