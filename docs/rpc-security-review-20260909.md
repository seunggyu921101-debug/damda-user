# Callable function security review — 2026-09-09

Follow-up to `security-warning-cleanup-20260909.md`. Reviewed all 25 client-callable public SECURITY DEFINER functions in each database against current definitions, grants, calling code and membership rules. Development and production have 24 functions in common: development additionally has `get_product_remaining`; production additionally has `get_public_popular_businesses`.

The guarded development and production operations have been applied after rollback rehearsals. Each updates 20 function definitions. No application runtime files, approval switches, customer passwords or financial records were changed. Development anonymous capacity lookup execution was revoked. Other required client and server grants were retained.

## Confirmed issues and corrections

1. Pending members could query unavailable reservation dates and invoke expired-hold cleanup. Date/capacity access now requires an approved daycare viewing a visible product from an active owner, the product's active owner, an active administrator, or the server role. Cleanup requires current approved membership/active ownership/admin/server. Availability reads no longer delete holds. Explicit cleanup still reclaims expired holds globally, which is necessary to release the unique product/date slot for the next customer; active holds remain untouched.
2. `is_business_owner` trusted a stale role record after the owner was deactivated. It now also requires a current active owner record.
3. An already authenticated active administrator could pass NULL as the current password to bypass its comparison in `change_admin_password`. NULL/empty inputs are now rejected and hash comparison uses `IS DISTINCT FROM`. This was reproduced with synthetic local passwords; no real administrator password was read or changed. This finding does not mean an ordinary member could become an administrator.
4. A valid business preview token returned unnecessary business registration/contact data. Preview responses now use explicit field allowlists, omitting internal business registration/contact metadata, internal date-block reasons and automatic confirmation settings. Token validation and both data functions bind the token to the product's current active owner, preventing reuse after an ownership transfer. Public display information and the selected draft product remain available to a valid link. Visible sibling products must belong to the same business and owner.
5. Tightened NULL status validation for signup review, NULL analytics metric validation and deleted-account exclusion from masked email recovery. Hardened applicable definer search paths with `pg_catalog` first and explicit `pg_temp` last. Existing empty paths and the payment boundary's exact owner/path configuration were preserved.

## Per-function decisions

“Member” means authenticated execution is granted; the function's internal checks further restrict what the caller can do. Anonymous role helpers only inspect the current identity and do not grant roles.

| Function | Retained access and review outcome |
| --- | --- |
| `create_verified_payment_order` | Member; existing verified boundary requires approved membership and server-computed pricing. Definition and owner unchanged; actual development positive/negative checkout verified with rollback. |
| `get_user_role` | Anonymous/member; returns only the caller's own role metadata. It is not sufficient by itself to authorize an operation. |
| `is_daycare` | Anonymous/member; checks current approval, nondeletion and daycare role. Existing guard retained. |
| `is_business_owner` | Anonymous/member; now requires current active ownership as well as role. |
| `is_active_admin` | Anonymous/member; checks the caller's active administrator record. |
| `current_business_owner_id` | Anonymous/member; returns only the caller's active owner ID. |
| `is_current_business_owner` | Anonymous/member; checks supplied owner against the caller's active owner. |
| `get_unavailable_dates` | Member; new current membership/product access guard; read only. |
| `check_reservation_available` | Member; same guard; read only. |
| `get_product_remaining` (development) | Member only after this patch; same membership/product guard. |
| `cleanup_expired_holds` | Member; new approval/active-owner/admin guard; only expired holds can be reclaimed. Server execution retained. |
| `change_admin_password` | Active administrator only; fixed NULL current-password bypass. |
| `approve_partner_onboarding` | Active administrator only; previously fixed guard retained. |
| `approve_business_owner_signup` | Active administrator only; existing guard retained. |
| `review_business_owner_signup` | Active administrator only; additionally validates non-NULL review status. |
| `create_admin_product_preview_token` | Active administrator only; existing product lookup and bounded token workflow retained. |
| `delete_business_owner_safely` | Active administrator only, existing record/name and business constraints retained. |
| `delete_daycare_safely` | Active administrator only, existing record/name and reservation constraints retained. |
| `delete_business_safely` | Active owning business or active administrator; prior NULL ownership fix retained. |
| `get_site_analytics` | Active administrator only; existing maximum 370-day range retained. |
| `validate_product_preview_token` | Anonymous/member; exact product/token, expiry and current active owner binding required. |
| `get_product_preview` | Anonymous/member; same token checks and explicit output allowlists. |
| `get_business_product_preview` | Anonymous/member; same checks plus exact business/product binding and restricted business fields. |
| `find_masked_daycare_email` | Anonymous/member; exact supplied name/phone, masked result; deleted accounts excluded. Public account-recovery functionality intentionally retained. |
| `track_site_analytics` | Anonymous/member; bounded metric names, daily visitor deduplication and NULL rejection. Public counters intentionally retained. |
| `get_public_popular_businesses` (production) | Anonymous/member; explicit public display fields for active/visible businesses and products, capped at 12 rows. Public homepage showcase intentionally retained. |

## Validation and limits

- Eleven local PGlite tests passed, including four new development/production reproduction and role/output matrix tests. Fixtures contain schema/function metadata and synthetic records, no exported customer rows. The password reproduction uses real pgcrypto hashing locally.
- Matrix checks cover approved/pending/revoked daycare accounts, active/inactive business owners, active/inactive administrators and anonymous callers. Negative admin calls, valid/wrong/expired/mismatched/transferred preview tokens, output exclusions, active/expired holds and NULL inputs are exercised.
- Local fixtures simplify table constraints and omit notification triggers. Admin approval/deletion positive checks exercise authorization and record validation, not complete real customer approval/deletion workflows. No real onboarding, deletion, password change, message send or charge was performed.
- Both live databases passed read-only membership/date/invalid-preview checks, payment boundary assertion, enabled payment approvals and retained server Alimtalk execution. These checks simulate JWT context in a privileged transaction; they do not replace a browser login test.
- Development actual current functions successfully created an unpaid order with server pricing and rejected an unapproved caller. The entire transaction was rolled back; zero payments and zero reservations were created.
- Production HTTP checks: homepage/login 200, protected products/cart/checkout redirect to login, existing product image 200 `image/jpeg`.
- Next.js production webpack build, TypeScript and all 55 pages completed successfully. Existing middleware convention and webpack cache notices remain unrelated to these database changes. Reapplying the development patch in a rollback rehearsal also passed its body/owner and payment checks.
- Effective public SECURITY DEFINER client grants after this review: production 12 anonymous + 25 member; development 11 anonymous + 25 member. These are catalog counts, not a new dashboard linter export. Many Advisor warnings remain because required functions still have execution grants; count reduction is not a measure of whether their internal authorization is correct.

## Remaining separate work

- Public document URLs and the pre-login document upload/cleanup flow still need the coordinated private-file migration described in the earlier report. This function review does not make those documents private.
- Public email recovery and analytics remain callable directly. Masking/validation/deduplication do not provide per-client rate limiting or prevent counters being inflated with different visitor IDs. Additional abuse controls would require an endpoint and grant transition.
- The existing custom administrator password store uses a legacy digest scheme. This patch closes its NULL comparison bypass; migration of administrator authentication/password storage requires a separate coordinated change.
- Development notification-worker isolation remains separate; tests intentionally avoid actual notification triggers.

## Operations and recovery

Use `20260909_rpc_review_dev.sql` only for development and `20260909_rpc_review_prod.sql` only for production. Both verify reviewed function body hashes and ownership before replacing definitions inside one transaction. They assert the payment boundary and approval setting before commit and accept their own resulting body hashes for reapplication. `20260909_rpc_review_verify.sql` performs read-only postchecks.

Corresponding rollback files restore previous definitions and can reopen the confirmed weaknesses. They are incident recovery tools, not normal completion steps. Inspect intervening changes before use. Rollback restores development anonymous capacity access directly to `anon`, not a broader PUBLIC grant.
