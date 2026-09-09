import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

// 로그인 없이 접근 가능한 공개 경로
const PUBLIC_PATHS = [
  "/",
  "/login",
  "/api/auth/login",
  "/signup",
  "/partner",
  "/free-forms",
  "/faq",
  "/notice",
  "/refund-policy",
  "/reservation-guide",
  "/privacy",
  "/terms",
  "/email-rejection",
  "/find-email",
  "/find-password",
  "/reset-password",
  "/auth/callback",
  "/sitemap.xml",
  "/robots.txt",
];

// 폐쇄형 서비스의 회원 전용 경로는 과거에 공유되었더라도 검색 결과에 남지 않도록 응답 단계에서 차단합니다.
const SEARCH_EXCLUDED_PATH_PREFIXES = [
  "/businesses",
  "/products",
  "/home",
  "/mypage",
  "/cart",
  "/checkout",
];
const SEARCH_EXCLUDED_ROBOTS = "noindex, nofollow, noarchive, nosnippet, noimageindex";

function isSearchExcludedPath(pathname: string): boolean {
  return SEARCH_EXCLUDED_PATH_PREFIXES.some(
    (path) => pathname === path || pathname.startsWith(`${path}/`)
  );
}

function applySearchExclusion(response: NextResponse): NextResponse {
  response.headers.set("X-Robots-Tag", SEARCH_EXCLUDED_ROBOTS);
  return response;
}

function isPublicPath(pathname: string): boolean {
  // 정확히 일치하거나 하위 경로인 경우 허용
  return PUBLIC_PATHS.some(
    (path) => pathname === path || pathname.startsWith(`${path}/`)
  );
}

export async function updateSession(request: NextRequest) {
  const pathname = request.nextUrl.pathname;

  // Route handlers are responsible for their own JSON authentication responses.
  // Redirecting an API call to the login page turns a 401/400 into a misleading
  // 200 HTML response and breaks payment callbacks and client error handling.
  if (pathname.startsWith('/api/')) {
    return NextResponse.next({ request });
  }

  let supabaseResponse = NextResponse.next({
    request,
  });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) =>
            request.cookies.set(name, value)
          );
          supabaseResponse = NextResponse.next({
            request,
          });
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  // IMPORTANT: Avoid writing any logic between createServerClient and
  // supabase.auth.getUser(). A simple mistake could make it very hard to debug
  // issues with users being randomly logged out.

  const {
    data: { user },
  } = await supabase.auth.getUser();

  // 미리보기 토큰 바이패스
  const previewToken = request.nextUrl.searchParams.get('preview_token')
  const productPathMatch = pathname.match(/^\/products\/([0-9a-f-]{36})$/)
  const businessPathMatch = pathname.match(/^\/businesses\/([0-9a-f-]{36})$/)
  const previewProductId = productPathMatch?.[1]
    || (businessPathMatch ? request.nextUrl.searchParams.get('preview_product_id') : null)

  if (previewToken && previewProductId) {
    const { data: isValidPreview, error: previewValidationError } = await supabase.rpc(
      'validate_product_preview_token',
      {
        p_product_id: previewProductId,
        p_token: previewToken,
      },
    )

    if (previewValidationError) {
      console.error('Preview token validation failed:', previewValidationError.message)
    }

    if (isValidPreview) {
      const requestHeaders = new Headers(request.headers)
      requestHeaders.set('x-preview-mode', 'true')
      return NextResponse.next({ request: { headers: requestHeaders } })
    }
    // 토큰 무효 → 일반 인증 플로우로 fallthrough
  }

  // 로그인하지 않은 사용자가 보호된 페이지에 접근하면 로그인 페이지로 리다이렉트
  if (!user && !isPublicPath(pathname)) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("redirect", pathname);
    const response = NextResponse.redirect(loginUrl);
    return isSearchExcludedPath(pathname) ? applySearchExclusion(response) : response;
  }

  // Every member page requires current approval, including list/cart/checkout routes.
  // Signup status/revision pages and validated previews use the explicit paths above.
  if (user && !isPublicPath(pathname)) {
    const { data: daycare } = await supabase
      .from('daycares')
      .select('status, deleted_at')
      .eq('id', user.id)
      .single()

    if (!daycare || daycare.status !== 'approved' || daycare.deleted_at) {
      if (daycare?.status === 'rejected') {
        return NextResponse.redirect(new URL('/signup/rejected', request.url))
      } else if (daycare?.status === 'revision_required') {
        return NextResponse.redirect(new URL('/signup/revision', request.url))
      } else {
        return NextResponse.redirect(new URL('/signup/complete', request.url))
      }
    }
  }

  // 로그인된 사용자가 로그인/회원가입 페이지에 접근하면 상태에 따라 리다이렉트
  if (user && (pathname === "/login" || pathname === "/signup")) {
    const { data: daycare } = await supabase
      .from("daycares")
      .select("status")
      .eq("id", user.id)
      .single();

    if (daycare?.status === "approved") {
      return NextResponse.redirect(new URL("/home", request.url));
    } else if (daycare?.status === "rejected") {
      return NextResponse.redirect(new URL("/signup/rejected", request.url));
    } else if (daycare?.status === "revision_required") {
      return NextResponse.redirect(new URL("/signup/revision", request.url));
    } else {
      // pending 등
      return NextResponse.redirect(new URL("/signup/complete", request.url));
    }
  }

  return isSearchExcludedPath(pathname) ? applySearchExclusion(supabaseResponse) : supabaseResponse;
}
