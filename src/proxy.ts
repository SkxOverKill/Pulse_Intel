import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const SESSION_COOKIE = "pulse_session";

// Routes reachable without a session.
const PUBLIC_PATHS = ["/login", "/forbidden"];

/// Renamed from `middleware` in Next.js 16.
///
/// This is deliberately a *cheap* check: cookie present or not. Next's guidance
/// is that proxy must not rely on shared modules or globals, so it never touches
/// the database. Real session verification lives in the DAL (`src/lib/auth/dal.ts`)
/// and runs on every protected page. This only saves an obviously-anonymous
/// visitor a wasted render.
export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (PUBLIC_PATHS.some((p) => pathname.startsWith(p))) {
    return NextResponse.next();
  }

  const hasCookie = request.cookies.has(SESSION_COOKIE);
  if (!hasCookie) {
    const url = new URL("/login", request.url);
    // Preserve where they were heading so login can bounce them back.
    if (pathname !== "/") url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  // Exclude API routes, Next internals, and static assets. Without this, auth
  // redirects would swallow CSS and JS requests.
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|.*\\.svg$).*)"],
};
