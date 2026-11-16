// Field test 2026-11-12, W5: Next.js 16 renamed middleware.ts to proxy.ts.
import { NextResponse, type NextRequest } from "next/server";

export function proxy(request: NextRequest) {
  if (!request.cookies.get("session")) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
}

export const config = { matcher: ["/api/:path*"] };
