// Field test round 2, N5 (seen in a real Next 16 app): an access gate whose matcher lists a few
// pages and one parameter-first pattern. `/:path*/embed` matches only paths ending in /embed.
import { NextResponse, type NextRequest } from "next/server";

export function proxy(request: NextRequest) {
  if (!request.cookies.get("session")) {
    return NextResponse.redirect(new URL("/auth/login", request.url));
  }
}

export const config = {
  matcher: ["/auth/login", "/login", "/apps/installed", "/:path*/embed", "/availability", "/api/auth/signup"],
};
