// Field test 2026-11-12, W4 (seen in a real Next.js starter): an access gate whose matcher does not
// include /api — it cannot cover the API route handlers, so nothing there may be withheld.
import { withAuth } from "next-auth/middleware";
import { NextResponse } from "next/server";

export default withAuth(async function middleware(req) {
  if (!req.nextauth.token) return NextResponse.redirect(new URL("/login", req.url));
});

export const config = {
  matcher: ["/dashboard/:path*", "/editor/:path*", "/login", "/register"],
};
