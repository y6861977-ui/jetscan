// Field test 2026-11-12, W4 (seen in a real Supabase starter): the middleware only refreshes the
// session cookie and never blocks a request — it is not an access gate.
import { type NextRequest } from "next/server";
import { updateSession } from "@/utils/supabase/middleware";

export async function middleware(request: NextRequest) {
  return await updateSession(request);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)"],
};
