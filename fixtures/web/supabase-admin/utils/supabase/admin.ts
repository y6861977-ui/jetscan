import { createClient } from "@supabase/supabase-js";

// Field test 2026-11-12, pattern 10: no "server-only" marker, but imported only by server files.
// INFO line 7: reported as a hardening hint, not as client-reachable code.
export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);
