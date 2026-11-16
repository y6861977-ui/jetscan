import "server-only";
import { createClient } from "@supabase/supabase-js";

// NEGATIVE (WEB-SUPABASE-005): server-only module, the right place for a service-role client.
export const supabaseAdmin = createClient(
  "https://jetscanfixture.supabase.co",
  "@@SUPABASE_SERVICE_JWT@@",
);
export const fromEnv = process.env.SUPABASE_SERVICE_ROLE_KEY;
