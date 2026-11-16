import { createClient } from "@supabase/supabase-js";

// The anon key is meant for the browser: not a finding. Data safety depends on RLS (WEB-RLS-009).
export const supabase = createClient("https://jetscanfixture.supabase.co", "@@SUPABASE_ANON_JWT@@");
