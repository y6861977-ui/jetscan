import { createClient } from "@supabase/supabase-js";

// NEGATIVE: the anon key from VITE_SUPABASE_ANON_KEY is meant for the browser (RLS protects data).
export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY);

// POSITIVE line 7 (WEB-SUPABASE-005): new-format secret key in a Vite client module.
export const supabaseAdmin = createClient(import.meta.env.VITE_SUPABASE_URL, "@@SB_SECRET@@");
