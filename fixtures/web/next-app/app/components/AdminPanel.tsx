"use client";

import { createClient } from "@supabase/supabase-js";

// POSITIVE line 6 (WEB-SUPABASE-005): service-role JWT in a client component.
const admin = createClient("https://jetscanfixture.supabase.co", "@@SUPABASE_SERVICE_JWT@@");

// NEEDS_REVIEW line 9: a server-only variable read from client code (undefined in the browser).
const fromEnv = createClient("https://jetscanfixture.supabase.co", process.env.SUPABASE_SERVICE_ROLE_KEY!);

// Read of the public variable flagged in .env.local by WEB-SUPABASE-005 (not repeated by WEB-ENV-002).
const leaked = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;

export function AdminPanel() {
  return <span>{[admin, fromEnv, leaked].length}</span>;
}
