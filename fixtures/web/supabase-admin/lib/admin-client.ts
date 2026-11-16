import { createClient } from "@supabase/supabase-js";

// MEDIUM line 5: a client component imports this module (see app/ui/Panel.tsx).
export const adminClient = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!,
);
