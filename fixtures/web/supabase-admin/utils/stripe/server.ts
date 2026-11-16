"use server";

import { supabaseAdmin } from "../supabase/admin";

export async function syncCustomer(id: string) {
  const { data } = await supabaseAdmin.auth.admin.getUserById(id);
  return data.user?.id ?? null;
}
