import { supabaseAdmin } from "@/utils/supabase/admin";

export async function POST(request: Request) {
  const event = await request.json();
  await supabaseAdmin.from("events").insert(event);
  return Response.json({ received: true });
}
