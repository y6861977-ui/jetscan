import { auth } from "@/auth";
import { db } from "@/lib/db";

// NEGATIVE (WEB-AUTH-004): the handler checks the session.
export async function POST(request: Request) {
  const session = await auth();
  if (!session?.user) return new Response(null, { status: 401 });
  await db.settings.update(await request.json());
  return Response.json({ ok: true });
}
