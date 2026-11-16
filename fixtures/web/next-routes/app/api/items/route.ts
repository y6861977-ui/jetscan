import { db } from "@/lib/db";

// NEEDS_REVIEW (WEB-AUTH-004) line 6: state-changing handler, no access check in this file.
// TODO: add an auth check (a comment is not a check)

export async function POST(request: Request) {
  const item = await request.json();
  await db.items.insert(item);
  return Response.json({ ok: true });
}

// NEGATIVE: read-only handler is out of scope for this rule.
export async function GET() {
  return Response.json(await db.items.all());
}
