import { getServerSession } from "next-auth";

// NEGATIVE: checks the session itself.
export async function POST(request: Request) {
  const session = await getServerSession();
  if (!session) return new Response(null, { status: 403 });
  return Response.json(await request.json());
}
