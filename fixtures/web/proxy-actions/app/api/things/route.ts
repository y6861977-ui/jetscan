// NEEDS_REVIEW line 2: /api/things is not covered by the matcher (not even by /:path*/embed).
export async function POST(request: Request) {
  return Response.json(await request.json());
}
