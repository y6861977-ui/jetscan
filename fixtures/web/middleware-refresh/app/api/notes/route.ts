// NEEDS_REVIEW line 2: reported — the session-refresh middleware does not withhold it.
export async function POST(request: Request) {
  return Response.json(await request.json());
}
