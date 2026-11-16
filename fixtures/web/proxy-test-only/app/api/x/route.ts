// NEEDS_REVIEW line 2: reported — there is no real gate, only test files.
export async function POST(request: Request) {
  return Response.json(await request.json());
}
