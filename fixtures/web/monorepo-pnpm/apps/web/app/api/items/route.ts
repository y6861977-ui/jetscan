// Seen only when apps/web is scanned on its own (AUTH-004 is not applicable at the generic root).
export async function POST(request: Request) {
  return Response.json(await request.json());
}
