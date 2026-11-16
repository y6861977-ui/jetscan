// Withheld: proxy.ts is an access gate and its matcher covers /api.
export async function POST(request: Request) {
  return Response.json(await request.json());
}
