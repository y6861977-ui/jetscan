// Reported: /pages-like/save is outside the proxy matcher (/api/:path*).
export async function PUT(request: Request) {
  return Response.json(await request.json());
}
