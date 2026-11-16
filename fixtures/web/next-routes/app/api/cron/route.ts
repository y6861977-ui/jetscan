// NEGATIVE (WEB-AUTH-004): shared-secret check (Authorization: Bearer CRON_SECRET).
export async function POST(request: Request) {
  if (request.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response(null, { status: 401 });
  }
  return Response.json({ ran: true });
}
