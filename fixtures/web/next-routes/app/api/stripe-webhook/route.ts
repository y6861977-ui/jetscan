// NEGATIVE (WEB-AUTH-004): webhooks are public by design (path contains "webhook").
export async function POST(request: Request) {
  const event = await request.json();
  return Response.json({ received: event.type });
}
