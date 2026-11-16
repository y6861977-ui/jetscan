// NEGATIVE (WEB-SECRET-001): App Router route handler runs on the server only.
const STRIPE_SECRET = "@@STRIPE_SECRET@@";
// NEGATIVE (WEB-ENV-002): a server-only file reading a public variable is not the exposure itself.
const routeSecret = process.env.NEXT_PUBLIC_ROUTE_SECRET;

export async function POST() {
  return Response.json({ configured: STRIPE_SECRET.length > 0 && Boolean(routeSecret) });
}
