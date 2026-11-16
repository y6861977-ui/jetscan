import { db } from "@/lib/db";

// NEEDS_REVIEW (WEB-AUTH-004) line 5: DELETE via an arrow export, route group (shop) is not part of the URL.

export const DELETE = async (_req: Request, { params }: { params: { id: string } }) => {
  await db.cart.remove(params.id);
  return new Response(null, { status: 204 });
};
