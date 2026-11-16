// Field test 2026-11-12, pattern 2: the handler delegates here, and this function checks a secret.
export async function revalidate(req: Request): Promise<Response> {
  const given = new URL(req.url).searchParams.get("secret");
  if (given !== process.env.SHOP_REVALIDATION_SECRET) {
    return new Response(null, { status: 401 });
  }
  return Response.json({ revalidated: true });
}
