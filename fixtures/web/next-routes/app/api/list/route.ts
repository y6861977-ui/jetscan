// NEGATIVE (WEB-AUTH-004): GET only.
export async function GET() {
  return Response.json([]);
}
