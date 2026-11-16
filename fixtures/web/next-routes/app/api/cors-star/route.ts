// POSITIVE (WEB-CORS-006, low / needs_review) line 5: "*" with credentials (browsers refuse it).
export async function GET() {
  return Response.json({ ok: true }, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": "true",
    },
  });
}
