// NEGATIVE (WEB-CORS-006): a public, credential-less API may use "*".
export async function GET() {
  return Response.json({ version: 1 }, { headers: { "Access-Control-Allow-Origin": "*" } });
}

// NEGATIVE: an allowlisted origin variable is not treated as reflection.
const ALLOWED = ["https://app.example"];
export function headersFor(origin: string) {
  return ALLOWED.includes(origin)
    ? { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true" }
    : {};
}
