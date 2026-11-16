import { trackDownload } from "photo-sdk";

// NEEDS_REVIEW line 4 (a real TP pattern): an unauthenticated POST spending the server's credentials.
export async function POST(req: Request) {
  const { url } = await req.json();
  return Response.json(await trackDownload(url));
}
