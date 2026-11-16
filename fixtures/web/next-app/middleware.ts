// NEGATIVE (WEB-SECRET-001): middleware runs on the server (edge runtime).
const ADMIN_TOKEN = "@@GITHUB_TOKEN@@";

export function middleware(request: Request) {
  return request.headers.get("x-admin") === ADMIN_TOKEN ? undefined : new Response(null, { status: 401 });
}
