// POSITIVE (WEB-CORS-006, high) line 5: echoes the caller's Origin and allows credentials.
export async function GET(request: Request) {
  return Response.json(await profile(), {
    headers: {
      "Access-Control-Allow-Origin": request.headers.get("origin") ?? "",
      "Access-Control-Allow-Credentials": "true",
    },
  });
}

async function profile() {
  return { name: "jetscan fixture" };
}
