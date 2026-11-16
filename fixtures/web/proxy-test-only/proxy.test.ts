// Field test round 2, N3: a unit test for the proxy is not the proxy. It mentions sessions and
// builds redirects, but it never runs in front of a route.
import { NextResponse } from "next/server";
import { proxy } from "./lib/proxy-impl";

test("redirects without a session cookie", () => {
  const expected = NextResponse.redirect(new URL("/login", "https://example.test"));
  const res = proxy(new Request("https://example.test/api/x") as never);
  expect(res?.status).toBe(expected.status);
});
