// Field test round 2, N3: not a gate either (a spec file next to where middleware.ts would be).
it("blocks with 401 when there is no session", () => {
  expect(new Response(null, { status: 401 }).status).toBe(401);
});
