// NEGATIVE (WEB-SECRET-001): tests are not part of the production bundle.
const KEY = "@@STRIPE_SECRET@@";

test("key length", () => {
  expect(KEY.length).toBeGreaterThan(10);
});
