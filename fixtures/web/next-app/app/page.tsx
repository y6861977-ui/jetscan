// NEGATIVE (WEB-SECRET-001): Server Component by default (no "use client").
// The same fake key as in components/Checkout.tsx, but it never reaches the browser.
const STRIPE_KEY = "@@STRIPE_SECRET@@";

export default async function Home() {
  const res = await fetch("https://api.stripe.com/v1/balance", {
    headers: { Authorization: `Bearer ${STRIPE_KEY}` },
  });
  return <main>jetscan fixture: Next.js App Router ({res.status})</main>;
}
