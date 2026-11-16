// POSITIVE line 3: everything under src/ in a Vite SPA ends up in the browser bundle.

const STRIPE_SECRET = "@@STRIPE_SECRET@@";

export default function App() {
  return <button onClick={() => charge(STRIPE_SECRET)}>Pay</button>;
}

function charge(key: string) {
  return fetch("https://api.stripe.com/v1/charges", { headers: { Authorization: `Bearer ${key}` } });
}
