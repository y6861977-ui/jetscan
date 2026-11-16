"use client";

// POSITIVE line 6: a privileged Stripe key in a client component.
import { useState } from "react";

const STRIPE_SECRET = "@@STRIPE_SECRET@@";

// NEGATIVE: line comment — const OLD_TOKEN = "@@GITHUB_TOKEN@@";
/* NEGATIVE: block comment
   const ROTATED = "@@GITHUB_TOKEN@@";
*/

export default function Checkout() {
  const [paid, setPaid] = useState(false);
  return (
    <div>
      {/* NEGATIVE: JSX comment @@GITHUB_TOKEN@@ */}
      <button onClick={() => pay(STRIPE_SECRET).then(() => setPaid(true))}>
        {paid ? "Paid" : "Pay"}
      </button>
    </div>
  );
}

async function pay(key: string) {
  return fetch("/api/pay", { method: "POST", headers: { "x-key": key } });
}
