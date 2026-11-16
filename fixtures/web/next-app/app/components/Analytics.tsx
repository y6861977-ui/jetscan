"use client";

// WEB-ENV-002 source references.
// Cross-referenced (the .env.local finding mentions this read): NEXT_PUBLIC_ADMIN_PASSWORD.
const adminPassword = process.env.NEXT_PUBLIC_ADMIN_PASSWORD;
// NEEDS_REVIEW line 7: secret-looking public variable read in client code, value not in .env files.
const signingSecret = process.env.NEXT_PUBLIC_SIGNING_SECRET;
// NEGATIVE: public by design.
const posthog = process.env.NEXT_PUBLIC_POSTHOG_KEY;
// NEGATIVE: a mention inside a string is not a read.
const doc = "process.env.NEXT_PUBLIC_FAKE_SECRET";

export function Analytics() {
  return <span>{[adminPassword, signingSecret, posthog, doc].length}</span>;
}
