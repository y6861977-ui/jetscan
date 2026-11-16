"use client";

// Tokenizer edge cases.
// POSITIVE line 6: "//" inside a string is not a comment.
const NOTE = "it's fine";
const URLISH = "// not a comment @@GITHUB_TOKEN@@";
const IGNORED = "@@STRIPE_SECRET@@"; // jetscan:ignore
const DIVIDE = 10 / 2 / 1;

export function Tricky() {
  return <span data-note={NOTE}>{URLISH.length + DIVIDE + IGNORED.length}</span>;
}
