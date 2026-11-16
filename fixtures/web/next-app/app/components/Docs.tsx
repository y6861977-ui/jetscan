'use client';

// NEGATIVE file: key-shaped text that is not a key.
const LIVE_KEY_PATTERN = /^sk_live_[0-9a-zA-Z]{24,}$/;
const HELP = "Secret keys start with \"sk_live_\" and must stay on the server";
const ESCAPED = "sk_live_ABC is shown escaped in docs";
const PLACEHOLDER = "@@STRIPE_PLACEHOLDER@@";
const TEMPLATE = "<your-key>";
const FROM_ENV = process.env.STRIPE_SECRET_KEY;
const INTERPOLATED = `sk_live_${process.env.SUFFIX}`;

export function KeyHelp() {
  return (
    <p title={HELP}>
      {LIVE_KEY_PATTERN.test(String(FROM_ENV)) ? "ok" : TEMPLATE} {PLACEHOLDER} {ESCAPED}
      {INTERPOLATED}
    </p>
  );
}
