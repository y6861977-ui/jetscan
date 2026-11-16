"use client";

// Field test 2026-11-12, pattern 11 (seen in a real app's PEM helper): the PEM armour line is kept as
// a constant to strip/format keys. A header alone is not a key.
// NEGATIVE: header only, header with a newline, header used in code.
const HEADER = "@@PEM_HEADER@@";
const HEADER_NL = "@@PEM_HEADER@@\n";
export const strip = (pem: string) => pem.replace("@@PEM_HEADER@@", "").trim();

// POSITIVE line 11: a full (fake) key with a base64 body in client code.
export const EMBEDDED = `@@PEM_KEY@@`;

export function PemFormat() {
  return <code>{[HEADER, HEADER_NL].join(",")}</code>;
}
