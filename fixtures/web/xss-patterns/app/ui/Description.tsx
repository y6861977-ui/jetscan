"use client";

import { renderMarkdown } from "@/lib/markdown";
import { markdownToSafeHTML } from "@acme/lib/markdown";

// NEGATIVE: renderMarkdown (defined in this project) sanitizes; markdownToSafeHTML says so by name.
export function Description({ text, desc }: { text: string; desc: string }) {
  return (
    <>
      <div dangerouslySetInnerHTML={{ __html: renderMarkdown(text) }} />
      <div dangerouslySetInnerHTML={{ __html: markdownToSafeHTML(desc) }} />
    </>
  );
}
