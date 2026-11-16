// Field test 2026-11-12, pattern 5: a project function whose definition calls a sanitizer.
import sanitizeHtml from "sanitize-html";
import { marked } from "marked";

export function renderMarkdown(md: string): string {
  return sanitizeHtml(marked.parse(md) as string);
}
