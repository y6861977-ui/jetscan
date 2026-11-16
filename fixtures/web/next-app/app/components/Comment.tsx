"use client";

import DOMPurify from "dompurify";
import { useSearchParams } from "next/navigation";

export function Comment({ html, bio }: { html: string; bio: string }) {
  const params = useSearchParams();
  return (
    <div>
      <div dangerouslySetInnerHTML={{ __html: html }} />
      <div dangerouslySetInnerHTML={{ __html: params.get("q") ?? "" }} />
      <div dangerouslySetInnerHTML={{ __html: "<b>Static, trusted</b>" }} />
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(bio) }} />
    </div>
  );
}

// Line 10: POSITIVE medium (value not visibly from a source).
// Line 11: POSITIVE high (searchParams visible in the expression).
// Line 12: NEGATIVE constant. Line 13: NEGATIVE sanitized.

export function legacy(el: HTMLElement, name: string) {
  el.innerHTML = "<i>loading</i>" + "<b>…</b>";
  el.innerHTML = escapeHtml(name);
  el.innerHTML = `<p>${name}</p>`;
  el.insertAdjacentHTML("beforeend", location.hash.slice(1));
  if (el.innerHTML === "") el.textContent = name;
  // el.innerHTML = name;
  el.innerHTML = `<hr/>`;
}

// Line 23: NEGATIVE constants. Line 24: NEGATIVE escaped. Line 25: POSITIVE medium (template with ${}).
// Line 26: POSITIVE high (location). Line 27: NEGATIVE comparison / textContent.
// Line 28: NEGATIVE comment. Line 29: NEGATIVE template without ${}.

function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}
