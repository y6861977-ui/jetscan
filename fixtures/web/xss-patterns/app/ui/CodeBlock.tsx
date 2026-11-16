"use client";

import { useEffect, useState } from "react";
import { codeToHtml } from "shiki";

// INFO line 13 (pattern 6): highlighter output reaches the sink through state.
export function CodeBlock({ code }: { code: string }) {
  const [html, setHtml] = useState("");
  useEffect(() => {
    codeToHtml(code, { lang: "ts", theme: "github-dark" }).then(setHtml);
  }, [code]);
  return (
    <div dangerouslySetInnerHTML={{ __html: html }} />
  );
}
