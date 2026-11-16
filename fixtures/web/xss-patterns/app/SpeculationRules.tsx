import Script from "next/script";

// Round 2, FP 5: JSON.stringify inside a JSON-typed <script> is LOW (line 10), also when wrapped in a template.
export function Speculation({ paths }: { paths: string[] }) {
  const speculationRules = { prerender: [{ source: "list", urls: paths }] };
  return (
    <Script
      id="speculation-rules"
      type="speculationrules"
      dangerouslySetInnerHTML={{
        __html: `${JSON.stringify(speculationRules)}`,
      }}
    />
  );
}

// LOW line 19: the type attribute comes after the sink.
export function ImportMap({ map }: { map: Record<string, string> }) {
  return <script dangerouslySetInnerHTML={{ __html: JSON.stringify(map) }} type="importmap" />;
}

// MEDIUM line 24: a plain <script> runs its content as JavaScript.
export function Boot({ state }: { state: Record<string, string> }) {
  return <script dangerouslySetInnerHTML={{ __html: JSON.stringify(state) }} />;
}
