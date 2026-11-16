// MEDIUM line 7 (a real TP pattern: raw CMS HTML). The sink spans lines — the excerpt must show
// the __html line too (pattern 8).
export function Prose({ html }: { html: string }) {
  return (
    <div
      className="prose"
      dangerouslySetInnerHTML={{
        __html: html,
      }}
    />
  );
}

// MEDIUM line 17 (a real TP pattern): user-entered value interpolated into HTML.
export function DomainHint({ domain }: { domain: { name: string } }) {
  return (
    <p dangerouslySetInnerHTML={{ __html: `Add <code>${domain.name}</code> to your DNS` }} />
  );
}
