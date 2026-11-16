// Field test 2026-11-12, pattern 7: values that are constant by construction (all NEGATIVE).
const RULES = { prerender: [{ source: "document", where: { href_matches: "/*" } }], eagerness: 1 };

export function SpeculationRules() {
  return <script type="speculationrules" dangerouslySetInnerHTML={{ __html: JSON.stringify(RULES) }} />;
}

export function Gtm() {
  return <script dangerouslySetInnerHTML={{ __html: `window.gtmId = "${process.env.NEXT_PUBLIC_GTM_ID}";` }} />;
}

export function PageStatus({ missing }: { missing: boolean }) {
  let pageStatus = "200";
  if (missing) pageStatus = "404";
  return <script dangerouslySetInnerHTML={{ __html: `window.pageStatus = "${pageStatus}";` }} />;
}
