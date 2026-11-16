// LOW line 4 (pattern 7): JSON.stringify of data in ld+json — "</script>" is not escaped.
export function ProductJsonLd({ product }: { product: Record<string, string> }) {
  return (
    <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(product) }} />
  );
}
