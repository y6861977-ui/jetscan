import type { GetServerSideProps } from "next";

// POSITIVE line 5: page components are bundled for the browser.
export default function Home({ stars }: { stars: number }) {
  const token = "@@GITHUB_TOKEN@@";
  return <p data-token-length={token.length}>{stars} stars</p>;
}

// NEGATIVE: Next.js strips getServerSideProps from the client bundle.
export const getServerSideProps: GetServerSideProps = async () => {
  const key = "@@STRIPE_SECRET@@";
  const res = await fetch("https://api.stripe.com/v1/balance", {
    headers: { Authorization: `Bearer ${key}` },
  });
  return { props: { stars: res.status } };
};
