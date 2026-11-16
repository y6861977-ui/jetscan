import { revalidate } from "@/lib/shop";

// NEGATIVE: one-hop delegation to a function that checks a shared secret.
export async function POST(req: Request) {
  return revalidate(req);
}
