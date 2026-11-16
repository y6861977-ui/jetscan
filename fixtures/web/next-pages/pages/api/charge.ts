import type { NextApiRequest, NextApiResponse } from "next";

// NEGATIVE (WEB-SECRET-001): Pages Router API routes run on the server only.
const STRIPE_SECRET = "@@STRIPE_SECRET@@";

export default function handler(_req: NextApiRequest, res: NextApiResponse) {
  res.status(200).json({ configured: STRIPE_SECRET.length > 0 });
}
