import type { NextApiRequest, NextApiResponse } from "next";

// NEGATIVE (WEB-AUTH-004): health checks are public by design.
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "POST") return res.status(405).end();
  res.status(200).json({ ok: true });
}
