import type { NextApiRequest, NextApiResponse } from "next";
import { db } from "@/lib/db";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // NEEDS_REVIEW (WEB-AUTH-004) line 6: the "POST" literal on this line.
  if (req.method === "POST") {
    await db.notes.insert(req.body);
    return res.status(201).end();
  }
  res.status(200).json(await db.notes.all());
}
