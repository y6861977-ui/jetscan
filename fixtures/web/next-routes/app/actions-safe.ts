"use server";

import { getSession } from "@/lib/session";
import { db } from "@/lib/db";

// NEGATIVE (WEB-AUTH-004): every action checks the session.
export async function archiveNote(id: string) {
  const session = await getSession();
  if (!session) throw new Error("not signed in");
  await db.notes.archive(id, session.userId);
}
