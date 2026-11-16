"use server";

import { db } from "@/lib/db";

// NEEDS_REVIEW (WEB-AUTH-004) line 7: Server Actions are public POST endpoints; two exported, no check.

export async function deleteNote(id: string) {
  await db.notes.remove(id);
}

export const renameNote = async (id: string, title: string) => {
  await db.notes.update(id, { title });
};
