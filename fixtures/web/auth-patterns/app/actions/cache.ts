"use server";

import { revalidateTag, unstable_cache } from "next/cache";
import { db } from "@/lib/db";

// NOT counted: cache purge only.
export async function bustSchedule() {
  revalidateTag("schedule");
}

// NEEDS_REVIEW line 12 (W7): not `async` itself, but a callable action that takes any id.
export const getSchedule = unstable_cache(async (id: string) => db.schedule.find(id));
