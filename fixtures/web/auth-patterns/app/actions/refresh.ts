"use server";

import { revalidatePath, revalidateTag } from "next/cache";

// NEGATIVE (pattern 3): actions that only purge the cache.
export async function refreshAvailability() {
  revalidatePath("/availability");
}

export const refreshTeam = async (slug: string) => revalidateTag(`team-${slug}`);
