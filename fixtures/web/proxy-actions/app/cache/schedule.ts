"use server";

import { unstable_cache } from "next/cache";
import { db } from "@/lib/db";

// NEEDS_REVIEW line 7: reported (never withheld), with a note that a gate exists.
export const getSchedule = unstable_cache(async (id: string) => db.schedule.find(id));
