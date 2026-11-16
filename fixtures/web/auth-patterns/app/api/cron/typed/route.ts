import { withCron } from "@/lib/cron/with-cron";

type Job = { id: string };

// NEGATIVE (round 2, N2): a project wrapper called with a type argument.
export const POST = withCron<Job>(async () => Response.json({ ok: true }));
