import { withCron } from "../../../../lib/cron/with-cron";

// NEGATIVE: `export { handler as POST }` of a wrapped local (relative import).
const handler = withCron(async () => Response.json({ queued: true }));

export { handler as GET, handler as POST };
