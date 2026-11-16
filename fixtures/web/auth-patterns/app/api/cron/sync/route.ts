import { withCron } from "@/lib/cron/with-cron";

// NEGATIVE: wrapped by a local function that verifies the signature (resolved via @/ alias).
export const POST = withCron(async () => {
  return Response.json({ synced: true });
});
