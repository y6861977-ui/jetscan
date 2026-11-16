import { serve } from "@upstash/workflow/nextjs";

// NEGATIVE: the workflow package verifies the QStash signature itself.
export const { POST } = serve(async (context) => {
  await context.run("renew", async () => ({ ok: true }));
});
