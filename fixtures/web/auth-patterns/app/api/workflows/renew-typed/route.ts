import { serve } from "@upstash/workflow/nextjs";

type Input = { domain: string };

// NEGATIVE (round 2, N2): TypeScript type arguments between the wrapper and its call.
export const { POST } = serve<Input>(async (context) => {
  await context.run("renew", async () => ({ ok: context.requestPayload.domain }));
});
