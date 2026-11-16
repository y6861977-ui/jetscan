// Field test 2026-11-12, pattern 1: a project-local wrapper that verifies the cron signature.
import { verifyVercelSignature } from "./verify";

export const withCron =
  (handler: (req: Request) => Promise<Response>) => async (req: Request) => {
    await verifyVercelSignature(req);
    return handler(req);
  };
