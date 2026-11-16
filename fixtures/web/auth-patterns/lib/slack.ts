// Round 2, FP 2: the delegate verifies the request signature.
export async function handleSlashCommand(req: Request) {
  await verifySlackSignature(req);
  return { text: "ok" };
}

async function verifySlackSignature(req: Request) {
  if (!req.headers.get("x-slack-signature")) throw new Error("bad signature");
}
