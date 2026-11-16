import { NextResponse } from "next/server";
import { handleSlashCommand } from "@/lib/slack";

// NEGATIVE (round 2, FP 2): delegation wrapped in a response constructor.
export async function POST(req: Request) {
  return NextResponse.json(await handleSlashCommand(req));
}
