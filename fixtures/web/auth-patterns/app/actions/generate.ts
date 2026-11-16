"use server";

import { streamText } from "ai";
import { llm } from "@/lib/llm";

// NEEDS_REVIEW line 7 (a real TP pattern): a public action calling a paid model with no check.
export async function generateFilters(prompt: string) {
  return streamText({ model: llm("large"), prompt });
}
