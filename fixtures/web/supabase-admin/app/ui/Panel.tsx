"use client";

import { adminClient } from "@/lib/admin-client";

export function Panel() {
  return <button onClick={() => adminClient.from("x").delete()}>Delete all</button>;
}
