import { NextResponse } from "next/server";
import { requireUser } from "@/lib/auth/dal";
import { search } from "@/lib/search/query";

/**
 * JSON search endpoint backing the command palette. Thin wrapper around the
 * existing `search()` used by `/search` — no new search logic here.
 */
export async function GET(request: Request) {
  await requireUser();
  const { searchParams } = new URL(request.url);
  const q = searchParams.get("q") ?? "";
  const hits = await search(q);
  return NextResponse.json({ hits });
}
