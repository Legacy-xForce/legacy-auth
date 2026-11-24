/**
 * Shared ETag / conditional-GET handling for file-backed responses.
 *
 * The validator is derived from the file's size and mtime, which change on every
 * write, so a replaced avatar or rebuilt frontend asset gets a new ETag without
 * having to hash the whole file on each request.
 */
import type { Ctx } from "./lib/context.ts";
import { headersToRecord } from "./lib/headers.ts";

type File = ReturnType<typeof Bun.file>;

export function fileEtag(file: File): string {
  return `"${file.size.toString(16)}-${Math.trunc(file.lastModified).toString(16)}"`;
}

function matchesIfNoneMatch(header: string | null, etag: string): boolean {
  if (!header) return false;
  if (header.trim() === "*") return true;
  // ETags are compared without the weak prefix; a client may send a list.
  return header.split(",").some((candidate) => candidate.trim().replace(/^W\//i, "") === etag);
}

export async function serveStaticFile(c: Ctx, file: File, headers: HeadersInit = {}): Promise<Response> {
  const responseHeaders = new Headers(headers);
  const etag = fileEtag(file);
  responseHeaders.set("ETag", etag);

  const record = headersToRecord(responseHeaders);
  if (matchesIfNoneMatch(c.req.header("if-none-match") ?? null, etag)) {
    return c.newResponse(null, 304, record);
  }

  return c.newResponse(file as any, 200, record);
}
