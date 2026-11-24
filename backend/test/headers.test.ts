import { describe, expect, test } from "bun:test";
import { headersToRecord } from "../src/lib/headers.ts";

describe("headersToRecord", () => {
  test("keeps a single value as a string", () => {
    const headers = new Headers({ "content-type": "image/webp", etag: '"1-2"' });
    expect(headersToRecord(headers)).toEqual({ "content-type": "image/webp", etag: '"1-2"' });
  });

  test("preserves every Set-Cookie instead of dropping all but the last", () => {
    const headers = new Headers();
    headers.append("link", '<a>; rel="one"');
    headers.append("link", '<b>; rel="two"');
    headers.append("set-cookie", "a=1");
    headers.append("set-cookie", "b=2");
    expect(headersToRecord(headers)["set-cookie"]).toEqual(["a=1", "b=2"]);
    // Bun's Headers.entries() coalesces other repeated headers into one value.
    expect(headersToRecord(headers).link).toBe('<a>; rel="one", <b>; rel="two"');
  });
});
