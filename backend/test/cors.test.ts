import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { call, startApp, type TestApp } from "./helpers.ts";

let app: TestApp;
beforeAll(() => {
  app = startApp();
});
afterAll(() => app.stop());

describe("CORS allowlist", () => {
  test("echoes a listed origin and varies on Origin", async () => {
    const result = await call(app, "GET", "/.well-known/jwks.json", { headers: { origin: "https://calendar.test.local" } });
    expect(result.headers.get("access-control-allow-origin")).toBe("https://calendar.test.local");
    expect(result.headers.get("vary")).toContain("Origin");
  });

  test("sends no allow-origin header to an unlisted origin", async () => {
    const result = await call(app, "GET", "/.well-known/jwks.json", { headers: { origin: "https://evil.example" } });
    expect(result.headers.get("access-control-allow-origin")).toBeNull();
  });

  test("never answers with a wildcard once an allowlist is set", async () => {
    const result = await call(app, "GET", "/.well-known/jwks.json", { headers: { origin: "https://tracker.test.local" } });
    expect(result.headers.get("access-control-allow-origin")).not.toBe("*");
  });

  test("answers preflight requests", async () => {
    const result = await call(app, "OPTIONS", "/auth/login", {
      headers: { origin: "https://tracker.test.local", "access-control-request-method": "POST", "access-control-request-headers": "content-type,authorization" },
    });
    expect(result.status).toBe(204);
    expect(result.headers.get("access-control-allow-origin")).toBe("https://tracker.test.local");
    expect(result.headers.get("access-control-allow-headers")).toBe("content-type,authorization");
  });
});
