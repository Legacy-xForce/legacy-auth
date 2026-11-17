import { describe, expect, test } from "bun:test";
import { createTestUser, loginOk, startApp, call } from "./helpers.ts";

describe("Hono owns path and method dispatch for the OIDC registry", () => {
  test("malformed client ids, unknown subpaths, wrong verbs and the bare path are 404", async () => {
    const app = startApp();
    const admin = await createTestUser({ role: "admin" });
    const token = (await loginOk(app, admin)).access_token;
    try {
      const cases = [
        ["GET", "/admin/oidc/clients/x"], // too short for a client id
        ["GET", "/admin/oidc/clients/UPPER"], // wrong character class
        ["GET", "/admin/oidc/clients/valid-id/unknown"], // no such action
        ["DELETE", "/admin/oidc/clients/valid-id"], // no such verb
        ["GET", "/admin/oidc"], // bare prefix, never a registry path
      ] as const;
      for (const [method, path] of cases) {
        const result = await call(app, method, path, { token });
        expect(result.status).toBe(404);
      }
    } finally {
      app.stop();
    }
  });

  test("a non-admin never reaches the Hono registry router", async () => {
    const app = startApp();
    const user = await createTestUser();
    const token = (await loginOk(app, user)).access_token;
    try {
      const result = await call(app, "GET", "/admin/oidc/clients", { token });
      expect(result.status).toBe(403);
      expect(result.body.error).toBe("Admin role required");
    } finally {
      app.stop();
    }
  });
});
