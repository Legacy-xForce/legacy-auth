import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { call, startApp, type TestApp } from "./helpers.ts";

let app: TestApp;
let doc: any;

beforeAll(async () => {
  app = startApp();
  doc = (await call(app, "GET", "/openapi.json")).body;
});
afterAll(() => app.stop());

const operations = () =>
  Object.entries<any>(doc.paths).flatMap(([path, item]) =>
    Object.entries<any>(item)
      .filter(([method]) => ["get", "post", "put", "patch", "delete"].includes(method))
      .map(([method, operation]) => ({ path, method: method.toUpperCase(), operation }))
  );

/** A concrete path for a template, so documented routes can be called. */
const concrete = (path: string) =>
  path
    .replace("{userId}", "00000000-0000-0000-0000-000000000000")
    .replace("{clientId}", "calendar-web")
    .replace("{id}", "x");

describe("/docs tells the truth", () => {
  test("is a valid-looking OpenAPI 3 document that every operation answers to", () => {
    expect(doc.openapi).toMatch(/^3\./);
    for (const { path, method, operation } of operations()) {
      expect(operation.responses, `${method} ${path}`).toBeObject();
      expect(Object.keys(operation.responses).length, `${method} ${path}`).toBeGreaterThan(0);
    }
  });

  test("no documented operation is a 404 that its own documentation does not allow", async () => {
    for (const { path, method, operation } of operations()) {
      // an empty JSON object, so a handler that reads a body has one to read
      const body = method === "GET" ? undefined : "{}";
      const response = await fetch(`${app.url}${concrete(path)}`, { method, body, headers: body ? { "content-type": "application/json" } : undefined, redirect: "manual" });
      const allowsNotFound = Object.keys(operation.responses).includes("404");
      if (!allowsNotFound) {
        expect(response.status, `${method} ${path} is documented but answered 404`).not.toBe(404);
      }
    }
  });

  test("documents every endpoint of the OpenID Provider", () => {
    const documented = operations().map(({ method, path }) => `${method} ${path}`);
    for (const expected of [
      "GET /.well-known/openid-configuration",
      "GET /authorize",
      "POST /token",
      "GET /userinfo",
      "GET /logout",
    ]) {
      expect(documented).toContain(expected);
    }
  });

  test("documents the client registry API", () => {
    const documented = operations().map(({ method, path }) => `${method} ${path}`);
    for (const expected of [
      "GET /admin/oidc/clients",
      "POST /admin/oidc/clients",
      "GET /admin/oidc/clients/{clientId}",
      "PATCH /admin/oidc/clients/{clientId}",
      "POST /admin/oidc/clients/{clientId}/rotate-secret",
      "POST /admin/oidc/clients/{clientId}/disable",
      "POST /admin/oidc/clients/{clientId}/enable",
      "GET /admin/audit-events",
    ]) {
      expect(documented).toContain(expected);
    }
  });

  test("marks exactly the retired login endpoints as deprecated", () => {
    const deprecated = operations().filter(({ operation }) => operation.deprecated === true).map(({ method, path }) => `${method} ${path}`).sort();
    expect(deprecated).toEqual(["POST /auth/login", "POST /auth/passkey/login-options", "POST /auth/passkey/login-verify"]);
  });

  test("every $ref points at a schema that exists", () => {
    const refs = [...JSON.stringify(doc).matchAll(/"\$ref":"#\/components\/schemas\/([^"]+)"/g)].map((match) => match[1]);
    expect(refs.length).toBeGreaterThan(0);
    for (const ref of new Set(refs)) expect(doc.components.schemas[ref], ref).toBeDefined();
  });

  test("the OP documents what it enforces: S256 only, a required nonce and redirect_uri", () => {
    const parameters = doc.paths["/authorize"].get.parameters as { name: string; required?: boolean; schema: any }[];
    const byName = Object.fromEntries(parameters.map((parameter) => [parameter.name, parameter]));
    expect(byName.code_challenge_method.schema.enum).toEqual(["S256"]);
    expect(byName.redirect_uri.required).toBe(true);
    expect(byName.response_type.schema.enum).toEqual(["code"]);
    expect(doc.paths["/authorize"].get.description).toContain("`nonce` is required");
  });

  test("the Swagger page and its assets are served", async () => {
    expect((await call(app, "GET", "/docs")).status).toBe(200);
  });
});
