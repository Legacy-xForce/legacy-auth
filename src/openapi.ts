import { config } from "./config.ts";

type OpenApiDocument = {
  openapi: string;
  info: {
    title: string;
    version: string;
    description: string;
  };
  servers: Array<{ url: string }>;
  paths: Record<string, unknown>;
  components: {
    schemas: Record<string, unknown>;
  };
};

export function createOpenApiDocument(): OpenApiDocument {
  return {
    openapi: "3.0.3",
    info: {
      title: "Legacy Auth Service",
      version: "0.1.0",
      description: "Authentication service for the Legacy ecosystem.",
    },
    servers: [{ url: "/" }],
    paths: {
      "/auth/login": {
        post: {
          tags: ["Auth"],
          summary: "Authenticate a user and issue tokens",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/LoginRequest" },
              },
            },
          },
          responses: {
            "200": {
              description: "Tokens issued successfully",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/TokenResponse" },
                },
              },
            },
            "400": { description: "Missing username or password" },
            "401": { description: "Invalid credentials" },
          },
        },
      },
      "/auth/refresh": {
        post: {
          tags: ["Auth"],
          summary: "Exchange a refresh token for a new token pair",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/RefreshRequest" },
              },
            },
          },
          responses: {
            "200": {
              description: "Tokens refreshed successfully",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/TokenResponse" },
                },
              },
            },
            "400": { description: "Missing refresh_token" },
            "401": { description: "Invalid, revoked, or expired refresh token" },
          },
        },
      },
      "/auth/logout": {
        post: {
          tags: ["Auth"],
          summary: "Revoke a refresh token",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/RefreshRequest" },
              },
            },
          },
          responses: {
            "200": {
              description: "Refresh token revoked",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/LogoutResponse" },
                },
              },
            },
            "400": { description: "Missing refresh_token" },
            "401": { description: "Invalid refresh token" },
          },
        },
      },
      "/openapi.json": {
        get: {
          tags: ["Docs"],
          summary: "OpenAPI document",
          responses: {
            "200": {
              description: "OpenAPI JSON document",
            },
          },
        },
      },
    },
    components: {
      schemas: {
        LoginRequest: {
          type: "object",
          required: ["username", "password"],
          properties: {
            username: { type: "string", example: "alice" },
            password: { type: "string", example: "secret" },
          },
        },
        RefreshRequest: {
          type: "object",
          required: ["refresh_token"],
          properties: {
            refresh_token: { type: "string", example: "eyJhbGciOi..." },
          },
        },
        TokenResponse: {
          type: "object",
          required: ["access_token", "refresh_token", "expires_in", "refresh_expires_in"],
          properties: {
            access_token: { type: "string" },
            refresh_token: { type: "string" },
            expires_in: { type: "integer", example: config.accessTokenTtlSeconds },
            refresh_expires_in: { type: "integer", example: config.refreshTokenTtlSeconds },
          },
        },
        LogoutResponse: {
          type: "object",
          required: ["success"],
          properties: {
            success: { type: "boolean", example: true },
          },
        },
      },
    },
  };
}
