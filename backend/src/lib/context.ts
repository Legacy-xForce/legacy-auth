import type { Context } from "hono";
import type { UserRecord } from "../types.ts";

export type AppEnv = { Variables: { user: UserRecord; userId: string } };
export type Ctx = Context<AppEnv>;
export type JsonCtx<T> = Context<AppEnv, any, { in: { json: T }; out: { json: T } }>;
export type QueryCtx<T> = Context<AppEnv, any, { in: { query: T }; out: { query: T } }>;
