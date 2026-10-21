import { AsyncLocalStorage } from "node:async_hooks";

/** What the OP backend knows about the request being served, for the adapter and audit log. */
export type RequestContext = { ip: string | null; userAgent: string | null };

export const requestContext = new AsyncLocalStorage<RequestContext>();

export const currentRequest = (): RequestContext => requestContext.getStore() ?? { ip: null, userAgent: null };
