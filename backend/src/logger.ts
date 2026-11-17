import { LogLayer, type LogLevelType } from "loglayer";
import { PinoTransport } from "@loglayer/transport-pino";
import { redactionPlugin } from "@loglayer/plugin-redaction";
import { pino } from "pino";
import pretty from "pino-pretty";

/** Human-readable, colourised lines on stdout (still fed by Pino's structured data). */
const prettyStream = pretty({
  colorize: true,
  translateTime: "SYS:standard",
  ignore: "pid,hostname",
});

const LOG_LEVELS = ["trace", "debug", "info", "warn", "error", "fatal", "silent"] as const;
const configured = process.env.LOG_LEVEL?.trim().toLowerCase();
const validLevel = LOG_LEVELS.find((candidate) => candidate === configured);
// `silent` is understood by Pino, not by LogLayer's level manager; Pino still
// drops every line, so the transport can sit at its highest level in that case.
const transportLevel = (validLevel === "silent" || validLevel === undefined ? "fatal" : validLevel) as LogLevelType;

/**
 * The LogLayer instance itself. Framework integrations (the Hono middleware)
 * need an `ILogLayer` so they can create request-scoped child loggers.
 */
export const logLayer = new LogLayer({
  transport: new PinoTransport({
    id: "pino",
    level: transportLevel,
    logger: pino({ level: validLevel ?? "info" }, prettyStream),
  }),
  plugins: [
    redactionPlugin({
      paths: [
        "password",
        "current_password",
        "new_password",
        "password_hash",
        "access_token",
        "refresh_token",
        "token",
        "authorization",
        "client_secret",
        "secret",
      ],
      censor: "[REDACTED]",
    }),
  ],
});

export type LogMetadata = Record<string, unknown>;
type Level = "debug" | "info" | "warn" | "error";

/**
 * Convenience wrapper for the non-Hono parts of the service (startup, the OIDC
 * backend, background jobs). Hono handlers get a request-scoped `c.var.logger`
 * instead, from the `honoLogLayer` middleware.
 */
function emit(level: Level, message: string, metadata?: LogMetadata, error?: unknown): void {
  const entry = logLayer.withMetadata(metadata);
  if (error === undefined) {
    entry[level](message);
    return;
  }
  entry.withError(error instanceof Error ? error : new Error(String(error)))[level](message);
}

export const log = {
  debug: (message: string, metadata?: LogMetadata, error?: unknown) => emit("debug", message, metadata, error),
  info: (message: string, metadata?: LogMetadata, error?: unknown) => emit("info", message, metadata, error),
  warn: (message: string, metadata?: LogMetadata, error?: unknown) => emit("warn", message, metadata, error),
  error: (message: string, metadata?: LogMetadata, error?: unknown) => emit("error", message, metadata, error),
};

if (configured && !validLevel) {
  log.warn(`[config] LOG_LEVEL="${configured}" is not a valid level; using info`);
}
