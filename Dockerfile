FROM oven/bun:1 AS base

WORKDIR /app

# ---- dependencies needed to build the frontend (includes devDependencies) ----
FROM base AS frontend-deps

COPY package.json bun.lock ./
COPY backend/package.json ./backend/package.json
COPY frontend/package.json ./frontend/package.json
RUN bun install --frozen-lockfile

FROM frontend-deps AS frontend-build

COPY frontend ./frontend
RUN cd frontend && bunx vite build

# ---- production-only dependencies for the backend runtime ----
FROM base AS backend-deps

COPY package.json bun.lock ./
COPY backend/package.json ./backend/package.json
COPY frontend/package.json ./frontend/package.json
RUN bun install --frozen-lockfile --production

# ---- runtime image: backend serves the API and the built frontend ----
FROM base AS runtime

ENV NODE_ENV=production

COPY --from=backend-deps /app/node_modules ./node_modules
COPY --from=backend-deps /app/backend/node_modules ./backend/node_modules
COPY package.json bun.lock ./
COPY backend/package.json ./backend/package.json
COPY backend/src ./backend/src
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

ENV FRONTEND_DIST_DIR=/app/frontend/dist

WORKDIR /app/backend

VOLUME ["/app/backend/data/avatars"]

EXPOSE 3000

# Coolify uses the image HEALTHCHECK to gate deployments and mark the
# container healthy. All legacy containers listen on 3000.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bun -e "fetch('http://127.0.0.1:3000/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["bun", "run", "src/index.ts"]
