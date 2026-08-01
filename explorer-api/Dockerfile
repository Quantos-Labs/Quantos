# ============================================================================
# Quantos Explorer API — Dockerfile
# Multi-stage build: build TS → slim runtime
# ============================================================================

# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM node:20-slim AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci || npm install

COPY tsconfig.json ./
COPY src/ ./src/
COPY supabase/ ./supabase/

RUN npm run build

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM node:20-slim AS runtime

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/supabase ./supabase

# Default port (overridable via env)
ENV API_PORT=3001
EXPOSE 3001

# Healthcheck: hit the /v1/health endpoint
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.API_PORT||3001)+'/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Run both indexer and API
CMD ["sh", "-c", "node dist/indexer.js & node dist/api.js"]
