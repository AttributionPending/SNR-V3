# syntax=docker/dockerfile:1
# ── Builder: install all deps and build the frontend ──────────────────────────
# node:sqlite requires Node ≥ 22.5; node:22-bookworm-slim ships the latest 22.x.
FROM node:22-bookworm-slim AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --legacy-peer-deps
COPY . .
RUN npm run build

# ── Runtime: production deps only (incl. tsx) + built assets ───────────────────
FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    PORT=3001 \
    HOST=0.0.0.0 \
    DB_PATH=/data/snr.db
WORKDIR /app

# Production dependencies only (tsx is a runtime dep so the TS server can run)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --legacy-peer-deps && npm cache clean --force

# Built frontend + server source
COPY --from=builder /app/dist ./dist
COPY server ./server

# Data dir (DB + backups) owned by the unprivileged node user. /app stays
# root-owned but world-readable (the runtime only writes to /data), which avoids
# an expensive recursive chown of node_modules.
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 3001

# Health check uses Node's global fetch (no curl needed in the slim image)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3001)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["npm", "start"]
