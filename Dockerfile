# ==============================================================================
# SECURE HARDENED CONTAINER SPECIFICATION (Production)
# Multi-Stage Build, Minimal Attack Surface, Non-Root Principle of Least Privilege
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build & Compilation Environment (builder)
# ------------------------------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /build

# Install build prerequisites and OpenSSL required by Prisma engine
RUN apk add --no-cache openssl libc6-compat

# Leverage Docker layer caching: copy package manifests first
COPY package*.json ./
COPY prisma ./prisma/

# Deterministic dependency installation
RUN npm ci

# Generate type-safe Prisma client and compile TypeScript to dist/
COPY tsconfig.json ./
COPY src ./src/
RUN npx prisma generate
RUN npm run build

# Prune development dependencies to isolate only production dependencies
RUN npm prune --production

# ------------------------------------------------------------------------------
# Stage 2: Hardened Production Runtime (runner)
# ------------------------------------------------------------------------------
FROM node:20-alpine AS runner

# Harden environment with security metadata and production variables
ENV NODE_ENV=production
ENV PORT=4000
ENV SECURITY_MODE=secure

WORKDIR /app

# Install minimal runtime shared library needed for Prisma engines
RUN apk add --no-cache openssl libc6-compat dumb-init

# Copy only production artifacts and pruned node_modules from builder
COPY --from=builder /build/package*.json ./
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/dist ./dist
COPY --from=builder /build/prisma ./prisma

# SECURITY CONTROL: Enforce Principle of Least Privilege
# Chown files to built-in unprivileged 'node' user (UID 1000:GID 1000)
RUN chown -R node:node /app

# Switch to non-root user before application execution
USER node

# Container health monitoring
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:4000/api/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

EXPOSE 4000

# Use dumb-init to properly handle PID 1 signals and zombie reaping
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "dist/src/server.js"]
