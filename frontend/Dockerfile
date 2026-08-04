# ==============================================================================
# Stage 1: Dependency Installation with pnpm
# ==============================================================================
FROM node:24-alpine AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Enable modern pnpm via Corepack
ENV COREPACK_ENABLE_AUTO_PIN=0
RUN corepack enable pnpm

# Copy package manifests, lockfiles, and pnpm configuration
COPY package.json pnpm-lock.yaml* .npmrc* ./
RUN pnpm install --frozen-lockfile --dangerously-allow-all-builds

# ==============================================================================
# Stage 2: Production Next.js Build
# ==============================================================================
FROM node:24-alpine AS builder
WORKDIR /app

ENV COREPACK_ENABLE_AUTO_PIN=0
RUN corepack enable pnpm

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Set build-time environment variables
ENV NEXT_TELEMETRY_DISABLED=1 \
    NODE_ENV=production

# Compile standalone Next.js bundle with pnpm
RUN pnpm run build

# ==============================================================================
# Stage 3: Minimal Production Runtime
# ==============================================================================
FROM node:24-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME="0.0.0.0"

# Create unprivileged system user
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy static assets and standalone bundle
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# Switch to non-root user
USER nextjs

EXPOSE 3000

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:3000/ || exit 1

CMD ["node", "server.js"]
