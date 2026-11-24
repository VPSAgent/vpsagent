# Multi-stage production image for VPSAgent v2 (Control API + Remote MCP + 4-Tab Dashboard)
# Zero Docker socket exposure — talks exclusively to the host Runtime Bridge via Unix socket.

FROM node:24-alpine AS builder
WORKDIR /app
RUN corepack enable

COPY package.json pnpm-workspace.yaml tsconfig.base.json pnpm-lock.yaml ./
COPY packages/shared/package.json packages/shared/tsconfig.json packages/shared/
COPY apps/api/package.json apps/api/tsconfig.json apps/api/
COPY apps/web/package.json apps/web/tsconfig.json apps/web/vite.config.ts apps/web/index.html apps/web/

RUN pnpm install --frozen-lockfile

COPY packages/shared/src packages/shared/src
COPY apps/api/src apps/api/src
COPY apps/web/src apps/web/src

RUN pnpm --filter @vpsagent/shared build \
  && pnpm --filter @vpsagent/api build \
  && pnpm --filter @vpsagent/web build

FROM node:24-alpine AS runtime
WORKDIR /srv/vpsagent
ENV NODE_ENV=production

COPY --from=builder /app/package.json /app/pnpm-workspace.yaml ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages/shared/package.json ./packages/shared/package.json
COPY --from=builder /app/packages/shared/dist ./packages/shared/dist
COPY --from=builder /app/packages/shared/node_modules ./packages/shared/node_modules
COPY --from=builder /app/apps/api/package.json ./apps/api/package.json
COPY --from=builder /app/apps/api/dist ./apps/api/dist
COPY --from=builder /app/apps/api/node_modules ./apps/api/node_modules
COPY --from=builder /app/apps/web/dist ./apps/web/dist

USER node
WORKDIR /srv/vpsagent/apps/api
EXPOSE 3001
CMD ["node", "dist/index.js"]
