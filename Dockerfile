# Aegis Auditor — multi-stage production image.

# 1) Build: install all deps, generate Prisma client, compile TS, prune to prod deps.
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
# --include=dev: the build needs typescript/tsx even if the build env sets
# NODE_ENV=production. `npm install` (not `npm ci`) tolerates lockfile drift.
# Dev deps are dropped later via `npm prune --omit=dev`.
RUN npm install --include=dev --no-audit --no-fund
COPY . .
# Generate the Prisma client (no live DB needed; dummy URL satisfies config load).
ENV DATABASE_URL="postgresql://build:build@localhost:5432/build?schema=public"
RUN npx prisma generate
RUN npm run build
# Drop dev dependencies but keep the generated client (node_modules/.prisma + @prisma/client).
RUN npm prune --omit=dev

# 2) Slim runtime.
FROM node:20-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S aegis && adduser -S aegis -G aegis

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/prisma ./prisma
COPY package.json ./
COPY public ./public

USER aegis
EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||4000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# In memory mode this starts immediately. With DATABASE_URL set, run
# `npm run db:migrate` (prisma migrate deploy) before/at startup — see docs/DEPLOYMENT.md.
CMD ["node", "dist/server.js"]
