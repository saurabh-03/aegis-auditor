# Next.js dashboard — production image (for docker-compose / VPS deploys).
# Render uses a Node runtime with build/start commands instead (see render.yaml).

FROM node:20-alpine AS build
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM node:20-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app/web
RUN addgroup -S aegis && adduser -S aegis -G aegis
COPY --from=build /app/web/node_modules ./node_modules
COPY --from=build /app/web/.next ./.next
COPY --from=build /app/web/public ./public
COPY --from=build /app/web/package.json ./package.json
COPY --from=build /app/web/next.config.mjs ./next.config.mjs
USER aegis
EXPOSE 3200
# API_ORIGIN and NEXT_PUBLIC_WS_ORIGIN are provided at runtime (see docker-compose).
CMD ["npm", "run", "start"]
