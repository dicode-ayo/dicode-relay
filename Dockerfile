FROM node:25-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig*.json ./
COPY src ./src
RUN npm run build

FROM node:25-alpine AS runtime
RUN addgroup -S dicode && adduser -S dicode -G dicode
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
USER dicode
# Defence-in-depth: explicitly null the E2E mock flag so a rogue base-image
# layer or orchestrator default can't accidentally flip it on. Production
# deployments should additionally set NODE_ENV=production, which
# isE2EMockEnabled() also honors as a hard refusal.
ENV DICODE_E2E_MOCK_PROVIDER=""
ENV NODE_ENV="production"
EXPOSE 5553
CMD ["node", "dist/index.js"]
