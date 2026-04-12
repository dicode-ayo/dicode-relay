FROM node:25-alpine AS build
WORKDIR /app
# build-base + python3 are needed to compile the better-sqlite3 native addon.
RUN apk add --no-cache build-base python3
COPY package*.json ./
RUN npm ci
COPY tsconfig*.json ./
COPY scripts ./scripts
COPY src ./src
RUN npm run build

FROM node:25-alpine AS runtime
# build tools needed once to compile better-sqlite3 during `npm ci --omit=dev`;
# pruned from the final image layer at the end.
RUN apk add --no-cache --virtual .build-deps build-base python3 \
    && addgroup -S dicode && adduser -S dicode -G dicode
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && apk del .build-deps
COPY --from=build /app/dist ./dist

# Persistence layer: SQLite database lives under /var/lib/dicode. Mount a
# Docker volume here so the DB survives container restarts. The default
# DICODE_RELAY_DB path matches this directory.
#
#   docker run -v dicode-relay-data:/var/lib/dicode ...
#
RUN mkdir -p /var/lib/dicode && chown -R dicode:dicode /var/lib/dicode
VOLUME ["/var/lib/dicode"]
ENV DICODE_RELAY_DB=/var/lib/dicode/relay.db

USER dicode
EXPOSE 5553
CMD ["node", "dist/index.js"]
