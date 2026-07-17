# syntax=docker/dockerfile:1.7
FROM debian:bookworm-slim AS compiler
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates cmake g++ libcurl4-openssl-dev libssl-dev make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY packages ./packages
COPY src ./src
COPY vendor/luau ./vendor/luau
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --target alexfuscator -j 2 \
    && strip build/alexfuscator

FROM node:24-bookworm-slim AS dependencies
WORKDIR /app
COPY web/alex-key-vault/package.json web/alex-key-vault/package-lock.json* ./
RUN npm install --omit=dev

FROM node:24-bookworm-slim
ENV NODE_ENV=production PORT=8792 ALEXFUSCATOR_BINARY=/app/bin/alexfuscator
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=dependencies --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node web/alex-key-vault/package.json ./package.json
COPY --chown=node:node web/alex-key-vault/lib/compile-token.js ./lib/compile-token.js
COPY --chown=node:node web/alex-key-vault/lib/admin-auth.js ./lib/admin-auth.js
COPY --chown=node:node web/alex-key-vault/worker/server.js ./worker/server.js
COPY --from=compiler --chown=node:node /src/build/alexfuscator ./bin/alexfuscator
RUN chmod 0555 ./bin/alexfuscator
USER node
EXPOSE 8792
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:8792/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "worker/server.js"]
