# syntax=docker/dockerfile:1.7
FROM debian:bookworm-slim AS compiler
ENV DEBIAN_FRONTEND=noninteractive
ARG CMAKE_BUILD_PARALLEL_LEVEL=2
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates cmake g++ libcurl4-openssl-dev libicu-dev libssl-dev make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY packages ./packages
COPY src ./src
COPY vendor/luau ./vendor/luau
COPY data/roblox/release-729/Full-API-Dump.json ./data/roblox/release-729/Full-API-Dump.json
COPY tests/roblox_oracle/probes/core.luau ./tests/roblox_oracle/probes/core.luau
COPY tests/roblox_oracle/fixtures/release-729/core.json ./tests/roblox_oracle/fixtures/release-729/core.json
COPY tests/fixtures/luraph/subject_ea93959c47e6.luau ./tests/fixtures/luraph/subject_ea93959c47e6.luau
COPY tests/fixtures/luraph/subject_1b642e9523c1.luau ./tests/fixtures/luraph/subject_1b642e9523c1.luau
COPY web/alex-key-vault/worker/scripts/smoke-alexfuscator.sh /usr/local/bin/smoke-alexfuscator
RUN chmod 0555 /usr/local/bin/smoke-alexfuscator \
    && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    && cmake --build build --target alexfuscator --parallel "${CMAKE_BUILD_PARALLEL_LEVEL}" \
    && strip build/alexfuscator
RUN /usr/local/bin/smoke-alexfuscator /src/build/alexfuscator

FROM node:24-bookworm-slim AS dependencies
WORKDIR /app
COPY web/alex-key-vault/package.json web/alex-key-vault/package-lock.json* ./
RUN npm install --omit=dev

FROM node:24-bookworm-slim
ENV NODE_ENV=production PORT=8792 ALEXFUSCATOR_BINARY=/app/bin/alexfuscator
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=dependencies /app/node_modules ./node_modules
COPY web/alex-key-vault/package.json ./package.json
COPY web/alex-key-vault/lib/compile-token.js ./lib/compile-token.js
COPY web/alex-key-vault/lib/admin-auth.js ./lib/admin-auth.js
COPY web/alex-key-vault/worker/server.js ./worker/server.js
COPY --from=compiler /src/build/alexfuscator ./bin/alexfuscator
RUN chmod -R go-w /app \
    && chmod 0555 ./bin/alexfuscator
USER node
EXPOSE 8792
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:8792/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "worker/server.js"]
