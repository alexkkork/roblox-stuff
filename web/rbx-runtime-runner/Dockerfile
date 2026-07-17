# syntax=docker/dockerfile:1.7

FROM debian:bookworm-slim AS native-build

ARG NATIVE_TARGETS="rbx_luau_runtime alexfuscator alex_deobfuscator"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        libcurl4-openssl-dev \
        libicu-dev \
        libssl-dev \
        ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt ./
COPY data ./data
COPY packages ./packages
COPY src ./src
COPY tests ./tests
COPY vendor ./vendor

RUN cmake -S . -B /build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=OFF \
        -DALEX_ANTITAMPER_BUILD_EXAMPLE=OFF \
    && cmake --build /build --target ${NATIVE_TARGETS} --parallel 2 \
    && for binary in /build/rbx_luau_runtime /build/alexfuscator /build/alex_deobfuscator; do \
        if [ -f "$binary" ]; then strip "$binary"; fi; \
    done

FROM mcr.microsoft.com/dotnet/sdk:9.0.316-bookworm-slim AS luraph-build

ARG TARGETARCH

WORKDIR /src/luraph_c#
COPY luraph_c#/global.json luraph_c#/Directory.Build.props ./
COPY luraph_c#/src/Luraph.Core/Luraph.Core.csproj ./src/Luraph.Core/
COPY luraph_c#/src/Luraph.Cli/Luraph.Cli.csproj ./src/Luraph.Cli/
RUN case "$TARGETARCH" in \
        amd64) rid=linux-x64 ;; \
        arm64) rid=linux-arm64 ;; \
        *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && dotnet restore ./src/Luraph.Cli/Luraph.Cli.csproj --runtime "$rid"
COPY luraph_c#/src ./src
RUN rm -rf ./src/Luraph.Core/bin ./src/Luraph.Core/obj ./src/Luraph.Cli/bin ./src/Luraph.Cli/obj \
    && case "$TARGETARCH" in \
        amd64) rid=linux-x64 ;; \
        arm64) rid=linux-arm64 ;; \
        *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && dotnet restore ./src/Luraph.Cli/Luraph.Cli.csproj --runtime "$rid" \
    && dotnet publish ./src/Luraph.Cli/Luraph.Cli.csproj \
        --configuration Release \
        --runtime "$rid" \
        --self-contained true \
        --no-restore \
        --output /luraph-publish \
        -p:PublishSingleFile=true \
        -p:IncludeNativeLibrariesForSelfExtract=true \
        -p:PublishTrimmed=false \
    && chmod 0755 /luraph-publish/luraph-cs

FROM node:22-bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libcurl4 libicu72 libssl3 python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --chown=node:node web/rbx-runtime-runner/package.json web/rbx-runtime-runner/package-lock.json ./
RUN npm ci --omit=dev \
    && npm cache clean --force
COPY --from=native-build --chown=node:node /build/rbx_luau_runtime /app/bin/rbx_luau_runtime
COPY --from=native-build --chown=node:node /build/alexfuscator /app/bin/alexfuscator
COPY --from=native-build --chown=node:node /build/alex_deobfuscator /app/bin/alex_deobfuscator
COPY --from=luraph-build --chown=node:node /luraph-publish/luraph-cs /app/bin/luraph-cs
COPY --chown=node:node tools ./tools
COPY --chown=node:node web/rbx-runtime-runner/api ./api
COPY --chown=node:node web/rbx-runtime-runner/public ./public
COPY --chown=node:node web/rbx-runtime-runner/scripts ./scripts

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8791 \
    ALEX_PROJECT_ROOT=/app \
    RBX_RUNTIME_BINARY=/app/bin/rbx_luau_runtime \
    ALEXFUSCATOR_BINARY=/app/bin/alexfuscator \
    ALEX_DEOBFUSCATOR_BINARY=/app/bin/alex_deobfuscator \
    LURAPH_CS_BINARY=/app/bin/luraph-cs \
    LURAPH_CS_MODE=off \
    DOTNET_BUNDLE_EXTRACT_BASE_DIR=/tmp/luraph-dotnet

USER node
EXPOSE 8791

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:8791/api/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

CMD ["node", "scripts/local-server.js"]
