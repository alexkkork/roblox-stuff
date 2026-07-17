# syntax=docker/dockerfile:1

ARG TOOLCHAIN_IMAGE=dockcross/windows-static-x64@sha256:e5fde458b54dda21d0265516f0310bc017532dd6f4fdad0b7239dc6ccd0f8ca9
FROM ${TOOLCHAIN_IMAGE}

ARG TOOLCHAIN_KIND
ARG OPENSSL_VERSION=3.5.7
ARG OPENSSL_SHA256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
ARG CURL_VERSION=8.8.0
ARG CURL_SHA256=0f58bb95fc330c8a46eeb3df5701b0d90c9d9bfcc42bd1cd08791d12551d4400

RUN set -eux; \
    wget -q "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" -O /tmp/openssl.tar.gz; \
    echo "${OPENSSL_SHA256}  /tmp/openssl.tar.gz" | sha256sum -c -; \
    tar -C /tmp -xf /tmp/openssl.tar.gz; \
    cd "/tmp/openssl-${OPENSSL_VERSION}"; \
    if [ "${TOOLCHAIN_KIND}" = "arm64" ]; then \
        sed -i '1739,1748{s/cflags           => "-m64"/cflags           => ""/}' Configurations/10-main.conf; \
    elif [ "${TOOLCHAIN_KIND}" != "x64" ]; then \
        echo "unsupported TOOLCHAIN_KIND: ${TOOLCHAIN_KIND}" >&2; \
        exit 1; \
    fi; \
    cross_prefix="${CC%gcc}"; \
    CC=gcc AR=ar RANLIB=ranlib RC=windres ./Configure mingw64 \
        --cross-compile-prefix="${cross_prefix}" \
        --prefix=/opt/windows-deps \
        --libdir=lib \
        no-shared no-tests no-apps no-docs no-asm; \
    make -s -j 4 build_generated; \
    make -s -j 4 libcrypto.a; \
    mkdir -p /opt/windows-deps/include /opt/windows-deps/lib; \
    cp -R include/openssl /opt/windows-deps/include/; \
    cp libcrypto.a /opt/windows-deps/lib/libcrypto.a; \
    test -f /opt/windows-deps/lib/libcrypto.a; \
    cd /; \
    rm -rf "/tmp/openssl-${OPENSSL_VERSION}" /tmp/openssl.tar.gz

RUN set -eux; \
    wget -q "https://curl.se/download/curl-${CURL_VERSION}.tar.xz" -O /tmp/curl.tar.xz; \
    echo "${CURL_SHA256}  /tmp/curl.tar.xz" | sha256sum -c -; \
    tar -C /tmp -xf /tmp/curl.tar.xz; \
    cmake -S "/tmp/curl-${CURL_VERSION}" -B /tmp/curl-build -GNinja \
        -DCMAKE_TOOLCHAIN_FILE="${CMAKE_TOOLCHAIN_FILE}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/windows-deps \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_CURL_EXE=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_LIBCURL_DOCS=OFF \
        -DBUILD_MISC_DOCS=OFF \
        -DBUILD_TESTING=OFF \
        -DHTTP_ONLY=ON \
        -DCURL_USE_SCHANNEL=ON \
        -DCURL_USE_OPENSSL=OFF \
        -DCURL_USE_LIBPSL=OFF \
        -DCURL_USE_LIBSSH2=OFF \
        -DCURL_USE_LIBSSH=OFF \
        -DCURL_ZLIB=OFF \
        -DCURL_BROTLI=OFF \
        -DCURL_ZSTD=OFF \
        -DUSE_LIBIDN2=OFF; \
    cmake --build /tmp/curl-build --target install -j 4; \
    test -f /opt/windows-deps/lib/libcurl.a; \
    rm -rf /tmp/curl-build "/tmp/curl-${CURL_VERSION}" /tmp/curl.tar.xz
