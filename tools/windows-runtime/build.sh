#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKERFILE="$ROOT/tools/windows-runtime/Dockerfile"
OUT="$ROOT/dist/rbx-luau-runtime-windows"
PACKAGE="$ROOT/dist/rbx-luau-runtime-windows.zip"
PACKAGE_TMP="$ROOT/dist/rbx-luau-runtime-windows.tmp.zip"
MODE="${1:-all}"

X64_BASE="dockcross/windows-static-x64@sha256:e5fde458b54dda21d0265516f0310bc017532dd6f4fdad0b7239dc6ccd0f8ca9"
ARM64_BASE="dockcross/windows-arm64@sha256:ce31851af743e20d86681a94bab15d36d004c747a1b9e9778b4120e27b2f7598"

build_arch() {
    local arch="$1"
    local base="$2"
    local image="rbx-luau-windows-toolchain:${arch}"
    local target_dir="$OUT/windows-${arch}"

    docker build --platform linux/amd64 --progress plain \
        --build-arg "TOOLCHAIN_IMAGE=$base" \
        --build-arg "TOOLCHAIN_KIND=$arch" \
        -f "$DOCKERFILE" \
        -t "$image" \
        "$ROOT/tools/windows-runtime"

    mkdir -p "$target_dir"

    docker run --rm --platform linux/amd64 \
        -v "$ROOT:/src:ro" \
        -v "$target_dir:/out" \
        -w /build \
        "$image" \
        bash -lc "
            set -euo pipefail
            tool_prefix=\${CC%gcc}
            cmake -S /src -B /build -GNinja \\
                -DCMAKE_TOOLCHAIN_FILE=\$CMAKE_TOOLCHAIN_FILE \\
                -DCMAKE_PREFIX_PATH=/opt/windows-deps \\
                -DCURL_DIR=/opt/windows-deps/lib/cmake/CURL \\
                -DCURL_INCLUDE_DIR=/opt/windows-deps/include \\
                -DCURL_LIBRARY=/opt/windows-deps/lib/libcurl.a \\
                -DOPENSSL_ROOT_DIR=/opt/windows-deps \\
                -DOPENSSL_USE_STATIC_LIBS=ON \\
                -DOPENSSL_INCLUDE_DIR=/opt/windows-deps/include \\
                -DOPENSSL_CRYPTO_LIBRARY=/opt/windows-deps/lib/libcrypto.a \\
                -DLIB_EAY=/opt/windows-deps/lib/libcrypto.a \\
                -DCMAKE_BUILD_TYPE=Release \\
                -DBUILD_TESTING=OFF \\
                -DCURL_USE_STATIC_LIBS=ON
            cmake --build /build --target rbx_luau_runtime -j 4
            \${tool_prefix}strip /build/rbx_luau_runtime.exe
            \${tool_prefix}objdump -f /build/rbx_luau_runtime.exe
            \${tool_prefix}objdump -p /build/rbx_luau_runtime.exe | sed -n '/DLL Name:/p'
            cp /build/rbx_luau_runtime.exe /out/rbx_luau_runtime.exe
        "
}

smoke_x64() {
    docker run --rm --platform linux/amd64 \
        -v "$OUT/windows-x64:/runtime" \
        "$X64_BASE" \
        bash -lc 'WINEDEBUG=-all wine /runtime/rbx_luau_runtime.exe --help >/tmp/runtime-help.txt 2>&1; grep -q "Usage:" /tmp/runtime-help.txt'
}

package_all() {
    if [[ -e "$PACKAGE_TMP" ]]; then
        printf 'temporary package already exists: %s\n' "$PACKAGE_TMP" >&2
        exit 1
    fi
    for binary in "$OUT/windows-x64/rbx_luau_runtime.exe" "$OUT/windows-arm64/rbx_luau_runtime.exe"; do
        if [[ ! -f "$binary" ]]; then
            printf 'missing Windows runtime: %s\n' "$binary" >&2
            exit 1
        fi
    done
    cp "$ROOT/tools/windows-runtime/README.txt" "$OUT/README.txt"
    (
        cd "$OUT"
        shasum -a 256 windows-x64/rbx_luau_runtime.exe windows-arm64/rbx_luau_runtime.exe > SHA256SUMS.txt
    )
    (
        cd "$ROOT/dist"
        zip -X -q -r "$PACKAGE_TMP" "$(basename "$OUT")"
    )
    mv -f "$PACKAGE_TMP" "$PACKAGE"
    printf '%s\n' "$PACKAGE"
}

case "$MODE" in
    all)
        if [[ ! -f "$OUT/windows-x64/rbx_luau_runtime.exe" ]]; then
            build_arch x64 "$X64_BASE"
            smoke_x64
        fi
        if [[ ! -f "$OUT/windows-arm64/rbx_luau_runtime.exe" ]]; then
            build_arch arm64 "$ARM64_BASE"
        fi
        package_all
        ;;
    x64)
        build_arch x64 "$X64_BASE"
        smoke_x64
        ;;
    arm64)
        build_arch arm64 "$ARM64_BASE"
        ;;
    package)
        package_all
        ;;
    *)
        printf 'usage: %s [all|x64|arm64|package]\n' "$0" >&2
        exit 2
        ;;
esac
