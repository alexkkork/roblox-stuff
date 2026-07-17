#!/bin/sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/../../../.." && pwd)"
image="${ALEX_WORKER_IMAGE:-alexfuscator-worker:vm6}"
platform="${ALEX_DOCKER_PLATFORM:-linux/amd64}"
container=""

cleanup() {
    if [ -n "$container" ]; then
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT HUP INT TERM

cd "$repo_root"

docker buildx build \
    --platform "$platform" \
    --file web/alex-key-vault/worker/Dockerfile \
    --tag "$image" \
    --load \
    .

image_user="$(docker image inspect --format '{{.Config.User}}' "$image")"
if [ "$image_user" != "node" ]; then
    echo "Worker image must run as node, found: $image_user" >&2
    exit 1
fi

container="$(docker run --detach --rm \
    --init \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 64 \
    --memory 768m \
    --cpus 2 \
    --publish 127.0.0.1::8792 \
    --env ALEX_ALLOW_EPHEMERAL_STATE=1 \
    --env ALEX_COMPILE_TOKEN_SECRET=local-image-smoke-token-secret \
    --env ALEX_RATE_LIMIT_HMAC_SECRET=local-image-smoke-rate-secret \
    "$image")"

mapping="$(docker port "$container" 8792/tcp | head -n 1)"
port="${mapping##*:}"

for attempt in $(seq 1 30); do
    if curl --fail --silent --show-error "http://127.0.0.1:$port/health" >"${TMPDIR:-/tmp}/alex-worker-health.json"; then
        break
    fi
    if [ "$attempt" -eq 30 ]; then
        docker logs "$container" >&2
        echo "Worker health check did not become ready" >&2
        exit 1
    fi
    sleep 1
done

if [ "$(docker exec "$container" id -u)" = "0" ]; then
    echo "Worker process unexpectedly runs as root" >&2
    exit 1
fi

if docker exec "$container" sh -c 'touch /app/worker-write-check' 2>/dev/null; then
    echo "Worker application directory is unexpectedly writable" >&2
    exit 1
fi

cat "${TMPDIR:-/tmp}/alex-worker-health.json"
printf '\nAlexfuscator VM6 worker image test passed (%s, %s)\n' "$image" "$platform"
