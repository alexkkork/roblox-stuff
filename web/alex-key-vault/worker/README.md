# Alexfuscator Worker v2

The worker accepts source only at `POST /v2/compile`; Vercel issues the short-lived token and never receives source. Production requires `REDIS_URL`, `ALEX_COMPILE_TOKEN_SECRET`, `ALEX_RATE_LIMIT_HMAC_SECRET`, `ALEX_WORKER_PUBLIC_URL`, and `ALEX_ONLINE_KEY_MASTERS_JSON`.

Run the container as non-root with a read-only root filesystem, a tmpfs at `/tmp`, no outbound network during compilation, explicit CPU/memory limits, and a five-minute platform timeout. The worker uses only pipes and memory for compile artifacts.

Build from the repository root so the image compiles the current C++ source:

```sh
docker buildx build --platform linux/amd64 -f web/alex-key-vault/worker/Dockerfile -t alexfuscator-worker:v2 --load .
```
