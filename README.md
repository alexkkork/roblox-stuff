# Roblox Luau Runtime Harness

This project builds a standalone Luau executable that embeds the official
`luau-lang/luau` VM and installs a high-fidelity, headless Roblox client
environment. Runtime v2 uses native Instance userdata, release-pinned reflection,
a deterministic coroutine scheduler, isolated script environments, fixture-backed
services, HTTP/JSON glue, math userdata, executor-analysis shims, and capture hooks
around dynamic code and network fetches.

It is not a byte-for-byte implementation of the Roblox engine. Real physics,
rendering, Roblox auth, live replication, security identities, and server
internals are still stubbed. The goal is script-visible compatibility for
controlled analysis and decrypted payload capture.

## Build

```sh
cmake -S . -B work/build -DCMAKE_BUILD_TYPE=Release
cmake --build work/build --target rbx_luau_runtime -j
cmake --build work/build --target alexfuscator -j
```

## Alexfuscator

`alexfuscator` vNext is a C++20 typed-IR-to-register-VM compiler. Every production
profile uses register VM v5 with profile-specific hardening; generated output
never reconstructs source or calls `loadstring`. Unsupported syntax is a
structured compile error, not a weaker fallback. The VM supports closures,
recursion, varargs and multiple returns, methods, all common loop forms,
break/continue, interpolation, if-expressions, type erasure, metamethods,
coroutine yields, and protected-frame executor metadata adapters.

Build reports use descriptor version 3 and identify `backend=register_vm_v5`,
the effective controls, actual feature flags, prototype/instruction counts, and
`fallback_used=false`. Maximum adds authenticated lazy block and constant
fragments using HKDF-SHA256 and ChaCha20-Poly1305. Standalone material remains
recoverable through runtime tracing and is not presented as perfect secrecy.

```sh
./work/build/alexfuscator path/to/input.luau \
  -o outputs/alexfuscator/input.obf.luau \
  --profile maximum \
  --runtime universal \
  --seed auto
```

Useful options:

- `--profile compatibility|hardened|maximum`: default is `maximum`; the old
  names are rejected with a migration error.
- `--runtime universal|roblox|executor` and `--key-mode standalone|online`.
- `--control-flow`, `--constant-protection`, `--vm-diversity`, and
  `--tamper-density`: accept `preset`, `off`, `standard`, `aggressive`, or
  `maximum`.
- `--environment-binding portable|roblox|executor`.
- `--stdin --stdout --report-fd 3`: fileless worker integration.
- `--seed auto|VALUE`: fixed values produce deterministic output; `auto`
  randomizes each run.
- `--analysis-notice TEXT`: embeds inert informational text and never changes
  encryption keys or scoring.

Local UI:

```sh
cd web/alex-key-vault
npm run worker
# second terminal
npm run local
```

Open `http://127.0.0.1:8791/`. The browser obtains a source-free compile token
and sends source directly to the worker on port `8792`. `/admin2` shows only
HMAC-hashed user identifiers and operational usage; the local development
password is `admin2-local`. Production must configure the secrets documented in
`web/alex-key-vault/.env.example` and Redis.

Quick verification:

```sh
./work/build/alexfuscator tests/alexfuscator_smoke.luau \
  -o outputs/alexfuscator/alexfuscator_smoke.obf.luau \
  --profile hardened --runtime universal --seed 123

grep -q loadstring outputs/alexfuscator/alexfuscator_smoke.obf.luau || \
  echo "custom VM output has no loadstring"

./work/build/rbx_luau_runtime \
  --profile executor-client \
  --out outputs/alexfuscator/runtime_smoke \
  outputs/alexfuscator/alexfuscator_smoke.obf.luau

python3 tests/run_vnext_differential.py --programs 500
python3 tests/test_alexfuscator_v5.py --seeds 100

./work/build/rbx_luau_runtime \
  --minimal-env \
  --out outputs/alexfuscator/minimal_smoke \
  outputs/alexfuscator/alexfuscator_smoke.obf.luau
```

## Run

```sh
./work/build/rbx_luau_runtime --out captures path/to/script.lua
```

## Web Runner

The browser workbench keeps the common path small: choose a client profile,
paste Luau, and run. Runtime identity, scheduler limits, scenarios, network
fixtures, capture hooks, call tracing, and Luraph controls live in the Advanced
drawer. Console output, fidelity metadata, hooks, and files are separated into
stable tabs. Temporary worker paths are removed from every API response. Hosted
runs begin offline. When a script reaches HTTP, the console names the exact host
and offers an explicit **Allow host and retry** action; the retry uses allowlist
mode for that host only and never silently enables live networking.

Run it against the local native binary:

```sh
cd web/rbx-runtime-runner
RBX_RUNTIME_BINARY=../../build/rbx_luau_runtime PORT=8794 npm run dev
```

Or build and start the isolated container:

```sh
cd web/rbx-runtime-runner
docker compose up --build
```

Open `http://127.0.0.1:8795/`. Set `ALEX_RUNTIME_PORT` before `docker compose`
to choose another host port. The container compiles the native runtime in a
multi-stage build, then runs the service as an unprivileged user with a
read-only root filesystem, a bounded tmpfs, dropped Linux capabilities, a PID
limit, and memory/CPU limits. Script HTTP remains offline unless the caller
explicitly changes the runner policy. Health is available at `/api/health`.

Useful options:

- `--out DIR`: directory where captured scripts and metadata are written.
- `--capture-min N`: minimum string size for conventional `captured_script.lua`
  and `captured_httpget.lua` mirrors. All `loadstring` inputs are still logged.
- `--capture-string-hooks|--no-capture-string-hooks`: enable or disable extra
  large-string capture around `string.*`, `table.concat`, `buffer.tostring`,
  and coroutine returns. Enabled by default for analysis.
- `--profile roblox-client|executor-client`: runtime persona. The default is
  `executor-client`.
- `--clock virtual|realtime`: deterministic virtual frames by default, with an
  optional monotonic real-time clock.
- `--frame-rate N` and `--max-virtual-seconds N`: virtual scheduler controls;
  defaults are 60 Hz and 30 seconds.
- `--scenario PATH`: load a version-1 JSON descriptor containing identity,
  Instances, ModuleScript source, attributes, tags, HTTP/remote fixtures, and
  scheduled input events. Explicit CLI identity and clock flags win.
- `--unsupported error|trace-nil`: strict Roblox-style errors or analysis-mode
  tracing with nil fallbacks. Defaults follow the selected profile.
- `--report PATH|-`: emit runtime/API versions, returns, output, scheduler state,
  native engine counts, unsupported calls, `termination_reason`, and structured
  `network_requirements` as JSON.
- `--minimal-env`: diagnostic mode that skips the Roblox shims and runs with
  core Luau globals plus native capture helpers.
- `--network-policy allowlist|live|offline`: default is `allowlist`.
- `--allow-host HOST`: allow an HTTP host under allowlist mode. Defaults include
  `raw.githubusercontent.com`, `localhost`, and loopback.
- `--fixture URL=PATH`: replay a URL from a local file.
- `--trace-compat PATH`: write missing globals/members/stub hits as JSONL.
- `--trace-calls`: include successful high-level API calls in the JSONL trace.
- `--luraph-mode off|auto|force`: enable exact-source-first Luraph recovery.
  `auto` activates when Luraph markers such as `LPH@` are detected.
- `--luraph-stop-after-exact-source|--no-luraph-stop-after-exact-source`:
  request early stop after `original_luau_exact.lua` is written.
- `--luraph-save-intermediates|--no-luraph-save-intermediates`: save packed
  blobs, bytecode-like data, unpack summaries, and fallback notes.
- `--luraph-max-steps N`: deterministic Luraph VM safepoint limit, default
  `50000000`.
- `--luraph-stall-steps N`: stop after extraction has begun and no new exact
  source, blob, function dump, or decompiler artifact appears for `N`
  safepoints. Default is `10000000`; use `0` to disable.
- `--progress-interval SECONDS`: print VM safepoint progress every interval.
  Use `--progress-interval 1` for once-per-second Luraph progress. Luraph runs
  also show `stall=idle/max` after extraction starts.
- `--sift-decompile|--decompile`: when bytecode-like strings are captured,
  upload them to Sift's `/api/v1/decompile` endpoint and save returned Luau as
  `luraph_decompiled_fallback.lua`.
- `--sift-disassemble|--disassemble`: upload captured bytecode-like strings to
  Sift's `/api/v1/disassemble` endpoint and save `luraph_disassembly.txt`.
- `--sift-api-key KEY`: API key for Sift. This overrides the environment and
  built-in fallback key.
- `--sift-api-key-env NAME`: environment variable used for the Sift key. The
  default is `SIFTRBLX_API_KEY`; if it is unset, this local build uses the
  compiled-in fallback key.
- `--sift-base-url URL`: Sift base URL, default `https://siftrblx.com`.
- `--chunk-name NAME`: override the Luau chunk name used in stack/error text.
- `--luau-opt-level N` and `--luau-debug-level N`: compiler diagnostics.
- `--timeout SECONDS`: VM safepoint timeout, default `30`.
- `--native-codegen|--no-native-codegen`: enable or disable Luau native
  codegen when supported.
- `--native-codegen-block-mb N` and `--native-codegen-max-mb N`: tune Luau
  native code allocation for very large obfuscated chunks.
- `--trace-pcall-errors`: log unique protected-call errors.
- `--normalize-pcall-errors|--no-normalize-pcall-errors`: apply the common
  Luraph anti-format line-number normalization. Enabled by default.
- `--place-id`, `--game-id`, `--job-id`, `--user-id`, `--player-name`: override
  the Roblox client persona.
- `--stop-after-capture`: reserved for workflows that want to abort after a
  capture point.
- `--autorun-loadstring`: immediately invokes zero-argument chunks returned by
  `loadstring` in addition to returning a wrapped function.
- `--no-autorun-loadstring`: disables that behavior. This is the default-safe
  mode for scripts whose loaded chunks require arguments.

Runtime reports use one of five termination reasons:

- `completed`: the main script and scheduler completed normally.
- `virtual_budget`: deterministic bounded simulation completed successfully
  with yielded work still pending.
- `network_required`: offline execution reached one or more blocked HTTP(S)
  hosts; the report lists the host and URL needed for an allowlist retry.
- `wall_timeout`: CPU-bound execution exceeded the watchdog.
- `runtime_error`: compilation or script execution failed.

Each Script receives its own environment, while `_G` is a mutable,
metatable-free table shared across scripts. ModuleScripts keep isolated script
environments and share `_G`. In the executor profile, `getgenv`, `getrenv`, and
`getsenv` preserve those distinctions, including loaded chunks and callbacks.

Example Luraph-oriented run:

```sh
./work/build/rbx_luau_runtime \
  --profile executor-client \
  --luraph-mode force \
  --network-policy allowlist \
  --allow-host raw.githubusercontent.com \
  --chunk-name "Luraph Script" \
  --native-codegen-block-mb 128 \
  --native-codegen-max-mb 1024 \
  --luraph-max-steps 50000000 \
  --luraph-stall-steps 10000000 \
  --progress-interval 1 \
  --sift-decompile \
  --sift-disassemble \
  --trace-compat captures/compat_trace.jsonl \
  --out captures \
  work/luraph_acceptance.lua
```

## Fidelity Oracle

Roblox Studio's documented command-line runner is used as the behavior oracle.
The updater exports both API schemas and executes the probe suite without manual
Studio interaction:

```sh
python3 tools/update_roblox_oracle.py
python3 tests/run_roblox_fidelity.py --operations 1000
```

Oracle fixtures are stored by Studio release. The runtime remains pinned to
release 728 until its Luau dependency and reflection snapshot are deliberately
advanced together; a newer installed Studio writes a separate fixture directory.

This local build includes a compiled-in Sift fallback key. Setting
`SIFTRBLX_API_KEY` or passing `--sift-api-key` overrides it. The selected key is
sent as `X-API-Key`; the key value is not written to reports.

## Captures

The runtime writes files such as:

- `loadstring_input_0001.lua`
- `loadstring_return_0001_01.lua`
- `loadstring_error_0001.txt`
- `httpget_0002.lua`
- `main_return_01.lua`
- `capture_index.jsonl`

`captured_script.lua` and `captured_httpget.lua` are also written for large
payloads for compatibility with common workflows.

In Luraph mode, exact source recovery is explicit:

- `original_luau_exact.lua` is written only when exact source text is captured
  from a runtime source-bearing path.
- `luraph_packed_blob.txt` stores captured `LPH@...` packed data.
- `luraph_unpacked_state.json` records packed/blob analysis status.
- `luraph_bytecode_or_prototypes.bin` stores binary bytecode-like captures.
- `luraph_function_dump.json` stores returned closure/upvalue metadata when a
  VM returns functions instead of source strings.
- `sift_decompile_response.json` and `sift_disassemble_response.json` store raw
  Sift responses when the Sift fallback is enabled.
- `luraph_disassembly.txt` stores Sift opcode listings when disassembly is
  enabled.
- `luraph_decompiled_fallback.lua` is a fallback note or Sift-generated
  decompile, never labeled as original source.
- `luraph_recovery_report.json` records `exact_recovery_status` as
  `recovered`, `not_present`, `blocked`, or `unknown`.

## Automatic Deobfuscator

The offline-first orchestrator combines conservative static transforms,
runtime capture hooks, family adapters, compile checks, and differential runs.
It labels output as exact only when a source-bearing artifact is recovered and
verified. Otherwise it emits readable reconstruction or structural artifacts.

```sh
python3 tools/auto_deobfuscator.py protected.luau \
  --runtime build/rbx_luau_runtime \
  --alexfuscator build/alexfuscator \
  --mode auto --profile executor-client
```

Use `--mode exact` to refuse reconstructed output, `--mode reconstruct` for a
readable best effort, or `--mode disassemble` for structural analysis only.
Network access is offline by default. Results include semantic IR, CFG,
constants, VM disassembly, a content-addressed artifact graph, and a report
that records provenance and verification.

The local web workbench is available at `/deobfuscator` when running the web
runner. Its API stores input and artifacts only in a per-request temporary
directory and removes them before the response completes.

## CI Artifacts

The GitHub Actions workflow builds:

- `rbx_luau_runtime_macos_arm64`
- `rbx_luau_runtime_ubuntu_x86_64`
- `roblox_luau_runtime_project.tar.gz`
- SHA-256 checksum files
