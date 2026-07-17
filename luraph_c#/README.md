# luraph c# worker

this is the local c# worker for luraph. it reads the wrapper, grabs traces from the luau runtime, rebuilds what it can, then runs both scripts to compare their output and behavior.

it stays offline. it also wont call something recovered when it only guessed.

deobfuscator version: `9.0`

## build it

```sh
/usr/local/share/dotnet/dotnet build Luraph.sln
/usr/local/share/dotnet/dotnet test Luraph.sln
```

## use it

```sh
dotnet run --project src/Luraph.Cli -- inspect input.luau --output out
dotnet run --project src/Luraph.Cli -- deobfuscate input.luau --output out
dotnet run --project src/Luraph.Cli -- verify input.luau out/reconstructed.luau --output check
```

the apple silicon runtime is at `runtime/rbx_luau_runtime`. windows x64 and arm64 builds are in their matching folders under `runtime`, and the cli picks the right one. `runtime/rbx-luau-runtime-windows.zip` has both windows builds together.

use `--runtime PATH` or `RBX_LUAU_RUNTIME` only when you wanna override the bundled one.

`--json` prints the report. `--progress-jsonl` prints live steps. theres also `--trace`, `--no-auto-trace`, `--timeout`, and `--max-steps`. the default trace budget is 2 billion runtime steps because large luraph loaders burn a lot before the payload starts.

when the native oracle returns a full graph, the worker writes `semantic_candidate.luau`, `readability.json`, and the native ir/cfg files. a partial candidate is only there for inspection. only compiled, runtime-equivalent output becomes `reconstructed.luau`.

exit codes:

- `0` worked
- `2` got blocked honestly
- `3` bad input
- `4` runtime is missing
- `5` timed out or got stopped
- `1` internal error

temporary oracle scripts and private run files get deleted when the job ends.
