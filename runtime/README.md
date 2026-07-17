# Runtime Guard

Small C++ check for a native Luau host. It checks that `game` is the real
`DataModel` from your engine registry instead of a Lua table pretending to be
one.

It also checks:

- `game`, `workspace`, and `Workspace` native object identity
- `DataModel` root and `Workspace` parent links
- one real instance of each core service
- destroyed or swapped objects
- place, universe, job, and place version
- runtime release, API hash, and reflection schema

## Build

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The demo should print:

```text
runtime check passed
```

## Use It

Add `guard.cpp` to your target and include `guard.h`.

```cpp
#include "guard.h"

rt::Rules rules = rt::defaults("729", "your-api-sha256");
rules.place = 123456;
rules.universe = 987654;

rt::State state = readNativeState();

if (!rt::enforce(state, rules, [](const rt::Result& result) {
    // Log locally, return harmless values, or stop loading the protected code.
})) {
    return;
}
```

`readNativeState()` is the part that connects this to your engine. Fill it from
your C++ Instance registry and userdata handles. Do not fill it by calling
script-visible `game:GetService()` and trusting the returned fields. A hooked
Lua environment could fake those answers.

In this project, the real adapter is `src/runtime_v2.cpp` in
`inspectDataModel()`. It compares userdata pointers with the engine registry,
checks parent IDs, and reads the identity fields from native Instance state.

## Important

This does not run inside normal Roblox by itself. Roblox scripts cannot load a
C++ library. It is for a custom native Luau host, emulator, or executor runtime
that owns the VM and Instance registry.

Client-side checks can still be patched by someone who controls the whole
process. Pair this with signed files and hash checks. Do not use destructive
failure behavior; just stop loading the protected payload or return a harmless
result.
