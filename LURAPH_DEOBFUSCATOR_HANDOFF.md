# Luraph Deobfuscator Full Handoff

Last updated: 2026-07-18

This document is meant to be pasted into a different AI task with much less
conversation history. It is the cold-start context for the local Luau runtime,
Luraph analysis, deobfuscator, reconstruction pipeline, current sample, proven
results, unfinished work, and correctness rules.

Do not summarize this document into a vague plan before working. Read the
referenced source and reports, reproduce the current build, and continue from
the evidence-backed boundary described below.

## One-Sentence Mission

Continue the local, offline, authorized reconstruction of the supplied Luraph
v14.7 Luau sample into behaviorally equivalent and increasingly readable Luau,
without claiming erased names/comments/formatting as recovered and without
turning a trace replay into fake source code.

## Cold-Start Instructions For The Next AI

1. Work in this directory:

   `/Users/alexkkork/Documents/Codex/2026-07-05/build-a-perfect-luau-runtime-with`

2. Read these files first:

   - `src/deobfuscator/core/deob.cpp`
   - `src/deobfuscator/luraph/emit.cpp`
   - `tests/deobfuscator/luraph/emit_test.cpp`
   - this handoff document

3. Build and run the focused test before editing:

   ```sh
   cd /Users/alexkkork/Documents/Codex/2026-07-05/build-a-perfect-luau-runtime-with
   cmake --build build --target alex_deobfuscator luraph_semantic_emitter_test -j4
   build/tests/luraph_semantic_emitter_test
   ```

4. Preserve all existing user changes. The workspace root is not a Git
   repository. There are nested repositories, so do not run broad reset,
   checkout, clean, or destructive Git commands.

5. Do not contact Luraph, Roblox, authentication endpoints, key services, or
   any other network service. The current analysis is based on a locally
   captured generated interpreter and a local bounded trace.

6. Do not remove, mutate, guess, or spoof `la_code`, license identities,
   hardware identities, authentication values, or external keys. Work on the
   already captured generated interpreter.

7. Use exact handler fingerprints, exact source ranges, trace guard evidence,
   and fail-closed recognizers. Do not label an opcode semantic when its handler
   shape or guard path does not match.

8. Keep the report status `blocked` while any reachable semantic operation is
   unresolved or while the readable candidate is not differentially verified.

9. Never claim that reconstructed Luau is the original source. Original local
   names, comments, formatting, and some high-level expression choices were
   erased by obfuscation.

10. The immediate next targets are opcodes `15`, `35`, and `184`, followed by a
    CFG terminal correction for opcode `236`, then the remaining singleton
    opcodes.

## Current Honest Status

The latest full run reconstructed or attached evidence to 2,905 of 2,919
reachable payload instructions. That is 99.52038369304556 percent evidence
coverage, but it is not 99.52 percent readable source reconstruction.

The coverage classes are:

| Coverage class | Instructions | Percent of reachable instructions |
| --- | ---: | ---: |
| Statically proven semantic | 2,246 | 76.94415895854745% |
| Runtime-validated observational semantic | 344 | about 11.785% |
| Trace evidence only | 315 | about 10.791% |
| Unresolved | 14 | 0.47961630695443647% |
| Total reachable | 2,919 | 100% |

Important interpretation:

- `static_semantic` means the deobfuscator has a reusable static semantic for
  the matching handler family and has passed its guard/fingerprint checks.
- `runtime_validated_observational_semantic` means the observed execution
  supports a semantic result on captured paths, but the proof is not yet fully
  static for every possible path.
- `trace_evidence_only` means the trace tells us what happened in this run, but
  that is not enough to emit general program logic safely.
- `unresolved` means a reachable operation still lacks an honest semantic.
- Evidence coverage must never be presented as original-source recovery.

The latest readable candidate is estimated around 43 percent human readability.
That estimate is informal and is not a report-backed score. It is still
VM-shaped and uses generated names. It is far better than the original wrapper,
but it is not close to hand-written source yet.

The current reconstruction status is deliberately `blocked` because 14
reachable operations remain unresolved and differential verification is not
complete.

## Exact Target Sample

Original supplied sample:

`/Users/alexkkork/Downloads/25ms_get.lua.txt`

Properties:

- Size: 177,257 bytes
- SHA-256:
  `73174921ffbb9880c19b58b483848fdaead2d60db2005f20c4d009944582e3f6`
- Detected family: Luraph
- Detected version: v14.7
- This is the currently supported Luraph version for this effort.

The sample contains Luraph authentication/bootstrap material. Do not alter the
authentication values and do not execute the bootstrap against external
services. The useful local object is the already captured generated interpreter.

## Captured Interpreter And Trace

Captured generated interpreter:

`/private/tmp/25ms-repro-captures/loadstring_input_0004.lua`

Interpreter SHA-256:

`c07a61cf17297595bdfcbc3daefae881a0ca44f8a4be2e53b4b185c00c5c0041`

Bounded payload trace:

`/private/tmp/25ms-repro-payload-trace-0718d.log`

Trace properties:

- Approximately 24 MB
- 318,413 lines
- Last trace step: 600,348
- Payload root activation: 15,200
- Payload root prototype: 138
- Payload root VM count: 519,334
- Root evidence marker: `runtime_application_global_handoff`
- Payload prototypes: 57
- Payload activations: 1,176
- Observed payload steps: 39,502
- Closure instructions: 5,283

Observed payload globals include:

- `Instance.new`
- `Random`
- `UDim.new`
- `UDim2.new`
- `Vector2.new`
- `game`
- `task`
- `workspace`

These globals are evidence about the payload surface. They do not by themselves
prove a particular high-level source statement.

## Latest Validated Artifact Set

Latest output directory:

`/private/tmp/25ms-repro-payload-lift-0718v`

Latest external report:

`/private/tmp/25ms-repro-payload-lift-0718v-report.json`

Important files in the output directory:

| File | Purpose |
| --- | --- |
| `deobfuscation_report.json` | Main structured status, coverage, diagnostics, and candidate metadata |
| `runtime_semantic_ir.json` | Runtime-oriented semantic instruction evidence |
| `payload_closure_ir.json` | Payload prototype and closure relationships |
| `payload_reachable_ir.json` | Reachable payload instruction set and semantics |
| `cfg.json` | Blocks, edges, entries, reachability, cycles, and invalid-edge checks |
| `semantic_state_machine_candidate.luau` | Canonical compilable VM/state-machine reconstruction candidate |
| `semantic_readable_candidate.luau` | More readable but still conservative reconstruction candidate |
| `opcode_handlers.json` | Extracted handler identities, ranges, and structure |
| `runtime_prototypes.json` | Parsed runtime prototype metadata |
| `trace_probe.luau` | Bounded trace instrumentation probe |
| `structure_probe.luau` | Structural inspection probe |
| `reconstruction_map.json` | Mapping from emitted statements back to VM evidence |
| `vm_disassembly.txt` | Text disassembly for manual inspection |

Do not rely on `/private/tmp` surviving a reboot. Before a long break or machine
restart, copy the exact evidence set to a durable project artifact directory
without deleting or overwriting earlier runs.

## Latest Candidate Facts

Canonical state-machine candidate:

- 16,432 lines
- 534,340 bytes
- Compiles
- Preserves the conservative state-machine shape
- Is not suitable as a claim of readable original source

Readable candidate:

- 4,266 lines
- 108,281 bytes
- Compiles
- Is partially structured and scalarized
- Is still VM-shaped
- Is not differentially verified
- Is not original source

Report candidate state:

- `available: true`
- `compiled: true`
- `differentially_verified: false`
- `fully_rendered: false`
- `source_claim: false`

There is an older Downloads artifact:

`/Users/alexkkork/Downloads/25ms_get_current_reconstructed.luau`

That file is from an older `0718j` run:

- 2,650 lines
- 98,345 bytes
- SHA-256 begins with `369e776b`

Do not present the older Downloads file as the latest result. Preserve it for
comparison. Only promote a newer candidate after its report, compilation, and
verification state are clearly recorded.

## Latest CFG Facts

The latest control-flow graph reports:

| Metric | Value |
| --- | ---: |
| Prototypes | 57 |
| Blocks | 3,312 |
| Edges | 3,360 |
| Reachable blocks | 2,843 |
| Reachable instructions | 2,919 |
| Invalid edges | 0 |
| Reachable invalid edges | 0 |
| Cyclic regions | 30 |
| Irreducible regions | 20 |
| Observed edge sites | 2,818 |

The graph is structurally valid under the current parser, but valid edges do not
mean every instruction has a valid semantic. The 14 unresolved operations are
still reachable and must be resolved or represented honestly.

## Remaining Reachable Unresolved Operations

By opcode:

| Opcode | Reachable unresolved count |
| ---: | ---: |
| 35 | 2 |
| 184 | 2 |
| 15 | 2 |
| 202 | 1 |
| 194 | 1 |
| 224 | 1 |
| 161 | 1 |
| 117 | 1 |
| 236 | 1 |
| 154 | 1 |
| 185 | 1 |
| Total | 14 |

By prototype:

| Prototype | Reachable unresolved count |
| ---: | ---: |
| 139 | 11 |
| 158 | 2 |
| 159 | 1 |

The best immediate cluster is opcodes 15, 35, and 184 because together they
remove six unresolved sites. After those, implement the opcode 236 CFG terminal
semantics, then inspect the remaining singleton opcodes.

An earlier subagent was asked to inspect opcodes 15, 35, and 184, but its final
analysis was not reliably preserved in the parent context. Reinspect their
handler ranges and trace evidence fresh. Do not invent or assume the missing
analysis.

## Source Layout And Responsibilities

### `src/deobfuscator/core/deob.cpp`

Current size: approximately 23,339 lines.

Responsibilities include:

- Parse the protected source or captured interpreter.
- Detect Luraph structures and version-specific handler shapes.
- Parse trace markers and execution evidence.
- Catalog handlers and exact source ranges.
- Recognize exact opcode semantics.
- Validate handler fingerprints and guard paths.
- Build runtime and payload semantic IR.
- Build prototype and closure graphs.
- Build and validate the CFG.
- Classify static, observational, trace-only, and unresolved coverage.
- Emit reports and artifact metadata.

Approximate recognizer locations before future line drift:

- Opcode 212 recognizer: around line 13,263
- Opcode 61 recognizer: around line 13,382
- Split move recognizer: around line 13,554
- Opcode 76 recognizer: around line 13,693
- Opcode 39 recognizer: around line 13,797
- Nested read recognizer: around line 13,943
- Opcode 209 recognizer: around line 14,083
- Opcode 50 recognizer: around line 14,199
- Opcode 38 recognizer: around line 14,306
- Dispatch wiring: around lines 15,695 through 15,9xx
- Coverage/report logic: around 16,748, 20,092, and 21,871

Search by recognizer function or opcode instead of trusting these line numbers.

### `src/deobfuscator/luraph/emit.cpp`

Current size: approximately 4,817 lines.

Responsibilities include:

- Emit the canonical state-machine candidate.
- Emit the more readable candidate.
- Lower semantic instructions to Luau.
- Represent registers, captures, calls, operand tables, helper tables, and VM
  state without silently changing behavior.
- Scalarize stable registers and capture cells where proof allows it.
- Remove or coalesce aliases conservatively.
- Structure some control-flow regions.
- Preserve statement-to-evidence reconstruction mapping.

### `tests/deobfuscator/luraph/emit_test.cpp`

Current size: approximately 2,811 lines.

Responsibilities include focused emitter and provenance regressions. More direct
recognizer tests are still needed.

### Current Core Line Count

The three main files total approximately 30,967 lines:

- `deob.cpp`: 23,339
- `emit.cpp`: 4,817
- `emit_test.cpp`: 2,811

Treat these as orientation numbers, not quality metrics.

## Build And Focused Test

Run:

```sh
cd /Users/alexkkork/Documents/Codex/2026-07-05/build-a-perfect-luau-runtime-with
cmake --build build --target alex_deobfuscator luraph_semantic_emitter_test -j4
build/tests/luraph_semantic_emitter_test
```

Latest known focused result:

```text
Luraph semantic emitter capture-key provenance tests passed
```

Known non-failing warnings:

- Existing unused parameters in vendored Luau headers
- Existing unused helper `liftLuraphRegisterClearRange`

Do not spend time cleaning unrelated warnings unless they obscure a new warning
caused by the current change.

## Full Regeneration Command

The latest complete command was:

```sh
cd /Users/alexkkork/Documents/Codex/2026-07-05/build-a-perfect-luau-runtime-with

build/alex_deobfuscator \
  /private/tmp/25ms-repro-captures/loadstring_input_0004.lua \
  --output-dir /private/tmp/25ms-repro-payload-lift-0718v \
  --mode reconstruct \
  --trace /private/tmp/25ms-repro-payload-trace-0718d.log \
  --report /private/tmp/25ms-repro-payload-lift-0718v-report.json
```

An exit code of 2 is currently expected because the report status is `blocked`.
The tool still emits the diagnostic and reconstruction artifacts. Do not treat
the expected blocked exit as a crash.

For the next full run, use a fresh suffix such as `0718w`. Never overwrite
`0718v`, because comparison between runs is part of the evidence trail.

Example:

```sh
build/alex_deobfuscator \
  /private/tmp/25ms-repro-captures/loadstring_input_0004.lua \
  --output-dir /private/tmp/25ms-repro-payload-lift-0718w \
  --mode reconstruct \
  --trace /private/tmp/25ms-repro-payload-trace-0718d.log \
  --report /private/tmp/25ms-repro-payload-lift-0718w-report.json
```

## Safe Runtime Configuration

Any local verification or trace probe must remain bounded and offline. Use the
equivalent of:

```text
--profile executor-client
--execution-mode faithful
--filesystem disabled
--network-policy offline
--analysis-hooks off
--no-native-codegen
```

Required boundaries:

- No outbound network.
- No Roblox authentication.
- No Luraph authentication or key service.
- No identity spoofing.
- No hardware identity reads.
- No filesystem APIs exposed to the analyzed Luau.
- Fixed wall-clock and virtual-time budgets.
- Fixed trace event and output caps.
- No native code generation.
- No persistent side effects.

## Trace Markers

The trace and probes use structured markers such as:

- `@@LPH_PROTO_V1@@`
- `@@LPH_INSN_V1@@`
- `@@LPH_STEP_V1@@`
- `@@LPH_GUARD_PATH_V1@@`
- `@@LPH_RETURN_V1@@`

Do not parse these with loose substring guesses when a structured parser is
available. Keep prototype, activation, PC, opcode, operands, next PC, guard
decision, result arity, and return evidence separate.

One known naming problem is `parent_return_observed`. In many current records it
means the parent instruction completed, not that a semantic function return
occurred. Rename or split that field before using it as return proof.

## Proven Recognizers Added Recently

The following recognizers were implemented and validated. Preserve their exact
semantics and fail-closed preconditions.

### Opcode 61: Zero-Argument, Single-Result Call

Static coverage:

- 89 of 89 matching sites
- 3 runtime executions validated
- 0 rejected validation events

Semantic:

```lua
R[Q] = R[Q]()
TOP = Q
```

This must preserve yielding, errors, callable metamethod behavior, and exactly
one result. It is not equivalent to a generic variadic call.

Handler evidence:

- Source range approximately 12,301 through 13,062
- Guard 12,304 through 12,315 observed false
- Guard 12,373 through 12,384 observed false

### Opcodes 36, 96, and 171: Split Move State Machine

Static coverage:

- 235 of 235 matching semantic sites
- 1,410 runtime executions validated
- 0 rejected validation events

Canonical state operations:

```lua
-- opcode 36
p = registers
o = V

-- opcode 96
G = registers
B = h

-- opcode 171
G = G[B]
p[o] = G
```

Combined meaning when all control-flow and liveness conditions are proven:

```lua
R[V_from_opcode_36] = R[h_from_opcode_96]
```

Do not fuse them in the canonical IR. The state assignments are the exact
semantics. A readable-only fusion is allowed only under the proof conditions in
the readability section below.

Handler evidence:

- Opcode 36 range approximately 17,341 through 17,779
- Opcode 36 guards 17,344 through 17,356 false, 17,383 through 17,394 false
- Opcode 96 range approximately 650 through 9,556
- Opcode 96 guards 653 through 665 false, 5,011 through 5,023 false, 5,075 through 5,087 false
- Opcode 171 range approximately 40,572 through 40,917
- Opcode 171 guards 19,910 through 19,922 true, 40,575 through 40,586 false, 40,660 through 40,671 false

### Opcode 76: Indexed Read

Static coverage:

- 554 of 554 sites
- 686 runtime executions validated
- 0 rejected validation events

Semantic:

```lua
R[Q] = R[h][C]
```

Observed key types include:

- Number
- String, including `"new"`
- Boolean
- Nil

Preserve exact Luau indexing behavior, including errors and `__index`
metamethods. Do not pre-coerce the key.

Handler evidence:

- Range approximately 9,892 through 10,051
- Guard 9,895 through 9,907 false
- Guard 9,932 through 9,944 false

### Opcode 39: Prepared State For Nested Read

Static coverage:

- 37 of 37 sites
- 15 runtime executions validated
- 0 rejected validation events

Semantic:

```lua
p = registers
o = Q
G = registers
```

Handler evidence:

- Range approximately 17,076 through 17,267
- Guard 17,079 through 17,090 false
- Guard 17,149 through 17,157 false

### Opcodes 172, 97, and 221: Prepared Nested Read

Static coverage:

- 156 of 156 semantic sites
- 54 runtime executions validated
- 0 rejected validation events

Canonical operations:

```lua
-- opcode 172
B = h
G = G[B]
B = C

-- opcode 97
G = G[B]

-- opcode 221
p[o] = G
```

When preceded by a proven opcode 39 and when CFG/state-liveness constraints are
met, the readable meaning can become a direct nested read. The canonical form
must keep the state sequence.

Handler evidence:

- Opcode 172 uses the opcode 171 handler family path
- Opcode 97 uses the opcode 96 handler family path
- Opcode 221 range approximately 20,133 through 20,142
- Opcode 221 guard 19,910 through 19,922 true

### Opcode 209: Guarded Two-Argument Discard Call

Static coverage:

- 138 of 138 sites
- 13 runtime executions validated
- 0 rejected validation events

Semantic:

```lua
if helper[34] ~= helper[47] then
    R[Q](R[Q + 1], R[Q + 2])
    TOP = Q - 1
end
```

The outer helper guard is semantically observable because it controls whether
the call occurs. Preserve it. The call may yield, throw, invoke `__call`, or
produce side effects. Return values are discarded.

Handler evidence:

- Range approximately 29,988 through 30,097
- Guard 19,910 through 19,922 true
- Guard 29,813 through 29,824 true
- Guard 29,991 through 30,003 false

### Opcode 50: Inclusive Register Range Clear

Static coverage:

- 208 of 208 sites
- 23 runtime executions validated
- 0 rejected validation events

Semantic:

```lua
for registerIndex = V, h do
    R[registerIndex] = nil
end
```

The range is inclusive. The implementation validates the outer guard and one
inner guard decision per logical iteration.

Handler evidence:

- Range approximately 11,972 through 12,074
- Guard 11,975 through 11,987 true
- Guard 12,022 through 12,034 true for each iteration

### Opcode 38: Dynamic Capture Descriptor Read

Static coverage:

- 55 of 55 sites
- 2 runtime executions validated
- 0 rejected validation events

Semantic:

```lua
p = upvalue_file[V]
R[h] = p[1][p[3]]
```

The descriptor must be evaluated once. Do not duplicate `upvalue_file[V]`
because metatable behavior or mutations could make repeated reads differ.

Handler evidence:

- Range approximately 17,076 through 17,267
- Same exact guard family as opcode 39

## Earlier Proven Recognizers

These were added before the latest batch and were green in earlier full corpus
runs. Recheck their report counts after major parser or trace changes.

### Opcode 87: Helper-Bank Load

- 418 of 418 static sites recognized in the earlier full run
- Exact helper-bank source and destination semantics preserved

### Opcode 142: Q Operand-Table Alias

- 946 of 946 static sites recognized in the earlier full run
- Keeps the operand-table alias instead of guessing a direct value

### Opcode 151: Inclusive Clear

- 777 of 777 static sites recognized
- 246 runtime executions validated
- Inclusive range semantics preserved

### Opcode 212: Fixed-Range One-Result Call

- 112 of 112 static sites recognized
- 163 runtime executions validated
- Exact argument range and one-result behavior preserved

### Opcode 23: Argument Copy

- Validation was tightened so operand and range mismatches fail closed

### Opcode 201: Jump

- Jump target bounds validation was added
- Invalid control targets are not silently accepted

### Observed Return Sites

- Proven observed returns now terminate CFG blocks
- This removed a false prototype 83, PC 32 fallthrough edge
- The opcode 236 case still needs a more general terminal override

## Opcode 236: Known Special Case

All 32 observed executions of opcode 236 returned zero values. However, the
handler has state-dependent paths that may return a boolean and may perform
cleanup before returning.

Safe current conclusion:

- It is a control terminal.
- It must have no CFG successors.
- Its return values are not yet statically resolved.
- Its pre-return side effects are not yet fully resolved.
- It must not be emitted as an unconditional plain empty `return`.
- Prototype 159, PC 24 remains reachable through a jump from PC 44.

Current CFG behavior for unknown instructions can fall through, which produces a
false PC 24 to PC 25 edge. Add a conservative semantic such as:

```json
{
  "cfg_terminal_override": "return_unknown"
}
```

The exact field name can follow local conventions. The required behavior is:

- terminate the block,
- emit no successor,
- preserve unresolved return arity/value metadata,
- preserve unresolved pre-return side-effect metadata,
- avoid pretending an empty return is proven.

When trace events contain both a next-PC-looking value and return evidence, the
return evidence should dominate CFG successor construction.

## Exact Recognizer Design Rules

Every new opcode recognizer should follow this checklist:

1. Identify all reachable sites for the opcode and prototype family.
2. Locate the exact handler source range in `opcode_handlers.json` and the
   captured interpreter.
3. Parse the handler structurally. Do not depend only on a randomized identifier
   or the numeric opcode.
4. Record the exact guard decisions required to reach the semantic body.
5. Confirm operands, table aliases, state fields, and assignment order.
6. Determine result arity: zero, one, fixed N, or variadic.
7. Determine whether it can yield, error, call metamethods, or mutate shared
   state.
8. Determine CFG behavior: fallthrough, jump, branch, iterator edge, or terminal.
9. Determine capture/upvalue behavior and whether descriptor reads must occur
   exactly once.
10. Validate every captured execution against the proposed semantic.
11. Reject mismatched guard paths instead of accepting them as close enough.
12. Emit a proof tag containing opcode, handler fingerprint/range, and semantic
    kind.
13. Add the recognizer to dispatch without shadowing a more specific handler.
14. Add focused regression tests for accepted and rejected shapes.
15. Regenerate into a fresh artifact directory and compare coverage counts.

Static proof must come from the handler structure plus its validated control
path. A trace is supporting evidence, not a replacement for static semantics.

## Readability Reconstruction Rules

The canonical state-machine candidate and readable candidate serve different
purposes.

The canonical candidate should preserve exact state operations even when they
look ugly. The readable candidate can fuse operations only after CFG and
liveness proofs show that the intermediate VM state is not externally visible.

### Safe Split-Move Fusion

Opcodes 36, 96, and 171 can be rendered as one direct move only if all of these
conditions hold:

- All three instructions carry the exact proof tags.
- Their PCs are consecutive: A, A+1, A+2.
- Successors are exactly A to A+1, A+1 to A+2, and A+2 to A+3.
- The middle two blocks or instruction sites each have one predecessor.
- Neither middle instruction is a prototype entry.
- There are zero invalid edges touching the sequence.
- State liveness proves `p`, `o`, `G`, and `B` are dead or overwritten before
  another read.
- No unresolved downstream operation can inspect that state.

The emitted statement can then be:

```lua
register_destination = register_source
```

The reconstruction map must still reference all three VM PCs. Attribute the
final rendered statement primarily to the opcode 171 PC but retain the setup
provenance.

### Safe Nested-Read Fusion

The opcode 39, 172, 97, 221 chain can be collapsed to a direct indexed
expression only if:

- The exact recognizers matched.
- The sites form one linear region with no alternate entry.
- The relevant VM state is dead after the final write.
- Register/table/key expressions are each evaluated exactly once.
- No unresolved instruction observes `p`, `o`, `G`, or `B` in the middle.
- The direct expression preserves `__index` order and errors.

Do not transform an exact step sequence into duplicated table/key expressions.

### Region Structuring

After all reachable opcodes have semantics:

1. Compute dominators and post-dominators per prototype.
2. Identify natural loops from back edges.
3. Identify single-entry/single-exit conditional regions.
4. Preserve irreducible regions as a small semantic state machine.
5. Convert proven loop protocols to `while`, `repeat`, numeric `for`, or generic
   `for` only when iterator/result arity matches.
6. Inline one-use pure temporaries.
7. Coalesce producer aliases only when order and metamethod behavior are safe.
8. Promote callback values into direct function expressions where capture and
   identity behavior remains correct.
9. Infer local names only after semantics are stable.
10. Keep a reconstruction map for every emitted statement.

### Naming

Original local names are not available. Use deterministic semantic names such
as:

- `players`
- `workspaceService`
- `part`
- `connection`
- `callback`
- `result`
- `argument_1`
- `local_1`
- `upvalue_1`

Only assign a domain name when its use strongly supports that meaning. Keep a
confidence or provenance record for inferred names. Never say the name was
recovered from the original source unless there is actual source-bearing data.

## Differential Verification Requirements

Compilation is necessary but not sufficient.

Run the captured generated interpreter and reconstructed candidate under the
same safe local runtime profile and the same fixture/scenario. Compare:

- Return count and values
- Printed output
- Warnings and errors
- Normalized stack/error locations where appropriate
- Global writes
- Roblox Instance and service effects
- Attribute and property writes
- Calls and method calls
- Signal connections and callbacks
- Scheduler events
- Yield/resume behavior
- Unsupported calls
- Termination reason

Do not normalize away semantic differences. Only normalize known path and line
number noise in error strings when the test explicitly allows it.

Do not substitute observed stdout or a recorded event list for missing program
logic. A replay can be a debugging artifact, never reconstructed source.

## Correctness Hazards

### Metamethods

Table reads, writes, arithmetic, equality, length, concatenation, calls, and
iteration may invoke metamethods. Reordering or duplicating an expression can
change behavior.

### Multiple Returns

Luau expands only final expressions in many contexts. Parentheses truncate
multiple results. Calls need explicit arity tracking.

### Assignment Order

Indexed assignment targets must evaluate object and key expressions exactly once
and in Luau order. Do not emit a simpler assignment that repeats either side.

### Closures And Captures

Capture descriptors can point into mutable cells. Closure identity and shared
upvalue mutation must survive reconstruction.

### Errors And Yields

Calls can yield or error. Protected calls, coroutines, callbacks, and task
scheduling require callable Luau closures and correct resume behavior.

### Trace Path Bias

The trace covers one bounded scenario. A branch not taken in the trace can still
be reachable for another input. Treat unobserved paths conservatively.

### Helper Guards

Some Luraph helper comparisons are not dead protector noise. Opcode 209 proves
that a helper guard can control whether a side-effectful call occurs.

### Return Markers

Do not infer return just because a parent instruction completed. Separate VM
instruction completion, prototype return, callback completion, and root
termination.

## Report Truthfulness Rules

The website and CLI previously had confusing recovery claims. Use these rules:

- `recovered_exact` only if source-bearing original Luau is actually found,
  compiles, and structurally matches the payload. This is not expected for the
  current sample.
- `reconstructed` only when all reachable operations are lifted, output
  compiles, and required verification gates pass.
- `disassembled` when the VM is decoded but semantic reconstruction is
  incomplete.
- `blocked` when reachable operations or required keys/edges remain unresolved.
- Never display the protected wrapper as reconstructed source.
- Never display a trace replay as reconstructed source.
- Never report 100 readability merely because compilation succeeds.
- Never report original source when names/comments/formatting were inferred.

For the current run, the correct claim is:

> A compilable reconstructed Luau candidate exists, but complete behavioral
> reconstruction and differential equivalence have not yet been proven.

## Quick Report Inspection Commands

Use Ruby or existing JSON tools instead of editing reports manually.

Example top-level inspection:

```sh
ruby -rjson -e '
  p = JSON.parse(File.read(ARGV[0]));
  puts JSON.pretty_generate(p.slice("status", "coverage", "verification", "semantic_candidate"))
' /private/tmp/25ms-repro-payload-lift-0718v-report.json
```

Example unresolved opcode count from the reachable IR, adapting field names to
the current schema:

```sh
ruby -rjson -e '
  rows = JSON.parse(File.read(ARGV[0]));
  rows = rows["instructions"] if rows.is_a?(Hash);
  counts = Hash.new(0);
  rows.each do |row|
    next unless row["reachable"];
    next unless row["coverage_class"] == "unresolved";
    counts[row["opcode"]] += 1;
  end;
  puts counts.sort_by { |opcode, _| opcode.to_i }.to_h
' /private/tmp/25ms-repro-payload-lift-0718v/payload_reachable_ir.json
```

The schema may evolve. Inspect actual keys before trusting a query that returns
zero rows.

## Recommended Next Implementation Sequence

### Phase 1: Preserve Evidence

1. Copy the interpreter, trace, `0718v` artifact directory, and external report
   to a durable, timestamped project artifact directory.
2. Record hashes and sizes.
3. Do not delete the `/private/tmp` originals until the durable copies verify.

### Phase 2: Resolve Opcode Cluster 15/35/184

1. List every reachable site and prototype.
2. Extract each handler range and normalized structure.
3. Trace all executions at those PCs, including guard decisions and state
   changes.
4. Determine whether the three opcodes form one split semantic sequence.
5. Check alternate entries and predecessor counts.
6. Specify canonical state operations first.
7. Implement exact fail-closed recognizers.
8. Add focused accepted and rejected tests.
9. Rebuild and run focused tests.
10. Regenerate to `0718w` and require the six sites to leave `unresolved` with
    zero validation rejections.

### Phase 3: Correct Opcode 236 CFG Termination

1. Add conservative `return_unknown` terminal metadata.
2. Remove false fallthrough from PC 24 to PC 25.
3. Preserve unresolved return values and pre-return side effects.
4. Add CFG regression tests.
5. Verify prototype 159 reachability remains correct through PC 44.

### Phase 4: Resolve Singleton Opcodes

Inspect in a trace- and handler-informed order:

- 202
- 194
- 224
- 161
- 117
- 154
- 185

Group any that share handler fingerprints or state sequences. Do not create
seven near-duplicate recognizers if one structural recognizer safely covers a
family.

### Phase 5: Strengthen Tests

1. Add direct unit tests for every recently added recognizer.
2. Include guard mismatch rejection tests.
3. Include handler-range/fingerprint mismatch rejection tests.
4. Include operand boundary and malformed trace tests.
5. Include metamethod-sensitive cases.
6. Include call arity, errors, and yields.
7. Include alternate CFG entries that must block readable fusion.

### Phase 6: Full Regeneration And Audit

1. Run a fresh full reconstruction.
2. Confirm reachable invalid edges remain zero.
3. Confirm every new validation has zero rejections.
4. Confirm the canonical candidate compiles.
5. Confirm the readable candidate compiles.
6. Confirm the report does not overclaim source recovery.
7. Compare artifact sizes and coverage with `0718v`.

### Phase 7: Differential Verification

1. Create a deterministic offline scenario for the observed Roblox globals.
2. Run the captured interpreter under strict budgets.
3. Run the canonical candidate under the same scenario.
4. Compare returns, output/errors, writes, calls, scheduler events, and
   termination.
5. Only after canonical equivalence, verify the readable candidate.
6. Record the exact runtime binary hash and scenario hash.

### Phase 8: Readability

1. Fuse the proven split move sequence in readable output.
2. Fuse the proven nested read sequence.
3. Structure reducible conditionals and loops.
4. Scalarize registers and captures with dataflow proof.
5. Inline pure one-use producers.
6. Coalesce safe aliases.
7. Promote direct callbacks.
8. Infer conservative semantic local names.
9. Keep irreducible regions as small state machines.
10. Re-run differential verification after every pass family.

## Definition Of Done For This Sample

The sample is not done merely when unresolved count reaches zero.

Minimum completion gates:

- All 2,919 reachable instructions have non-trace-only reusable semantics, or a
  precisely represented conservative semantic where values cannot be known.
- No reachable invalid CFG edges.
- Every prototype has valid entries, terminators, closure references, captures,
  and return arity.
- Canonical reconstructed Luau compiles.
- Canonical reconstructed Luau is differentially equivalent under the committed
  offline scenario set.
- Readable reconstruction compiles.
- Readable reconstruction is differentially equivalent to the canonical form.
- Reconstruction map covers every emitted semantic statement.
- Report clearly says reconstructed, not original source.
- No network, identity spoofing, key bypass, or source replay is involved.
- The promoted artifact and report are copied to a durable location with hashes.

Readability can continue improving after these gates. Exact original comments,
formatting, and erased local names are not a realistic completion gate.

## What Not To Do

- Do not call external authentication or obfuscation services.
- Do not guess a license response.
- Do not strip auth variables from the original sample and pretend it is a
  successful deobfuscation.
- Do not change the trace to fit a proposed semantic.
- Do not map unknown opcodes to `nop`.
- Do not turn every observed return into an empty source return.
- Do not use regex-only rewriting for VM semantics.
- Do not emit the 177 KB protected wrapper as `source`.
- Do not emit the generated interpreter as reconstructed payload.
- Do not emit recorded output as reconstructed payload.
- Do not count trace-only instructions as statically reconstructed semantics.
- Do not fake 100/100 readability.
- Do not claim inferred names are original names.
- Do not overwrite previous evidence directories.
- Do not push, deploy, or change the website unless explicitly requested.
- Do not revert unrelated user changes.
- Do not include passwords, tokens, cookies, or private credentials in reports,
  commits, or future handoff documents.

## Wider Project Context

This workspace grew from several connected efforts. The current priority is the
Luraph deobfuscator, but the next AI may encounter files from the other efforts.

### Luau/Roblox Runtime

The project includes a native Luau runtime intended to approximate script-visible
Roblox client behavior for offline analysis and differential tests. Earlier work
covered:

- Executor and Roblox-client profiles
- Sandboxed environments
- `_G`, `getfenv`, `getgenv`, `getrenv`, and `getsenv` behavior
- A coroutine/task scheduler
- Roblox-like Instances, services, signals, and value types
- Fixture-backed HTTP and service behavior
- Offline network policy and structured termination reasons
- A web runner with local and hosted UI experiments

For deobfuscation, the runtime is a verifier and bounded tracer. It must never be
used to replace missing program logic with an observed replay.

### WeAreDevs Deobfuscator

There is earlier WeAreDevs v1 analysis and reconstruction code in the workspace.
That work introduced useful ideas:

- Structural family detection
- String-table and wrapper decoding
- CFG recovery
- VM-to-semantic lifting
- State-machine fallback for irreducible control flow
- Deterministic generated names
- Reconstruction maps
- Honest source withholding when lifting is incomplete

Do not confuse WeAreDevs handler semantics with Luraph v14.7 semantics. Reuse
architecture and tests only where the behavior is genuinely shared.

### Website

A local deobfuscator UI has been run around:

`http://127.0.0.1:8807/deobfuscator`

The UI has shown stages such as Detect, Decode, CFG, Lift, Structure, and Verify,
plus coverage and readability fields. The website has previously displayed
confusing or empty metrics. The current task is core deobfuscation, and the user
explicitly asked at one point not to change the site yet. Do not spend core
analysis time polishing UI unless explicitly redirected.

When UI work resumes, it should display the four coverage classes separately and
explain why evidence coverage is not static reconstruction or original-source
recovery.

### Alexfuscator And Alex Language

The workspace also contains plans and partial work around Alexfuscator, AlexIR,
AlexVM, and an Alex source language. Those are obfuscator/compiler projects, not
the current Luraph deobfuscation goal. Do not switch to them unless the user asks.

### C# Luraph Project

There is a nested `luraph_c#` repository used for C# deobfuscator experiments,
configuration, packaging, and GitHub pushes. The active evidence-backed opcode
work described in this document is currently in the C++ deobfuscator files under
the workspace root. Do not assume that improving one automatically updates the
other. Synchronization requires an explicit, reviewed port.

### Mobile/Mac Codex Experiments

The conversation also included Swift app experiments for remote Codex task
monitoring and automatic continuation. Those apps are unrelated to Luraph
semantics and should not distract from this handoff.

## Repository And Git Notes

The workspace root is not itself a Git repository.

Known nested repositories include:

- `luraph_c#/.git`
- `vendor/luau/.git`

Consequences:

- `git status` at the workspace root will not describe all files.
- Do not initialize or reorganize repositories without explicit permission.
- Do not commit vendored Luau changes accidentally.
- Do not push the full workspace to an unrelated repository.
- Do not expose local captures or private sample material in public Git history.

No push or deployment is requested by this handoff.

## Suggested Durable Evidence Layout

Create a local artifact layout similar to:

```text
artifacts/
  luraph-v14.7/
    25ms_get/
      sample.sha256.txt
      interpreter/
        loadstring_input_0004.lua
        sha256.txt
      traces/
        0718d.log
        0718d.sha256.txt
      runs/
        0718v/
          artifacts...
        0718w/
          artifacts...
```

If the sample is sensitive, keep this directory ignored and local. Record only
source-free fixture metadata in a repository unless the user explicitly approves
committing the sample.

## Suggested Progress Reporting

When the user asks for percentages, report at least these separate numbers:

```text
Static semantic reconstruction: 76.94%
Runtime-observational semantics: 11.79%
Trace-only evidence: 10.79%
Unresolved reachable operations: 0.48%
Total evidence coverage: 99.52%
Differential verification: not complete
Readable-source quality: estimated about 43%, informal
Original names/comments/formatting: not recoverable from current evidence
```

Do not collapse these into one percentage. The user strongly wants 100/100, but
the correct response is to improve the implementation and keep the metrics
truthful.

## Suggested Work Update Style

Keep updates concise and concrete. Good examples:

- "I found both reachable opcode 35 sites in prototype 139 and am comparing the
  exact handler branch with their guard traces."
- "The recognizer now accepts the two captured sites and rejects a modified
  guard path; I am rebuilding the full artifact set next."
- "Unresolved dropped from 14 to 12, but the new sites are observational rather
  than static, so static semantic coverage did not increase yet."

Avoid vague updates such as "still working" when a specific file, recognizer,
test, or coverage change can be named.

## Final Handoff Snapshot

At the moment this document was written:

- The Luraph v14.7 envelope and generated interpreter are captured locally.
- The payload root, 57 prototypes, closure graph, and reachable CFG are known.
- 2,246 of 2,919 reachable operations have static semantics.
- 344 have runtime-validated observational semantics.
- 315 have trace-only evidence.
- 14 remain unresolved.
- The CFG has no reported invalid reachable edges, except the known semantic
  fallthrough issue for opcode 236 that should be corrected with a terminal
  override.
- Both canonical and readable candidates compile.
- Neither candidate has completed differential verification.
- The readable candidate is still substantially VM-shaped.
- The next high-value work is the opcode 15/35/184 cluster.
- The final goal is readable, behaviorally equivalent reconstructed Luau, not a
  false claim of byte-for-byte original source.

Continue from the evidence, keep every transformation reversible through the
reconstruction map, and make the report more honest as the code becomes more
capable.
