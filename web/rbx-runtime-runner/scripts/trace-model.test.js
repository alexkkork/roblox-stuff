const test = require("node:test");
const assert = require("node:assert/strict");

const traceModel = require("../public/trace-model.js");

function repeated(kind, name, count) {
  return Array.from({ length: count }, () => ({ kind, name }));
}

test("23 fingerprint checks become one narrated environment scan with counts and examples", () => {
  const compatTrace = [
    ...repeated("missing_global", "getgc", 10),
    ...repeated("missing_global", "hookfunction", 6),
    ...repeated("missing_member", "DataModel.Hidden", 4),
    ...repeated("unsupported_call", "request", 3)
  ];

  const events = traceModel.buildTraceEvents({ ok: true, compatTrace });
  const scans = events.filter((event) => event.raw?.kind === "environment_scan");

  assert.equal(scans.length, 1);
  assert.equal(scans[0].count, 23);
  assert.equal(scans[0].raw.count, 23);
  assert.equal(scans[0].raw.uniqueCount, 4);
  assert.match(scans[0].description, /23 unavailable or restricted API checks/);
  assert.match(scans[0].description, /4 unique names/);
  assert.match(scans[0].description, /getgc \(10x\)/);
  assert.match(scans[0].description, /hookfunction \(6x\)/);
  assert.match(scans[0].description, /intent/);
  assert.equal(events.filter((event) => event.category === "PROBE").length, 0);
});

test("internal codegen is filtered while the user compile and stdout payload event remain", () => {
  const events = traceModel.buildTraceEvents({
    ok: true,
    stdout: "hello from payload\nvalue 42\n",
    compatTrace: [
      { kind: "native_codegen", name: "=roblox_runtime_setup", functionsCompiled: 69, functionsTotal: 69, result: "Success" },
      { kind: "native_codegen", name: "=roblox_high_fidelity_setup", functionsCompiled: 139, functionsTotal: 139, result: "Success" },
      { kind: "native_codegen", name: "=Web Runner Script", functionsCompiled: 12, functionsTotal: 12, result: "Success" }
    ]
  }, { chunkName: "Web Runner Script" });

  const compileEvents = events.filter((event) => event.category === "COMPILE");
  assert.equal(compileEvents.length, 1);
  assert.match(compileEvents[0].description, /Web Runner Script/);
  assert.doesNotMatch(compileEvents[0].description, /roblox_(?:runtime|high_fidelity)_setup/);

  const output = events.find((event) => event.category === "OUTPUT");
  assert.ok(output);
  assert.equal(output.phase, "PAYLOAD");
  assert.equal(output.confidence, "Direct");
  assert.match(output.description, /hello from payload/);
});

test("network requirements remain direct evidence even beside a large environment scan", () => {
  const url = "https://example.test/key.lua";
  const events = traceModel.buildTraceEvents({
    ok: false,
    terminationReason: "network_required",
    compatTrace: [
      ...repeated("missing_global", "getgc", 30),
      { kind: "network_blocked", name: url, host: "example.test" }
    ],
    networkRequirements: [{ host: "example.test", url, policy: "allowlist" }]
  });

  const network = events.filter((event) => event.category === "NETWORK");
  assert.ok(network.length >= 1);
  assert.ok(network.every((event) => event.confidence === "Direct"));
  assert.ok(network.some((event) => event.description.includes(url)));
});

test("identical runtime and scheduler noise is summarized", () => {
  const schedulerEvents = [];
  for (let index = 0; index < 12; index += 1) {
    schedulerEvents.push({ kind: "resume", frame: 1, time: 0 });
    schedulerEvents.push({ kind: "complete", frame: 1, time: 0 });
  }
  const events = traceModel.buildTraceEvents({
    ok: true,
    compatTrace: repeated("api_call", "Workspace.GetChildren", 8),
    runtimeReport: { scheduler: { events: schedulerEvents } }
  });

  const runtime = events.filter((event) => event.category === "RUNTIME");
  assert.equal(runtime.length, 1);
  assert.equal(runtime[0].count, 8);
  const scheduler = events.filter((event) => event.category === "SCHEDULE");
  assert.equal(scheduler.length, 1);
  assert.equal(scheduler[0].count, 24);
  assert.match(scheduler[0].description, /resume 12/);
  assert.match(scheduler[0].description, /complete 12/);
});

test("WeAreDevs narration requires structural evidence and stays inferred", () => {
  const source = `return(function(...)
local h={"\\065\\066\\067\\068\\069\\070\\071\\072\\073\\074\\075\\076\\077\\078\\079\\080"}
for i,p in ipairs({{1,2}}) do while p[1]<p[2] do h[p[1]],h[p[2]]=h[p[2]],h[p[1]] end end
local a=table.concat local b=string.char local c=string.sub local d=math.floor
local function decode(value) if c(value,1,1)=="\\061" then return b(d(64%3)) end return a({value}) end
local state=10 while state do if state<5 then state=nil else state=4 end end
return decode((getfenv and getfenv() or _ENV) and h[1])
end)(...)`;

  const events = traceModel.buildTraceEvents({ ok: true }, { source });
  const detected = events.find((event) => event.category === "DETECT");
  const decoded = events.find((event) => event.category === "DECODE");
  assert.ok(detected);
  assert.ok(decoded);
  assert.equal(detected.confidence, "Inferred");
  assert.equal(decoded.confidence, "Inferred");
  assert.match(detected.description, /does not reveal the original payload/);
  assert.match(decoded.description, /no plaintext payload or completed decryption was directly observed/i);

  const commentOnly = traceModel.buildTraceEvents({ ok: true }, {
    source: "--[[ v1.0.0 https://wearedevs.net/obfuscator ]] print('hello')"
  });
  assert.equal(commentOnly.some((event) => event.category === "DETECT"), false);
});
