#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import random
import re
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILES = ("compatibility", "hardened", "maximum")
SEEDS = (101, 202, 303)


def run(command, *, check=True):
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(map(str, command))}\n{result.stderr}")
    return result


def generated_program(index, seed=0xA13F):
    rng = random.Random(seed + index * 7919)
    a = rng.randint(2, 19)
    b = rng.randint(3, 23)
    c = rng.randint(2, 8)
    kind = index % 12

    programs = (
        f"""local captured = {a}
local function step(value) captured += value return captured end
local function fib(n) if n < 2 then return n end return fib(n - 1) + fib(n - 2) end
print("closure", step({b}), step({c}), fib(7))
return captured
""",
        f"""local function spread(first, ...) return first + {a}, ... end
local x, y, z = spread({b}, nil, {c})
local grouped, missing = (spread({c}, {a}))
print("arity", x, y, z, grouped, missing)
return x, y, z
""",
        f"""local total = 0
for value = 1, {b} do if value % {c} == 0 then continue end total += value end
local n = 0
repeat n += 1 if n == 2 then continue end total += n until n >= {c + 2}
for _, value in ipairs({{{a}, {b}, {c}}}) do total += value end
print("loops", total, n)
return total
""",
        f"""local calls = 0
local box = {{{a}}}
local function target() calls += 1 return box end
local function key() calls += 1 return 1 end
target()[key()] += {b}
local left, right = {a}, {b}
left, right = right, left
print("assign", box[1], calls, left, right)
return box[1], calls
""",
        f"""local mt = {{__add=function(self, value) return self.value + value end}}
local object = setmetatable({{value={a}}}, mt)
function object:scale(value) return self.value * value end
print("meta", object + {b}, object:scale({c}))
return object + {c}
""",
        f"""local value = {a}
local label = `value:{{value + {b}}}:{{if value > 0 then "yes" else "no"}}`
local list = {{1, 2, (function() return {c}, {b} end)()}}
print("interp", label, #list, list[3], list[4])
return label
""",
        f"""local thread = coroutine.create(function(value)
    local resumed = coroutine.yield(value + {a})
    return resumed + {b}
end)
local ok1, first = coroutine.resume(thread, {c})
local ok2, second = coroutine.resume(thread, {a})
print("coroutine", ok1, first, ok2, second, coroutine.status(thread))
return second
""",
        f"""local source = setmetatable({{{a}, {b}, {c}}}, {{
    __iter=function(self)
        local index = 0
        return function()
            index += 1
            if self[index] ~= nil then return index, self[index] end
        end
    end
}})
local total = 0
for key, value in source do total += key * value end
print("iterator", total)
return total
""",
        f"""local nan = 0 / 0
local negativeZero = -0.0
local infinity = 1 / 0
print("numbers", nan ~= nan, 1 / negativeZero == -infinity, infinity > {a})
return nan ~= nan
""",
        f"""local function apply(callback, ...) return callback(...) end
local factor = {c}
local function callback(left, right) return (left + right) * factor end
local result = apply(callback, {a}, {b})
print("callback", result)
return result
""",
        f"""local ok, message = pcall(function()
    local value = nil
    return value.missing
end)
local ok2, value = pcall(function() return {a} + {b} end)
print("errors", ok, type(message), ok2, value)
return ok, ok2
""",
        f"""local function tail() return {a}, nil, {b}, {c} end
local packed = {{"start", tail()}}
local one, two, three, four = tail()
print("tables", #packed, packed[1], packed[2], packed[3], packed[4], one, two, three, four)
return tail()
""",
    )
    return programs[kind]


def normalize_error(value):
    if isinstance(value, str):
        return re.sub(r"(?:[^\s:]+[/\\])*[^\s:]+\.lua(?:u)?:\d+:\s*", "", value)
    if isinstance(value, dict):
        return {key: normalize_error(item) for key, item in value.items() if key not in {"source", "path", "thread"}}
    if isinstance(value, list):
        return [normalize_error(item) for item in value]
    return value


def runtime_observation(runtime, source, temporary, label):
    report_path = temporary / f"{label}-runtime.json"
    output_dir = temporary / f"{label}-captures"
    shutil.rmtree(output_dir, ignore_errors=True)
    result = run([
        str(runtime), "--luraph-mode", "off", "--analysis-hooks", "off", "--network-policy", "offline",
        "--report", str(report_path), "--out", str(output_dir), str(source),
    ], check=False)
    if not report_path.exists():
        raise RuntimeError(f"runtime did not produce a report for {label}: {result.stderr}")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    scheduler = report.get("scheduler") or {}
    events = [
        {key: event.get(key) for key in ("kind", "frame", "time")}
        for event in scheduler.get("events", [])
    ]
    return {
        "exit_code": result.returncode,
        "status": report.get("status"),
        "termination_reason": report.get("termination_reason"),
        "returns": report.get("returns"),
        "stdout": report.get("stdout"),
        "stderr": normalize_error(report.get("stderr")),
        "error": normalize_error(report.get("error")),
        "unsupported": report.get("unsupported"),
        "scheduler": {
            "budget_reached": scheduler.get("budget_reached"),
            "stop_reason": scheduler.get("stop_reason"),
            "frames": scheduler.get("frames"),
            "virtual_time": scheduler.get("virtual_time"),
            "events": events,
        },
    }


def verify_source(source_text, name, alexfuscator, runtime, temporary):
    source = temporary / "source.luau"
    artifact = temporary / "artifact.luau"
    compile_report = temporary / "compile-report.json"
    source.write_text(source_text, encoding="utf-8")
    expected = runtime_observation(runtime, source, temporary, f"{name}-original")

    for profile in PROFILES:
        for seed in SEEDS:
            run([
                str(alexfuscator), str(source), "-o", str(artifact), "--report", str(compile_report),
                "--profile", profile, "--runtime", "universal", "--environment-binding", "portable",
                "--seed", str(seed), "--format", "one-line", "--no-watermark",
            ])
            generated = artifact.read_text(encoding="utf-8")
            descriptor = json.loads(compile_report.read_text(encoding="utf-8"))
            if descriptor.get("report_version") != 4 or descriptor.get("backend") != "alexvm6" or descriptor.get("vm_version") != 6:
                raise RuntimeError(f"invalid VM 6 report in {name}/{profile}/{seed}: {descriptor}")
            if descriptor.get("profile") != profile or descriptor.get("fallback_used") is not False:
                raise RuntimeError(f"profile downgrade in {name}/{profile}/{seed}: {descriptor}")
            if "loadstring" in generated or source_text.strip() in generated:
                raise RuntimeError(f"plaintext/source-loader regression in {name}/{profile}/{seed}")
            actual = runtime_observation(runtime, artifact, temporary, f"{name}-{profile}-{seed}")
            if actual != expected:
                raise RuntimeError(
                    f"semantic mismatch in {name}/{profile}/{seed}\n"
                    f"source:\n{source_text}\nexpected={json.dumps(expected, sort_keys=True)}\nactual={json.dumps(actual, sort_keys=True)}"
                )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--programs", type=int, default=int(os.environ.get("ALEX_SEMANTIC_PROGRAMS", "500")))
    parser.add_argument("--alexfuscator", type=pathlib.Path, default=ROOT / "build" / "alexfuscator")
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    parser.add_argument("--skip-fixture", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="alex-vnext-diff-") as directory:
        temporary = pathlib.Path(directory)
        if not args.skip_fixture:
            verify_source((ROOT / "tests" / "vnext_semantics.luau").read_text(encoding="utf-8"), "fixture", args.alexfuscator, args.runtime, temporary)
        for index in range(args.programs):
            verify_source(generated_program(index), f"generated-{index:05d}", args.alexfuscator, args.runtime, temporary)
            if (index + 1) % 25 == 0:
                print(f"verified {index + 1}/{args.programs} independent programs", flush=True)

    total = args.programs + (0 if args.skip_fixture else 1)
    print(f"vNext differential OK: {total} independent programs, 3 profiles, 3 seeds")


if __name__ == "__main__":
    main()
