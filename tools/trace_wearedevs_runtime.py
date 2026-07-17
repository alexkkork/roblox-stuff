#!/usr/bin/env python3
"""Build and run a trace harness around an obfuscated WeAreDevs sample.

The goal is to collect actual runtime operations from the transformed program
without relying on stdout-only reconstruction.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from pathlib import Path


PRELUDE = r'''
local __wd_trace = {}
local __wd_raw_print = print
local __wd_raw_table_concat = table and table.concat
local __wd_raw_string_byte = string and string.byte
local __wd_raw_string_sub = string and string.sub

local function __wd_escape(s)
    s = tostring(s)
    local out = {}
    for i = 1, #s do
        local b = __wd_raw_string_byte(s, i)
        if b == 34 then
            out[#out + 1] = '\\"'
        elseif b == 92 then
            out[#out + 1] = "\\\\"
        elseif b >= 32 and b <= 126 then
            out[#out + 1] = __wd_raw_string_sub(s, i, i)
        elseif b == 10 then
            out[#out + 1] = "\\n"
        elseif b == 13 then
            out[#out + 1] = "\\r"
        elseif b == 9 then
            out[#out + 1] = "\\t"
        else
            out[#out + 1] = string.format("\\u%04x", b)
        end
    end
    return '"' .. __wd_raw_table_concat(out, "") .. '"'
end

local function __wd_repr(v, depth)
    depth = depth or 0
    local tv = type(v)
    if tv == "nil" then
        return "null"
    elseif tv == "string" then
        return __wd_escape(v)
    elseif tv == "number" or tv == "boolean" then
        return tostring(v)
    elseif tv == "function" then
        return __wd_escape("function")
    elseif tv == "table" then
        return __wd_escape(tostring(v))
    else
        return __wd_escape(tv .. ":" .. tostring(v))
    end
end

local function __wd_log(kind, ...)
    local values = {}
    for i = 1, select("#", ...) do
        values[i] = __wd_repr((select(i, ...)))
    end
    table.insert(__wd_trace, '{"kind":' .. __wd_escape(kind) .. ',"values":[' .. __wd_raw_table_concat(values, ",") .. "]}")
end

local function __wd_pack(...)
    return { n = select("#", ...), ... }
end

local function __wd_wrap(container, key, label)
    if type(container) ~= "table" or type(container[key]) ~= "function" then
        return
    end
    local raw = container[key]
    container[key] = function(...)
        local results = __wd_pack(raw(...))
        __wd_log(label or key, "args", ..., "returns", table.unpack(results, 1, results.n))
        return table.unpack(results, 1, results.n)
    end
end

-- Avoid pcall/xpcall wrapping: this obfuscator checks exact pcall error line
-- text. These wrappers keep the values and return counts stable for the APIs
-- we need to prove the recovered source.
local __wd_raw_print2 = print
print = function(...)
    __wd_log("print", ...)
    return __wd_raw_print2(...)
end

if math then
    for _, key in ipairs({ "min", "floor", "sqrt" }) do
        local raw = math[key]
        if type(raw) == "function" then
            math[key] = function(...)
                local results = __wd_pack(raw(...))
                __wd_log("math." .. key, "args", ..., "returns", table.unpack(results, 1, results.n))
                return table.unpack(results, 1, results.n)
            end
        end
    end
end

if string then
    for _, key in ipairs({ "reverse", "upper", "byte" }) do
        local raw = string[key]
        if type(raw) == "function" then
            string[key] = function(...)
                local results = __wd_pack(raw(...))
                __wd_log("string." .. key, "args", ..., "returns", table.unpack(results, 1, results.n))
                return table.unpack(results, 1, results.n)
            end
        end
    end
end

if table and type(table.concat) == "function" then
    local raw_concat = table.concat
    table.concat = function(...)
        local result = raw_concat(...)
        __wd_log("table.concat", "args", ..., "returns", result)
        return result
    end
end

if type(ipairs) == "function" then
    local raw_ipairs = ipairs
    ipairs = function(t)
        local iter, state, initial = raw_ipairs(t)
        return function(st, key)
            local nextKey, value = iter(st, key)
            if nextKey ~= nil then
                __wd_log("ipairs.yield", nextKey, value)
            end
            return nextKey, value
        end, state, initial
    end
end

if type(pairs) == "function" then
    local raw_pairs = pairs
    pairs = function(t)
        local iter, state, initial = raw_pairs(t)
        return function(st, key)
            local nextKey, value = iter(st, key)
            if nextKey ~= nil then
                __wd_log("pairs.yield", nextKey, value)
            end
            return nextKey, value
        end, state, initial
    end
end

if os and type(os.time) == "function" then
    local raw_time = os.time
    os.time = function(...)
        local result = raw_time(...)
        __wd_log("os.time", "args", ..., "returns", result)
        return result
    end
end

if coroutine then
    if type(coroutine.create) == "function" then
        local raw_create = coroutine.create
        coroutine.create = function(...)
            local thread = raw_create(...)
            __wd_log("coroutine.create", "args", ..., "returns", thread)
            return thread
        end
    end
    if type(coroutine.resume) == "function" then
        local raw_resume = coroutine.resume
        coroutine.resume = function(...)
            local results = __wd_pack(raw_resume(...))
            __wd_log("coroutine.resume", "args", ..., "returns", table.unpack(results, 1, results.n))
            return table.unpack(results, 1, results.n)
        end
    end
    if type(coroutine.status) == "function" then
        local raw_status = coroutine.status
        coroutine.status = function(...)
            local result = raw_status(...)
            __wd_log("coroutine.status", "args", ..., "returns", result)
            return result
        end
    end
end

if Vector3 and type(Vector3.new) == "function" then
    local raw_vector3_new = Vector3.new
    Vector3.new = function(...)
        local result = raw_vector3_new(...)
        __wd_log("Vector3.new", "args", ..., "returns", result)
        return result
    end
end

if Instance and type(Instance.new) == "function" then
    local raw_instance_new = Instance.new
    Instance.new = function(...)
        local result = raw_instance_new(...)
        local mt = getmetatable(result)
        if type(mt) == "table" and type(mt.__newindex) == "function" and not mt.__wd_trace_newindex then
            local raw_newindex = mt.__newindex
            mt.__wd_trace_newindex = true
            mt.__newindex = function(self, key, value)
                __wd_log("Instance.__newindex", self, key, value)
                return raw_newindex(self, key, value)
            end
        end
        if type(result) == "table" and type(result.Destroy) == "function" and not rawget(result, "__wd_trace_destroy") then
            local raw_destroy = result.Destroy
            rawset(result, "__wd_trace_destroy", true)
            result.Destroy = function(self, ...)
                local results = __wd_pack(raw_destroy(self, ...))
                __wd_log("Instance.Destroy", "args", self, ..., "returns", table.unpack(results, 1, results.n))
                return table.unpack(results, 1, results.n)
            end
        end
        __wd_log("Instance.new", "args", ..., "returns", result)
        return result
    end
end

if game and type(game.GetService) == "function" then
    local raw_get_service = game.GetService
    game.GetService = function(self, ...)
        local results = __wd_pack(raw_get_service(self, ...))
        __wd_log("game.GetService", "args", ..., "returns", table.unpack(results, 1, results.n))
        return table.unpack(results, 1, results.n)
    end
end

if type(delay) == "function" then
    local raw_delay = delay
    delay = function(...)
        local results = __wd_pack(raw_delay(...))
        __wd_log("delay", "args", ..., "returns", table.unpack(results, 1, results.n))
        return table.unpack(results, 1, results.n)
    end
end

if task and type(task.delay) == "function" then
    local raw_task_delay = task.delay
    task.delay = function(...)
        local results = __wd_pack(raw_task_delay(...))
        __wd_log("task.delay", "args", ..., "returns", table.unpack(results, 1, results.n))
        return table.unpack(results, 1, results.n)
    end
end

local function __wd_wrap_connect(signal, label)
    if type(signal) ~= "table" or type(signal.Connect) ~= "function" then
        return
    end
    local raw_connect = signal.Connect
    signal.Connect = function(...)
        local results = __wd_pack(raw_connect(...))
        __wd_log(label .. ".Connect", "args", ..., "returns", table.unpack(results, 1, results.n))
        return table.unpack(results, 1, results.n)
    end
end

local __wd_runservice = nil
if game and type(game.GetService) == "function" then
    pcall(function()
        __wd_runservice = game:GetService("RunService")
    end)
end
if __wd_runservice then
    __wd_wrap_connect(__wd_runservice.Heartbeat, "RunService.Heartbeat")
end
'''


EPILOGUE = r'''
__WD_POST_WAIT__
if __rbx_capture_text then
    __rbx_capture_text("wearedevs_runtime_trace", __wd_raw_table_concat(__wd_trace, "\n"), ".jsonl")
end
return __wd_result
'''


def build_harness(source: str, post_wait: float = 0) -> str:
    wait_snippet = ""
    if post_wait > 0:
        wait_snippet = f"\nif task and type(task.wait) == 'function' then task.wait({post_wait!r}) end\n"
    epilogue = EPILOGUE.replace("__WD_POST_WAIT__", wait_snippet)
    return PRELUDE + "\nlocal __wd_result = (function(...)\n" + source + "\nend)()\n" + epilogue


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--runtime", type=Path, default=Path("outputs/rbx_luau_runtime_macos_arm64"))
    parser.add_argument("--work-dir", type=Path, default=Path("work/wearedevs2-traceback"))
    parser.add_argument("--harness", type=Path, default=Path("work/wearedevs2_trace_harness.lua"))
    parser.add_argument("--post-wait", type=float, default=0)
    args = parser.parse_args()

    source = args.input.read_text()
    args.harness.parent.mkdir(parents=True, exist_ok=True)
    args.harness.write_text(build_harness(source, args.post_wait))
    args.work_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(args.runtime),
        "--profile",
        "executor-client",
        "--network-policy",
        "offline",
        "--timeout",
        "10",
        "--capture-min",
        "1",
        "--no-normalize-pcall-errors",
        "--no-capture-string-hooks",
        "--out",
        str(args.work_dir),
        str(args.harness),
    ]
    run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    trace_files = sorted(args.work_dir.glob("wearedevs_runtime_trace_*.jsonl"))
    report = {
        "command": " ".join(shlex.quote(part) for part in cmd),
        "exit_code": run.returncode,
        "stdout": run.stdout.splitlines(),
        "harness": str(args.harness),
        "trace": str(trace_files[-1]) if trace_files else None,
    }
    print(json.dumps(report, indent=2))
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
