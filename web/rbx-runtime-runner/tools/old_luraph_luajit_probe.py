#!/usr/bin/env python3
"""Probe old Lua/Luraph wrappers with LuaJIT.

Some older Luraph builds use Lua 5.x `goto` flattening plus 5.1-era globals
(`setfenv`, `getfenv`, `unpack`, `bit`).  The Luau runtime cannot parse these
wrappers, so this helper runs them under LuaJIT in a restricted environment and
captures decoded strings, loadstring inputs, returns, function bytecode dumps,
and upvalue snapshots.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


LUA_HARNESS = r'''
local target = assert(arg[1], "target path missing")
local outdir = assert(arg[2], "output dir missing")
local capture_min = tonumber(arg[3]) or 64
local call_functions = arg[4] == "1"

local counter = 0
local seen = {}

local function json_escape(s)
    s = tostring(s)
    s = s:gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
    return '"' .. s .. '"'
end

local function sanitize(kind)
    return (tostring(kind):gsub("[^%w_.-]", "_"))
end

local function has_source_shape(s)
    local h = s:sub(1, 4096)
    return h:find("local%s+") or h:find("function%s*[%w_(]") or h:find("return%s+") or h:find("game%s*[:.]") or h:find("loadstring%s*%(")
end

local function is_binary_like(s)
    if s:find("%z") then return true end
    local sample = s:sub(1, math.min(#s, 4096))
    local odd = 0
    for i = 1, #sample do
        local b = sample:byte(i)
        if b < 9 or (b > 13 and b < 32) or b > 126 then
            odd = odd + 1
        end
    end
    return #sample > 0 and odd / #sample > 0.08
end

local function extension_for(s, fallback)
    if fallback then return fallback end
    if is_binary_like(s) then return ".bin" end
    if has_source_shape(s) then return ".lua" end
    return ".txt"
end

local function write_file(path, data)
    local f, err = io.open(path, "wb")
    if not f then error(err, 0) end
    f:write(data)
    f:close()
end

local function capture(kind, value, ext, force)
    local data = tostring(value)
    if not force and #data < capture_min then return nil end
    local key = kind .. "\0" .. data
    if seen[key] then return seen[key] end
    counter = counter + 1
    kind = sanitize(kind)
    ext = extension_for(data, ext)
    local path = string.format("%s/%s_%04d%s", outdir, kind, counter, ext)
    write_file(path, data)
    local idx = assert(io.open(outdir .. "/capture_index.jsonl", "ab"))
    idx:write('{"kind":', json_escape(kind), ',"bytes":', tostring(#data), ',"path":', json_escape(path), '}\n')
    idx:close()
    print(string.format("[capture] %s: %d bytes -> %s", kind, #data, path))
    seen[key] = path
    return path
end

local function capture_error(kind, value)
    capture(kind, tostring(value), ".txt", true)
end

local base_loadstring = loadstring
local base_loadfile = loadfile
local base_setfenv = setfenv
local base_getfenv = getfenv
local base_unpack = unpack
local base_pcall = pcall
local base_xpcall = xpcall
local base_tostring = tostring
local base_type = type
local base_pairs = pairs
local base_ipairs = ipairs
local base_next = next
local base_select = select
local base_print = print
local orig_string = string
local orig_table = table
local orig_math = math
local orig_bit = bit
local orig_debug = debug

local env = {}
env._G = env
env._VERSION = _VERSION
env.assert = assert
env.error = error
env.pcall = base_pcall
env.xpcall = base_xpcall
env.tostring = base_tostring
env.tonumber = tonumber
env.type = base_type
env.select = base_select
env.next = base_next
env.pairs = base_pairs
env.ipairs = base_ipairs
env.unpack = base_unpack
env.print = function(...)
    local parts = {}
    for i = 1, base_select("#", ...) do
        parts[#parts + 1] = base_tostring(base_select(i, ...))
    end
    capture("stdout", table.concat(parts, "\t"), ".txt", true)
    return base_print(...)
end
env.rawequal = rawequal
env.rawget = rawget
env.rawset = rawset
env.setmetatable = setmetatable
env.getmetatable = getmetatable
env.collectgarbage = collectgarbage
env.coroutine = coroutine
env.math = orig_math
env.bit = orig_bit

local string_proxy = {}
for k, v in base_pairs(orig_string) do string_proxy[k] = v end
local table_proxy = {}
for k, v in base_pairs(orig_table) do table_proxy[k] = v end
env.string = string_proxy
env.table = table_proxy

local function wrap_string_return(kind, fn)
    return function(...)
        local r = {fn(...)}
        r.n = base_select("#", ...)
        for i = 1, base_select("#", unpack(r)) do
            if base_type(r[i]) == "string" then
                capture(kind .. "_return_" .. tostring(i), r[i])
            end
        end
        return base_unpack(r, 1, table.maxn(r))
    end
end

string_proxy.char = function(...)
    local s = orig_string.char(...)
    capture("string_char_return", s)
    return s
end
string_proxy.gsub = function(...)
    local a, b = orig_string.gsub(...)
    if base_type(a) == "string" then capture("string_gsub_return", a) end
    return a, b
end
string_proxy.sub = function(...)
    local s = orig_string.sub(...)
    capture("string_sub_return", s)
    return s
end
string_proxy.reverse = function(...)
    local s = orig_string.reverse(...)
    capture("string_reverse_return", s)
    return s
end
table_proxy.concat = function(...)
    local s = orig_table.concat(...)
    capture("table_concat_return", s)
    return s
end

local function snapshot_value(value, label, depth, visited)
    local tv = base_type(value)
    if tv == "string" then
        capture(label, value)
        return
    end
    if tv == "function" then
        local ok, dumped = base_pcall(string.dump, value)
        if ok and base_type(dumped) == "string" then
            capture(label .. "_luajit_bytecode", dumped, ".luajitbc", true)
        else
            capture_error(label .. "_dump_error", dumped)
        end
        if depth <= 0 or not orig_debug then return end
        for i = 1, 80 do
            local name, uv = orig_debug.getupvalue(value, i)
            if not name then break end
            capture(label .. "_upvalue_" .. tostring(i) .. "_name", name, ".txt", true)
            snapshot_value(uv, label .. "_upvalue_" .. tostring(i) .. "_" .. sanitize(name), depth - 1, visited)
        end
        return
    end
    if tv == "table" then
        if visited[value] or depth <= 0 then return end
        visited[value] = true
        local count = 0
        for k, v in base_pairs(value) do
            count = count + 1
            if count > 256 then break end
            local child = label .. "_table_" .. sanitize(base_tostring(k))
            snapshot_value(k, child .. "_key", depth - 1, visited)
            snapshot_value(v, child .. "_value", depth - 1, visited)
        end
    end
end

env.loadstring = function(code, chunkname)
    if base_type(code) == "string" then
        capture("loadstring_input", code, nil, true)
    end
    local fn, err = base_loadstring(code, chunkname)
    if not fn then
        capture_error("loadstring_error", err)
        return nil, err
    end
    base_setfenv(fn, env)
    snapshot_value(fn, "loadstring_function", 2, {})
    return function(...)
        local results = {base_xpcall(function(...) return fn(...) end, function(err)
            if orig_debug and orig_debug.traceback then
                return orig_debug.traceback(err, 2)
            end
            return err
        end, ...)}
        local ok = results[1]
        if not ok then
            capture_error("loadstring_runtime_error", results[2])
            error(results[2], 0)
        end
        for i = 2, table.maxn(results) do
            snapshot_value(results[i], "loadstring_return_" .. tostring(i - 1), 3, {})
        end
        return base_unpack(results, 2, table.maxn(results))
    end
end
env.load = env.loadstring
env.getfenv = function(x)
    if base_type(x) == "number" then x = x + 1 end
    local ok, result = base_pcall(base_getfenv, x or 2)
    if ok and base_type(result) == "table" then return result end
    return env
end
env.setfenv = function(fn, newenv)
    if newenv == nil then newenv = env end
    if base_type(fn) == "number" then fn = fn + 1 end
    return base_setfenv(fn, newenv)
end

local signal = {Connect = function() return {Disconnect = function() end} end, Wait = function() return nil end}
local function noop() end
local game = {}
game.PlaceId = 0
game.JobId = "old-luraph-probe"
game.GameId = 0
game.IsLoaded = true
function game:GetService(name)
    if name == "HttpService" then
        return {
            JSONEncode = function(_, x) return base_tostring(x) end,
            JSONDecode = function() return {} end,
            GetAsync = function(_, url) capture("http_get_blocked", url, ".txt", true); return "" end,
            PostAsync = function(_, url, body) capture("http_post_blocked", url .. "\n" .. base_tostring(body), ".txt", true); return "" end,
        }
    end
    if name == "Players" then
        return {LocalPlayer = {Name = "Player", UserId = 123456, CharacterAdded = signal, PlayerGui = {}}, GetPlayers = function(self) return {self.LocalPlayer} end}
    end
    if name == "RunService" then
        return {Heartbeat = signal, RenderStepped = signal, Stepped = signal, IsClient = function() return true end, IsServer = function() return false end, IsStudio = function() return false end}
    end
    return {Name = name, ClassName = name, Changed = signal, FindFirstChild = function() return nil end, WaitForChild = function() return nil end}
end
function game:HttpGet(url) capture("httpget_blocked", url, ".txt", true); return "" end
function game:HttpGetAsync(url) return self:HttpGet(url) end
env.game = game
env.workspace = {Name = "Workspace", ClassName = "Workspace"}
env.Workspace = env.workspace
env.Enum = setmetatable({}, {__index = function(t, k) local v = {}; rawset(t, k, v); return v end})
env.Instance = {new = function(className) return {ClassName = className, Name = className, Changed = signal, Destroy = noop} end}
env.task = {wait = function() return 0 end, spawn = function(f, ...) return coroutine.wrap(f)(...) end, defer = function(f, ...) return coroutine.wrap(f)(...) end, delay = function(_, f, ...) return coroutine.wrap(f)(...) end}
env.wait = env.task.wait
env.spawn = env.task.spawn
env.delay = env.task.delay
env.tick = function() return 0 end
env.time = function() return 0 end
env.typeof = base_type
env.getgenv = function() return env end
env.getrenv = function() return env end

local chunk, err = base_loadfile(target)
if not chunk then
    capture_error("main_compile_error", err)
    os.exit(2)
end
base_setfenv(chunk, env)
snapshot_value(chunk, "main_function", 2, {})
local results = {base_xpcall(chunk, function(err)
    if orig_debug and orig_debug.traceback then
        return orig_debug.traceback(err, 2)
    end
    return err
end)}
local ok = results[1]
if not ok then
    capture_error("main_runtime_error", results[2])
    os.exit(1)
end
for i = 2, table.maxn(results) do
    snapshot_value(results[i], "main_return_" .. tostring(i - 1), 4, {})
end
if call_functions then
    for i = 2, table.maxn(results) do
        if base_type(results[i]) == "function" then
            local called = {base_xpcall(results[i], function(err)
                if orig_debug and orig_debug.traceback then
                    return orig_debug.traceback(err, 2)
                end
                return err
            end)}
            if called[1] then
                for j = 2, table.maxn(called) do
                    snapshot_value(called[j], "called_main_return_" .. tostring(i - 1) .. "_" .. tostring(j - 1), 4, {})
                end
            else
                capture_error("called_main_return_error_" .. tostring(i - 1), called[2])
            end
        end
    end
end
'''


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def lua_unescape_short_string_body(body: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(body):
            out.append("\\")
            break
        esc = body[i]
        if esc.isdigit():
            digits = [esc]
            j = i + 1
            while j < len(body) and len(digits) < 3 and body[j].isdigit():
                digits.append(body[j])
                j += 1
            out.append(chr(int("".join(digits)) % 256))
            i = j
            continue
        if esc == "x" and i + 2 < len(body):
            hx = body[i + 1 : i + 3]
            if re.fullmatch(r"[0-9A-Fa-f]{2}", hx):
                out.append(chr(int(hx, 16)))
                i += 3
                continue
        if esc == "z":
            i += 1
            while i < len(body) and body[i].isspace():
                i += 1
            continue
        simple = {
            "a": "\a",
            "b": "\b",
            "f": "\f",
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "v": "\v",
            "\\": "\\",
            '"': '"',
            "'": "'",
        }
        out.append(simple.get(esc, esc))
        i += 1
    return "".join(out)


def find_lph_v14_literal(source: str) -> tuple[str, tuple[int, int]] | None:
    match = re.search(r'n\("((?:LPH[-@])(?:\\.|[^"\\])*)",0X5\)', source, re.S)
    if not match:
        return None
    return match.group(1), (match.start(1), match.end(1))


class LuraphV14Parser:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise EOFError(self.pos)
        value = self.data[self.pos]
        self.pos += 1
        return value

    def read_u32_le(self) -> int:
        if self.pos + 4 > len(self.data):
            raise EOFError(self.pos)
        value = int.from_bytes(self.data[self.pos : self.pos + 4], "little", signed=False)
        self.pos += 4
        return value

    def read_i64ish(self) -> int:
        lo = self.read_u32_le()
        hi = self.read_u32_le()
        if hi == 0:
            return lo
        if hi >= 0x80000000:
            hi -= 0x100000000
        return hi * 0x100000000 + lo

    def read_float64_custom(self) -> float:
        lo = self.read_u32_le()
        hi = self.read_u32_le()
        sign = -1.0 if ((hi >> 31) & 1) else 1.0
        exp = (hi >> 20) & 0x7FF
        frac = ((hi & 0xFFFFF) << 32) | lo
        if exp == 0:
            if frac == 0:
                return -0.0 if sign < 0 else 0.0
            return sign * (2 ** (1 - 1023)) * (frac / (2**52))
        if exp == 2047:
            return sign * (math.inf if frac == 0 else math.nan)
        return sign * (2 ** (exp - 1023)) * (frac / (2**52) + 1)

    def read_varint(self) -> int:
        value = 0
        scale = 1
        while True:
            byte = self.read_byte()
            value += (byte - 0x80 if byte > 0x7F else byte) * scale
            scale *= 0x80
            if byte < 0x80:
                return value

    def read_adjusted_number(self) -> int:
        value = self.read_varint()
        return value - 9007199254740992 if value >= 4503599627370496 else value

    def read_string(self) -> bytes:
        size = self.read_varint()
        if self.pos + size > len(self.data):
            raise EOFError(self.pos)
        value = self.data[self.pos : self.pos + size]
        self.pos += size
        return value

    def parse_constant_value(self) -> dict:
        tag = self.read_byte()
        if tag <= 104:
            if tag >= 104:
                return {"tag": tag, "type": "integer", "value": self.read_i64ish()}
            data = self.read_string()
            return {
                "tag": tag,
                "type": "string",
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "text_preview": data.decode("utf-8", "replace")[:1000],
                "hex_preview": data[:96].hex(),
            }
        if tag <= 195:
            return {"tag": tag, "type": "boolean", "value": self.read_byte() == 1}
        if tag < 244:
            value = self.read_float64_custom()
            if math.isnan(value) or math.isinf(value):
                encoded: object = str(value)
            else:
                encoded = value
            return {"tag": tag, "type": "float", "value": encoded}
        return {"tag": tag, "type": "nil", "value": None}

    def parse_proto(self) -> dict:
        proto: dict[str, object] = {
            "start_offset": self.pos,
            "header4": self.read_varint(),
            "header5": self.read_varint(),
        }
        ins_count = self.read_varint() - 0xF592
        instructions = []
        for _ in range(ins_count):
            raw_a = self.read_adjusted_number()
            opcode = self.read_adjusted_number()
            raw_c = self.read_adjusted_number()
            raw_b = self.read_adjusted_number()
            k = raw_b % 4
            o = raw_a % 4
            c = raw_c % 4
            instructions.append(
                {
                    "op": opcode,
                    "a": (raw_c - c) // 4,
                    "b": (raw_b - k) // 4,
                    "c": (raw_a - o) // 4,
                    "mode_b": k,
                    "mode_c": o,
                    "mode_a": c,
                }
            )
        captures = []
        for _ in range(self.read_varint()):
            raw = self.read_varint()
            captures.append({"kind": raw % 4, "index": raw // 4})
        proto["instruction_count"] = len(instructions)
        proto["capture_count"] = len(captures)
        proto["instructions_preview"] = instructions[:128]
        proto["captures_preview"] = captures[:128]
        proto["end_offset"] = self.pos
        return proto

    def parse_chunk(self) -> dict:
        constants_count = self.read_varint() - 0x7B74
        has_debug_names = self.read_byte() != 0
        constants = []
        for seq in range(constants_count):
            item = self.parse_constant_value()
            item["seq"] = seq
            constants.append(item)
        proto_count = self.read_varint() - 0x13F3E
        protos = [self.parse_proto() for _ in range(proto_count)]
        root_index = self.read_varint() if self.pos < len(self.data) else None
        op_hist: dict[str, int] = {}
        for proto in protos:
            for instr in proto.get("instructions_preview", []):
                # The preview is enough for a compact first-pass report; counts
                # are marked preview in the output.
                key = str(instr["op"])
                op_hist[key] = op_hist.get(key, 0) + 1
        source_like = []
        for item in constants:
            if item.get("type") != "string":
                continue
            text = str(item.get("text_preview", ""))
            if any(token in text for token in ("local ", "function", "return ", "loadstring", "game:", "HttpGet", "--[[")):
                source_like.append(
                    {
                        "seq": item["seq"],
                        "bytes": item.get("bytes"),
                        "sha256": item.get("sha256"),
                        "text_preview": text[:500],
                    }
                )
        return {
            "constants_count": constants_count,
            "has_debug_names": has_debug_names,
            "constants": constants,
            "source_like_constants": source_like,
            "proto_count": proto_count,
            "protos": protos,
            "root_index": root_index,
            "cursor_after_first_chunk": self.pos,
            "remaining_bytes": len(self.data) - self.pos,
            "remaining_sha256": sha256_bytes(self.data[self.pos :]) if self.pos < len(self.data) else None,
            "opcode_histogram_preview_only": op_hist,
        }


def decode_lph_v14_static(input_path: Path, out_dir: Path) -> dict:
    source = input_path.read_text(errors="replace")
    found = find_lph_v14_literal(source)
    if not found:
        return {"status": "not_found"}
    raw_literal, span = found
    evaluated = lua_unescape_short_string_body(raw_literal)
    if not evaluated.startswith(("LPH-", "LPH@")):
        return {"status": "invalid_marker", "marker": evaluated[:4]}

    marker = evaluated[:4]
    ascii85_body = evaluated[4:]
    if marker == "LPH-":
        decoded = base64.a85decode(ascii85_body, adobe=False)
        decode_kind = "standard_ascii85_lph_dash"
    else:
        # This helper is for old wrappers; keep LPH@ visible in the report but
        # do not pretend to handle the newer Luau-buffer word order here.
        return {"status": "unsupported_marker_for_legacy_probe", "marker": marker}

    packed_path = out_dir / "luraph_v14_packed_blob.txt"
    ascii_path = out_dir / "luraph_v14_ascii85_body.txt"
    decoded_path = out_dir / "luraph_v14_decoded_payload.bin"
    strings_path = out_dir / "luraph_v14_decoded_strings.txt"
    parse_path = out_dir / "luraph_v14_unpacked_state.json"
    packed_path.write_text(evaluated)
    ascii_path.write_text(ascii85_body)
    decoded_path.write_bytes(decoded)

    strings = []
    for match in re.finditer(rb"[\x09\x0a\x0d\x20-\x7e]{4,}", decoded):
        text = match.group(0).decode("utf-8", "replace")
        strings.append({"offset": match.start(), "bytes": len(match.group(0)), "text": text[:1000]})
    strings_path.write_text("\n".join(f"{row['offset']:08x} {row['bytes']:5d} {row['text']}" for row in strings) + "\n")

    parse_status: dict[str, object]
    try:
        parse_status = LuraphV14Parser(decoded).parse_chunk()
        parse_status["status"] = "parsed_first_chunk"
    except Exception as exc:
        parse_status = {"status": "parse_failed", "error": repr(exc)}
    parse_path.write_text(json.dumps(parse_status, indent=2))

    return {
        "status": "decoded",
        "decode_kind": decode_kind,
        "marker": marker,
        "source_span": [span[0], span[1] - 1],
        "raw_literal_bytes": len(raw_literal),
        "evaluated_payload_bytes": len(evaluated),
        "ascii85_body_bytes": len(ascii85_body),
        "ascii85_z_count": ascii85_body.count("z"),
        "expanded_ascii85_bytes": len(ascii85_body) + ascii85_body.count("z") * 4,
        "decoded_bytes": len(decoded),
        "decoded_sha256": sha256_bytes(decoded),
        "packed_blob": str(packed_path),
        "ascii85_body": str(ascii_path),
        "decoded_payload": str(decoded_path),
        "decoded_strings": str(strings_path),
        "unpacked_state": str(parse_path),
        "unpacked_status": parse_status.get("status"),
        "constants_count": parse_status.get("constants_count"),
        "proto_count": parse_status.get("proto_count"),
        "root_index": parse_status.get("root_index"),
        "remaining_bytes": parse_status.get("remaining_bytes"),
        "source_like_constants": parse_status.get("source_like_constants", [])[:25],
    }


def run_probe(input_path: Path, out_dir: Path, capture_min: int, timeout: float, call_functions: bool) -> dict:
    input_path = input_path.expanduser().resolve()
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    static_decode = decode_lph_v14_static(input_path, out_dir)
    harness = out_dir / "old_luraph_luajit_harness.lua"
    harness.write_text(LUA_HARNESS)
    luajit = shutil.which("luajit")
    if not luajit:
        raise RuntimeError("luajit not found")
    cmd = [luajit, str(harness), str(input_path), str(out_dir), str(capture_min), "1" if call_functions else "0"]
    started = time.time()
    try:
        run = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        run = subprocess.CompletedProcess(cmd, 124, exc.stdout or "")
        timed_out = True
    log_path = out_dir / "run.log"
    log_path.write_text(run.stdout or "")
    captures = []
    index = out_dir / "capture_index.jsonl"
    if index.exists():
        for line in index.read_text(errors="replace").splitlines():
            try:
                captures.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    existing = []
    for row in captures:
        path = Path(str(row.get("path", "")))
        if path.exists():
            existing.append({**row, "sha256": sha256_path(path)})
    largest = sorted(existing, key=lambda x: int(x.get("bytes", 0)), reverse=True)[:20]
    source_like = []
    for row in existing:
        path = Path(str(row["path"]))
        if path.suffix in {".lua", ".txt"}:
            text = path.read_text(errors="replace")
            head = text[:4096]
            if any(token in head for token in ("local ", "function", "return ", "game:", "loadstring")):
                source_like.append(row)
    report = {
        "input": str(input_path),
        "input_sha256": sha256_path(input_path),
        "output_dir": str(out_dir),
        "command": cmd,
        "exit_code": run.returncode,
        "status": (
            "decoded_static_runtime_ok"
            if run.returncode == 0 and static_decode.get("status") == "decoded"
            else "decoded_static_runtime_blocked"
            if static_decode.get("status") == "decoded"
            else "runtime_only"
        ),
        "static_decode": static_decode,
        "timed_out": timed_out,
        "elapsed_seconds": round(time.time() - started, 3),
        "capture_count": len(existing),
        "largest_captures": largest,
        "source_like_captures": source_like[:50],
        "log": str(log_path),
    }
    report_path = out_dir / "old_luraph_luajit_probe_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Probe old Luraph Lua wrappers with LuaJIT")
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "work" / "old-luraph-luajit-probe")
    parser.add_argument("--capture-min", type=int, default=64)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--call-functions", action="store_true", help="pcall function values returned by the wrapper")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = run_probe(args.input, args.out, args.capture_min, args.timeout, args.call_functions)
    print(f"Exit code: {report['exit_code']}")
    print(f"Status: {report['status']}")
    static_decode = report.get("static_decode", {})
    if static_decode.get("status") == "decoded":
        print(f"Decoded payload: {static_decode['decoded_payload']}")
        print(f"Decoded bytes: {static_decode['decoded_bytes']} sha256={static_decode['decoded_sha256']}")
        print(f"Unpacked state: {static_decode['unpacked_state']}")
    print(f"Timed out: {report['timed_out']}")
    print(f"Captures: {report['capture_count']}")
    print(f"Report: {Path(report['output_dir']) / 'old_luraph_luajit_probe_report.json'}")
    if report["largest_captures"]:
        print("Largest captures:")
        for row in report["largest_captures"][:8]:
            print(f"  {row['bytes']:>8} {row['kind']} {row['path']}")
    return 0 if report["exit_code"] == 0 or report.get("static_decode", {}).get("status") == "decoded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
