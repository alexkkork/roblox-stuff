#!/usr/bin/env python3
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


MOONVEIL_A85_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
VM_FIELD_ALIASES = {
    "10389": "f_0x2895",
    "25137": "f_0x6231",
    "15394": "f_0x3c22",
    "50066": "f_0xc392",
    "46251": "f_0xb4ab",
    "54140": "f_0xd37c",
    "41102": "f_0xa08e",
    "36629": "f_0x8f15",
    "6731": "f_0x1a4b",
    "45043": "f_0xaff3",
    "51755": "f_0xca2b",
}
VM_FIELD_KEYS = set(VM_FIELD_ALIASES)


def parse_pc_jump(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"\s*(0x[0-9a-fA-F]+|\d+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*", value)
    if not match:
        raise argparse.ArgumentTypeError("expected FROM=TO, for example 224=225")
    return int(match.group(1), 0), int(match.group(2), 0)


def patch_table_source_for_vm_trace(table_source: str, trace_dispatch: bool = False, trace_registers: int = 24, trace_limit: int = 2400, empty_proto_returns: bool = False, snapshot_calls: bool = True, snapshot_min_trace: int = 0, capture_vm_strings: bool = False, capture_vm_string_min: int = 1, empty_proto_explore: bool = False, brutecall_return_frame: bool = False, brutecall_min_trace: int = 0, force_pc_jumps: list[tuple[int, int]] | None = None) -> str:
    op48 = 'q,n,p=l[0xa08e],o-p,c[0b1000][0b10][c[0b1000][1]]o=p[q]d[n]=o'
    op48_traced = r'''q,n,p=l[0xa08e],o-p,c[0b1000][0b10][c[0b1000][1]] if type(__rbx_capture_text)=="function" then local __mv_lines={"pc="..tostring(j),"dst="..tostring(n),"key="..tostring(q),"pool_type="..type(p),"pool="..tostring(p)} if type(p)=="table" then local __mv_c=0 for __mv_k,__mv_v in pairs(p) do __mv_c=__mv_c+1 if __mv_c<=40 then __mv_lines[#__mv_lines+1]="pool["..tostring(__mv_k).."]="..type(__mv_v)..":"..tostring(__mv_v) end end __mv_lines[#__mv_lines+1]="pool_count_seen="..tostring(__mv_c) end local __mv_o=p[q] __mv_lines[#__mv_lines+1]="result_type="..type(__mv_o) __mv_lines[#__mv_lines+1]="result="..tostring(__mv_o) __rbx_capture_text("moonveil_op48_lookup", table.concat(__mv_lines,"\n"), ".txt") end o=p[q]d[n]=o'''
    if op48 not in table_source:
        raise ValueError("MoonVeil opcode-48 lookup pattern was not found for tracing")
    table_source = table_source.replace(op48, op48_traced, 1)

    if trace_dispatch:
        dispatch = 'l=g[j]n,m=1,l[0x3c22]j,n=j+n,0x92 b=m<n and 0b1111 or b+-0b100000'
        force_pc_entries = ""
        force_pc_block = ""
        if force_pc_jumps:
            force_pc_entries = ",".join(f"[{int(src)}]={int(dst)}" for src, dst in force_pc_jumps)
            force_pc_block = r'''
local __mv_force_jumps={__FORCE_PC_ENTRIES__}
local __mv_force_to=__mv_force_jumps[tonumber(j)]
if __mv_force_to~=nil then
    if type(__rbx_capture_text)=="function" then
        local function __mv_force_desc(__mv_v)
            local __mv_t=type(__mv_v)
            if __mv_t=="table" then
                local __mv_seen=0
                local __mv_parts={}
                for __mv_k,__mv_x in pairs(__mv_v) do
                    __mv_seen=__mv_seen+1
                    if __mv_seen<=8 then
                        __mv_parts[#__mv_parts+1]=tostring(__mv_k)..":"..type(__mv_x)..":"..tostring(__mv_x)
                    end
                end
                return "table(ptr="..tostring(__mv_v)..",len="..tostring(#__mv_v)..",seen="..tostring(__mv_seen).."):"..table.concat(__mv_parts,",")
            elseif __mv_t=="function" then
                return "function:"..tostring(__mv_v)
            elseif __mv_t=="string" then
                __rbx_capture_text("moonveil_forced_pc_string_pc"..tostring(j), __mv_v, ".bin")
                return "string(len="..tostring(#__mv_v).."):"..tostring(__mv_v)
            end
            return __mv_t..":"..tostring(__mv_v)
        end
        local __mv_lines={
            "trace="..tostring(__mv_dispatch_trace_count),
            "from_pc="..tostring(j),
            "to_pc="..tostring(__mv_force_to),
            "program_len="..tostring(type(g)=="table" and #g or -1),
            "before_row="..__mv_force_desc(l),
            "before_op="..tostring(type(l)=="table" and l[0x3c22] or nil)
        }
        if type(d)=="table" then
            for __mv_i=1,__TRACE_REGISTERS__ do
                local __mv_v=d[__mv_i]
                if __mv_v~=nil then
                    __mv_lines[#__mv_lines+1]="before_r"..tostring(__mv_i).."="..__mv_force_desc(__mv_v)
                end
            end
        end
        local __mv_after=type(g)=="table" and g[__mv_force_to] or nil
        __mv_lines[#__mv_lines+1]="after_row="..__mv_force_desc(__mv_after)
        __mv_lines[#__mv_lines+1]="after_op="..tostring(type(__mv_after)=="table" and __mv_after[0x3c22] or nil)
        __rbx_capture_text("moonveil_forced_pc_jump", table.concat(__mv_lines,"\n"), ".txt")
    end
    j=__mv_force_to
    l=g[j]
end
'''.replace("__FORCE_PC_ENTRIES__", force_pc_entries)
        dispatch_traced = r'''
l=g[j]
__FORCE_PC_BLOCK__
if (__EMPTY_PROTO_RETURNS__ or __EMPTY_PROTO_EXPLORE__) and l==nil and type(g)=="table" and #g==0 then
    if type(__rbx_capture_text)=="function" then
        local __mv_lines={"trace="..tostring(__mv_dispatch_trace_count),"pc="..tostring(j),"program_ptr="..tostring(g),"program_len="..tostring(#g)}
        local function __mv_seen_count(__mv_tbl)
            local __mv_c=0
            if type(__mv_tbl)=="table" then
                for _ in pairs(__mv_tbl) do __mv_c=__mv_c+1 end
            end
            return __mv_c
        end
        local function __mv_brief(__mv_v)
            local __mv_t=type(__mv_v)
            if __mv_t=="table" then
                return "table(ptr="..tostring(__mv_v)..",len="..tostring(#__mv_v)..",seen="..tostring(__mv_seen_count(__mv_v))..")"
            elseif __mv_t=="function" then
                return "function:"..tostring(__mv_v)
            elseif __mv_t=="string" then
                return "string(len="..tostring(#__mv_v).."):"..tostring(__mv_v)
            end
            return __mv_t..":"..tostring(__mv_v)
        end
        if type(e)=="table" then
            __mv_lines[#__mv_lines+1]="upvalue_table="..__mv_brief(e)
            for __mv_i=1,12 do
                if e[__mv_i]~=nil then
                    __mv_lines[#__mv_lines+1]="u"..tostring(__mv_i).."="..__mv_brief(e[__mv_i])
                end
            end
        end
        local __mv_protos=type(e)=="table" and type(e[2])=="table" and type(e[2][0x7807])=="table" and e[2][0x7807] or nil
        if type(__mv_protos)=="table" then
            __mv_lines[#__mv_lines+1]="sibling_proto_table="..__mv_brief(__mv_protos)
            local __mv_seen=0
            for __mv_k,__mv_proto in pairs(__mv_protos) do
                __mv_seen=__mv_seen+1
                if __mv_seen<=80 then
                    __mv_lines[#__mv_lines+1]="proto["..tostring(__mv_k).."]="..__mv_brief(__mv_proto)
                end
            end
            __mv_lines[#__mv_lines+1]="sibling_proto_seen="..tostring(__mv_seen)
        end
        __rbx_capture_text("moonveil_empty_proto_return", table.concat(__mv_lines,"\n"), ".txt")
    end
    if __EMPTY_PROTO_RETURNS__ then
        return nil
    end
end
if type(__rbx_capture_text)=="function" then
    __mv_dispatch_trace_count=(__mv_dispatch_trace_count or 0)+1
    if __mv_dispatch_trace_count<=__TRACE_LIMIT__ then
        local function __mv_count(__mv_tbl)
            local __mv_c=0
            if type(__mv_tbl)=="table" then
                for _ in pairs(__mv_tbl) do __mv_c=__mv_c+1 end
            end
            return __mv_c
        end
        local function __mv_safe_label(__mv_label)
            __mv_label=tostring(__mv_label or "string"):gsub("[^%w_]+","_")
            if #__mv_label>96 then
                __mv_label=__mv_label:sub(1,96)
            end
            return __mv_label
        end
        local function __mv_capture_string(__mv_label,__mv_v)
            if __CAPTURE_VM_STRINGS__ and type(__mv_v)=="string" and #__mv_v>=__CAPTURE_VM_STRING_MIN__ and type(__rbx_capture_text)=="function" then
                __rbx_capture_text("moonveil_vm_string_"..__mv_safe_label(__mv_label), __mv_v, ".bin")
            end
        end
        local function __mv_desc(__mv_v,__mv_label)
            local __mv_t=type(__mv_v)
            if __mv_t=="table" then
                local __mv_seen=0
                local __mv_parts={}
                for __mv_k,__mv_x in pairs(__mv_v) do
                    __mv_seen=__mv_seen+1
                    if __mv_seen<=8 then
                        if type(__mv_x)=="string" then
                            __mv_capture_string(tostring(__mv_label or "table").."_"..tostring(__mv_k), __mv_x)
                        end
                        __mv_parts[#__mv_parts+1]=tostring(__mv_k)..":"..type(__mv_x)..":"..tostring(__mv_x)
                    end
                end
                return "table(ptr="..tostring(__mv_v)..",len="..tostring(#__mv_v)..",seen="..tostring(__mv_seen).."):"..table.concat(__mv_parts,",")
            elseif __mv_t=="function" then
                return "function:"..tostring(__mv_v)
            elseif __mv_t=="string" then
                __mv_capture_string(__mv_label,__mv_v)
                return "string(len="..tostring(#__mv_v).."):"..tostring(__mv_v)
            else
                return __mv_t..":"..tostring(__mv_v)
            end
        end
        local __mv_op=type(l)=="table" and l[0x3c22] or nil
        local __mv_a=type(l)=="table" and l[0x2895] or nil
        local __mv_b=type(l)=="table" and l[0xc392] or nil
        local __mv_c=type(l)=="table" and l[0xb4ab] or nil
        local __mv_lines={
            "trace="..tostring(__mv_dispatch_trace_count),
            "pc="..tostring(j),
            "program_ptr="..tostring(g),
            "stack_ptr="..tostring(d),
            "upvalue_ptr="..tostring(e),
            "frame_ptr="..tostring(h),
            "program_len="..tostring(type(g)=="table" and #g or -1),
            "program_seen="..tostring(__mv_count(g)),
            "row_type="..type(l),
            "row_ptr="..tostring(l),
            "op="..tostring(__mv_op),
            "a="..tostring(__mv_a),
            "b="..tostring(__mv_b),
            "c="..tostring(__mv_c),
            "d37c="..tostring(type(l)=="table" and l[0xd37c] or nil),
            "i1="..tostring(type(l)=="table" and l[0x1a4b] or nil),
            "i2="..tostring(type(l)=="table" and l[0xaff3] or nil),
            "lit="..tostring(type(l)=="table" and l[0xa08e] or nil)
        }
        if __mv_op==106 then
            local __mv_call_base=(tonumber(__mv_a) or 0)-0x17
            local __mv_argc=(tonumber(__mv_b) or 0)-0x28
            local __mv_retctl=(tonumber(__mv_c) or 0)-0x3d
            __mv_lines[#__mv_lines+1]="call_base="..tostring(__mv_call_base)
            __mv_lines[#__mv_lines+1]="call_argc="..tostring(__mv_argc)
            __mv_lines[#__mv_lines+1]="call_retctl="..tostring(__mv_retctl)
            __mv_lines[#__mv_lines+1]="call_target="..__mv_desc(type(d)=="table" and d[__mv_call_base] or nil, "t"..tostring(__mv_dispatch_trace_count).."_call_target")
        elseif __mv_op==224 then
            local __mv_dst=(tonumber(__mv_a) or 0)-0x14
            local __mv_proto=(tonumber(type(l)=="table" and l[0xd37c] or nil) or 0)-0x3f
            __mv_lines[#__mv_lines+1]="closure_dst="..tostring(__mv_dst)
            __mv_lines[#__mv_lines+1]="closure_proto_idx="..tostring(__mv_proto)
            __mv_lines[#__mv_lines+1]="closure_proto="..__mv_desc(type(e)=="table" and type(e[2])=="table" and type(e[2][0x7807])=="table" and e[2][0x7807][__mv_proto] or nil, "t"..tostring(__mv_dispatch_trace_count).."_closure_proto")
        end
        if type(d)=="table" then
            for __mv_i=1,__TRACE_REGISTERS__ do
                local __mv_v=d[__mv_i]
                if __mv_v~=nil then
                    __mv_lines[#__mv_lines+1]="r"..tostring(__mv_i).."="..__mv_desc(__mv_v, "t"..tostring(__mv_dispatch_trace_count).."_r"..tostring(__mv_i))
                end
            end
        end
        if type(e)=="table" then
            for __mv_i=1,12 do
                local __mv_v=e[__mv_i]
                if __mv_v~=nil then
                    __mv_lines[#__mv_lines+1]="u"..tostring(__mv_i).."="..__mv_desc(__mv_v, "t"..tostring(__mv_dispatch_trace_count).."_u"..tostring(__mv_i))
                end
            end
        end
        if (__mv_op==105 or __mv_op==106 or __mv_op==209 or __mv_op==224 or l==nil) then
            local __mv_hidden={{"n",n},{"o",o},{"p",p},{"q",q},{"r",r},{"s",s},{"t",t},{"u",u},{"v",v},{"w",w},{"x",x},{"y",y},{"z",z},{"A",A},{"B",B},{"C",C},{"m",m},{"i",i}}
            for __mv_hi=1,#__mv_hidden do
                local __mv_item=__mv_hidden[__mv_hi]
                if __mv_item[2]~=nil then
                    __mv_lines[#__mv_lines+1]="hidden_"..__mv_item[1].."="..__mv_desc(__mv_item[2], "t"..tostring(__mv_dispatch_trace_count).."_hidden_"..__mv_item[1])
                end
            end
        end
        if type(k)=="table" then
            local __mv_seen=0
            for __mv_k,__mv_v in pairs(k) do
                __mv_seen=__mv_seen+1
                if __mv_seen<=12 then
                    __mv_lines[#__mv_lines+1]="cache["..tostring(__mv_k).."]="..__mv_desc(__mv_v, "t"..tostring(__mv_dispatch_trace_count).."_cache_"..tostring(__mv_k))
                end
            end
            __mv_lines[#__mv_lines+1]="cache_seen="..tostring(__mv_seen)
        end
        __rbx_capture_text("moonveil_dispatch_trace", table.concat(__mv_lines,"\n"), ".txt")
        if __SNAPSHOT_CALLS__ and __mv_dispatch_trace_count>=__SNAPSHOT_MIN_TRACE__ and type(__rbx_function_snapshot)=="function" and (__mv_op==106 or l==nil) then
            local function __mv_snap(__mv_label,__mv_fn)
                if type(__mv_fn)=="function" then
                    local __mv_ok,__mv_json=pcall(__rbx_function_snapshot,__mv_fn,__mv_label,true)
                    if __mv_ok and type(__mv_json)=="string" then
                        __rbx_capture_text("moonveil_function_snapshot", __mv_json, ".json")
                    else
                        __rbx_capture_text("moonveil_function_snapshot_error", tostring(__mv_label).."\n"..tostring(__mv_json), ".txt")
                    end
                end
            end
            if __mv_op==106 and type(d)=="table" then
                local __mv_call_base=(tonumber(__mv_a) or 0)-0x17
                __mv_snap("trace="..tostring(__mv_dispatch_trace_count)..":pc="..tostring(j)..":call_base="..tostring(__mv_call_base), d[__mv_call_base])
            elseif l==nil and type(d)=="table" then
                for __mv_i=1,__TRACE_REGISTERS__ do
                    __mv_snap("trace="..tostring(__mv_dispatch_trace_count)..":pc="..tostring(j)..":nilrow:r"..tostring(__mv_i), d[__mv_i])
                end
            end
        end
    end
end
n,m=1,l[0x3c22]j,n=j+n,0x92 b=m<n and 0b1111 or b+-0b100000'''
        dispatch_traced = (
            dispatch_traced
            .replace("__FORCE_PC_BLOCK__", force_pc_block)
            .replace("__TRACE_LIMIT__", str(int(trace_limit)))
            .replace("__TRACE_REGISTERS__", str(int(trace_registers)))
            .replace("__EMPTY_PROTO_RETURNS__", "true" if empty_proto_returns else "false")
            .replace("__EMPTY_PROTO_EXPLORE__", "true" if empty_proto_explore else "false")
            .replace("__SNAPSHOT_CALLS__", "true" if snapshot_calls else "false")
            .replace("__SNAPSHOT_MIN_TRACE__", str(int(snapshot_min_trace)))
            .replace("__CAPTURE_VM_STRINGS__", "true" if capture_vm_strings else "false")
            .replace("__CAPTURE_VM_STRING_MIN__", str(int(capture_vm_string_min)))
        )
        if dispatch not in table_source:
            raise ValueError("MoonVeil dispatch pattern was not found for tracing")
        table_source = table_source.replace(dispatch, dispatch_traced, 1)

        packed_return = 'r=a.c(r(s,t,u))return a.d(r)'
        packed_return_traced = r'''local __mv_ret_fn,__mv_ret_s,__mv_ret_t,__mv_ret_u=r,s,t,u r=a.c(r(s,t,u)) if type(__rbx_capture_text)=="function" then local function __mv_ret_desc(__mv_v) local __mv_t=type(__mv_v) if __mv_t=="table" then local __mv_seen=0 local __mv_parts={} for __mv_k,__mv_x in pairs(__mv_v) do __mv_seen=__mv_seen+1 if __mv_seen<=8 then __mv_parts[#__mv_parts+1]=tostring(__mv_k)..":"..type(__mv_x)..":"..tostring(__mv_x) end end return "table(ptr="..tostring(__mv_v)..",len="..tostring(#__mv_v)..",seen="..tostring(__mv_seen).."):"..table.concat(__mv_parts,",") elseif __mv_t=="function" then return "function:"..tostring(__mv_v) elseif __mv_t=="string" then return "string(len="..tostring(#__mv_v).."):"..tostring(__mv_v) else return __mv_t..":"..tostring(__mv_v) end end local __mv_lines={"trace="..tostring(__mv_dispatch_trace_count),"return_fn="..__mv_ret_desc(__mv_ret_fn),"return_s="..__mv_ret_desc(__mv_ret_s),"return_t="..__mv_ret_desc(__mv_ret_t),"return_u="..__mv_ret_desc(__mv_ret_u),"pack="..__mv_ret_desc(r),"pack_count="..tostring(type(r)=="table" and r[2] or nil)} if type(__mv_ret_s)=="table" then for __mv_i=1,math.min(64,#__mv_ret_s) do local __mv_v=__mv_ret_s[__mv_i] if type(__mv_v)=="string" then __mv_lines[#__mv_lines+1]="frame_r"..tostring(__mv_i).."="..__mv_ret_desc(__mv_v) __rbx_capture_text("moonveil_return_frame_string_r"..tostring(__mv_i), __mv_v, ".bin") end end end local __mv_vals=type(r)=="table" and r[1] or nil if type(__mv_vals)=="table" then for __mv_i=1,math.min(32,tonumber(r[2]) or #__mv_vals) do local __mv_v=__mv_vals[__mv_i] __mv_lines[#__mv_lines+1]="value"..tostring(__mv_i).."="..__mv_ret_desc(__mv_v) if type(__mv_v)=="string" then __rbx_capture_text("moonveil_return_string", __mv_v, ".bin") elseif type(__mv_v)=="function" and type(__rbx_function_snapshot)=="function" then local __mv_ok,__mv_json=pcall(__rbx_function_snapshot,__mv_v,"return_trace="..tostring(__mv_dispatch_trace_count)..":value"..tostring(__mv_i),true) if __mv_ok and type(__mv_json)=="string" then __rbx_capture_text("moonveil_return_function_snapshot", __mv_json, ".json") end end end end __rbx_capture_text("moonveil_packed_return", table.concat(__mv_lines,"\n"), ".txt") end return a.d(r)'''
        if brutecall_return_frame:
            frame_probe = 'if type(__mv_ret_s)=="table" then for __mv_i=1,math.min(64,#__mv_ret_s) do local __mv_v=__mv_ret_s[__mv_i] if type(__mv_v)=="string" then __mv_lines[#__mv_lines+1]="frame_r"..tostring(__mv_i).."="..__mv_ret_desc(__mv_v) __rbx_capture_text("moonveil_return_frame_string_r"..tostring(__mv_i), __mv_v, ".bin") end end end local __mv_vals='
            brute_probe = 'if type(__mv_ret_s)=="table" then for __mv_i=1,math.min(64,#__mv_ret_s) do local __mv_v=__mv_ret_s[__mv_i] if type(__mv_v)=="string" then __mv_lines[#__mv_lines+1]="frame_r"..tostring(__mv_i).."="..__mv_ret_desc(__mv_v) __rbx_capture_text("moonveil_return_frame_string_r"..tostring(__mv_i), __mv_v, ".bin") elseif type(__mv_v)=="function" and (tonumber(__mv_dispatch_trace_count) or 0)>=__BRUTECALL_MIN_TRACE__ then local __mv_ok,__mv_a,__mv_b,__mv_c=pcall(__mv_v) __mv_lines[#__mv_lines+1]="brutecall_frame_r"..tostring(__mv_i).."="..tostring(__mv_ok)..":"..__mv_ret_desc(__mv_a)..","..__mv_ret_desc(__mv_b)..","..__mv_ret_desc(__mv_c) if type(__mv_a)=="string" then __rbx_capture_text("moonveil_brutecall_return_r"..tostring(__mv_i).."_1", __mv_a, ".bin") end if type(__mv_b)=="string" then __rbx_capture_text("moonveil_brutecall_return_r"..tostring(__mv_i).."_2", __mv_b, ".bin") end if type(__mv_c)=="string" then __rbx_capture_text("moonveil_brutecall_return_r"..tostring(__mv_i).."_3", __mv_c, ".bin") end end end end local __mv_vals='
            packed_return_traced = packed_return_traced.replace(frame_probe, brute_probe.replace("__BRUTECALL_MIN_TRACE__", str(int(brutecall_min_trace))))
        if packed_return not in table_source:
            raise ValueError("MoonVeil packed return pattern was not found for tracing")
        table_source = table_source.replace(packed_return, packed_return_traced, 1)

    return table_source


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def long_bracket(text: str) -> str:
    eq = ""
    while f"]{eq}]" in text:
        eq += "="
    return f"[{eq}[{text}]{eq}]"


def extract_printable_strings(data: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127 or b in (9,):
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("latin1"))
            cur.clear()
    if len(cur) >= min_len:
        out.append(cur.decode("latin1"))
    return out


def printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)


def looks_like_luau_source(data: bytes) -> tuple[bool, str]:
    if not data or b"\x00" in data:
        return False, "binary-or-empty"
    if printable_ratio(data) < 0.92:
        return False, "low-printable-ratio"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False, "not-utf8"
    debug_markers = [
        "-- locals --",
        "roblox_high_fidelity_setup",
        "__rbx_debug_snapshot",
        "attempt to index nil",
        "attempt to call",
        "[string \"moonveil_table\"]",
    ]
    if any(marker in text for marker in debug_markers):
        return False, "debug-or-error-text"
    if "MoonVeil" in text and "return({" in text:
        return False, "moonveil-wrapper-source"
    if re.search(r"\b(function|local|return|if|for|while)\b", text) and re.search(r"[=().{}]", text):
        return True, "source-like-luau-text"
    return False, "not-source-like"


def moonveil_base85_decode(encoded: str) -> tuple[bytes, bytes, int]:
    index = {ch: i for i, ch in enumerate(MOONVEIL_A85_ALPHABET)}
    rem = len(encoded) % 5
    pad_chars = 0 if rem == 0 else 5 - rem
    padded = encoded + ("~" * pad_chars)

    raw = bytearray()
    for pos in range(0, len(padded), 5):
        chunk = padded[pos : pos + 5]
        value = 0
        for ch in chunk:
            if ch not in index:
                raise ValueError(f"bad MoonVeil base85 char {ch!r} at encoded offset {pos}")
            value = value * 85 + index[ch]
        raw.extend(value.to_bytes(4, "big"))

    stripped = bytes(raw[:-pad_chars] if pad_chars else raw)
    return bytes(raw), stripped, pad_chars


def find_moonveil_payload(source: str) -> dict:
    header = re.search(r"MoonVeil\s+([^\[]+)\[https://moonveil\.cc\]", source)
    suffix = re.search(r"\}\):([A-Za-z_]\w*)\(\.\.\.\)\s*$", source)
    payload = re.search(r'f=function\(a,b\)return a\.x\(a\.l\(a\.i"([^"]+)"\),b\)end', source)

    if not suffix:
        raise ValueError("MoonVeil v2 suffix `}):ENTRY(...)` was not found")
    if not payload:
        raise ValueError('MoonVeil v2 payload pattern `f=function(a,b)return a.x(a.l(a.i"..."),b)end` was not found')

    entry = suffix.group(1)
    table_source = source[: suffix.start()] + "})"

    entry_re = re.compile(
        re.escape(entry) + r"=function\(a,\.\.\.\)(.*?)return a:f\(\)\(\.\.\.\)end",
        re.S,
    )
    entry_match = entry_re.search(source)
    init_order = []
    if entry_match:
        init_order = re.findall(r"a:([A-Za-z_]\w*)\(\)", entry_match.group(1))

    if not init_order:
        init_order = ["g", "q", "x", "l", "n", "i"]

    return {
        "version": header.group(1).strip() if header else "unknown",
        "entrypoint": entry,
        "entrypoint_offset": suffix.start(),
        "payload": payload.group(1),
        "payload_offset": payload.start(1),
        "payload_end": payload.end(1),
        "payload_marker_offset": payload.start(),
        "table_source": table_source,
        "init_order": init_order,
    }


def make_driver(table_source: str, encoded: str, init_order: list[str], execute_vm: bool, proxy_game_children: list[str], trace_vm_lookups: bool = False, trace_vm_dispatch: bool = False, vm_arg_mode: str = "none", trace_registers: int = 24, trace_limit: int = 2400, empty_proto_returns: bool = False, roblox_type_shim: bool = False, game_call_error: str = "attempt to call a userdata value", snapshot_calls: bool = True, snapshot_min_trace: int = 0, capture_vm_strings: bool = False, capture_vm_string_min: int = 1, empty_proto_explore: bool = False, brutecall_return_frame: bool = False, brutecall_min_trace: int = 0, force_pc_jumps: list[tuple[int, int]] | None = None) -> str:
    if trace_vm_lookups or trace_vm_dispatch:
        table_source = patch_table_source_for_vm_trace(table_source, trace_vm_dispatch, trace_registers, trace_limit, empty_proto_returns, snapshot_calls, snapshot_min_trace, capture_vm_strings, capture_vm_string_min, empty_proto_explore, brutecall_return_frame, brutecall_min_trace, force_pc_jumps)

    init_lua = "{" + ",".join(repr(name).replace("'", '"') for name in init_order) + "}"
    proxy_lua = "{" + ",".join(repr(name).replace("'", '"') for name in proxy_game_children) + "}"
    return f"""
local tableSrc = {long_bracket(table_source)}
local encoded = {long_bracket(encoded)}
local initOrder = {init_lua}
local proxyGameChildren = {proxy_lua}
local vmArgMode = {vm_arg_mode!r}
local robloxTypeShim = {str(roblox_type_shim).lower()}
local gameCallError = {long_bracket(game_call_error)}

if robloxTypeShim then
    local originalType = type
    local originalTypeof = rawget(_G, "typeof") or originalType
    local originalGame = rawget(_G, "game")
    local originalEnum = rawget(_G, "Enum")
    local robloxUserdataTables = {{}}
    local enumUserdataTables = {{}}
    local instanceUserdataTables = {{}}

    local function markRobloxUserdata(value, label, depth, enumLike)
        if originalType(value) ~= "table" or robloxUserdataTables[value] then
            return
        end
        robloxUserdataTables[value] = true
        if enumLike then
            enumUserdataTables[value] = true
        else
            instanceUserdataTables[value] = true
        end
        local mt = getmetatable(value) or {{}}
        mt.__call = mt.__call or function()
            error(gameCallError, 2)
        end
        mt.__tostring = mt.__tostring or function()
            return tostring(label or "userdata")
        end
        pcall(setmetatable, value, mt)
        if depth <= 0 then
            return
        end
        for key, child in pairs(value) do
            if originalType(child) == "table" then
                local childLabel = tostring(label or "userdata") .. "." .. tostring(key)
                if enumLike or child.ClassName ~= nil or child.Name ~= nil or child.IsA ~= nil then
                    markRobloxUserdata(child, childLabel, depth - 1, enumLike)
                end
            end
        end
    end

    markRobloxUserdata(originalGame, "game", 5, false)
    markRobloxUserdata(rawget(_G, "workspace"), "workspace", 5, false)
    markRobloxUserdata(originalEnum, "Enum", 8, true)
    for _, serviceName in ipairs({{"Players","RunService","HttpService","TweenService","UserInputService","StarterGui","CoreGui","StarterPack","StarterPlayer","Lighting","ReplicatedStorage","CollectionService","Debris","MarketplaceService","TeleportService","GuiService","Stats","LogService"}}) do
        markRobloxUserdata(rawget(_G, serviceName), serviceName, 5, false)
    end

    type = function(value)
        if robloxUserdataTables[value] then
            return "userdata"
        end
        return originalType(value)
    end
    typeof = function(value)
        if enumUserdataTables[value] then
            return value == originalEnum and "Enum" or "EnumItem"
        elseif instanceUserdataTables[value] then
            return "Instance"
        end
        return originalTypeof(value)
    end
end

local function capture(kind, value, ext)
    if type(__rbx_capture_text) == "function" then
        __rbx_capture_text(kind, value, ext or ".bin")
    end
end

local function captureValues(prefix, ...)
    for i = 1, select("#", ...) do
        local value = select(i, ...)
        local t = type(value)
        if t == "string" then
            capture(prefix .. "_" .. tostring(i), value, ".lua")
        elseif t == "number" or t == "boolean" or value == nil then
            capture(prefix .. "_" .. tostring(i), tostring(value), ".txt")
        else
            capture(prefix .. "_" .. tostring(i), t .. ": " .. tostring(value), ".txt")
        end
    end
end

local root = assert(loadstring(tableSrc, "moonveil_table"))()
for _, name in ipairs(initOrder) do
    local factory = root[name]
    assert(type(factory) == "function", "missing MoonVeil initializer " .. tostring(name))
    root[name] = factory(root)
end

local decoded = root.i(encoded)
capture("moonveil_i_decoded", decoded, ".bin")

local unpacked = root.l(decoded)
capture("moonveil_vm_chunk", unpacked, ".bin")

local ok, fn = pcall(root.x, unpacked, nil)
capture("moonveil_x_status", tostring(ok) .. "\\n" .. type(fn) .. "\\n" .. tostring(fn), ".txt")
if not ok then
    error(fn)
end
assert(type(fn) == "function", "MoonVeil x() did not return a function")

if {str(execute_vm).lower()} then
    local function makeProxy(label)
        local proxy = {{}}
        local mt = {{}}
        mt.__index = function(_, key)
            if key == "ClassName" then return "Folder" end
            if key == "Name" then return label end
            if key == "Parent" then return game end
            if key == "GetFullName" then return function() return "game." .. label end end
            if key == "IsA" then return function(_, className) return className == "Folder" or className == "Instance" end end
            if key == "FindFirstChild" or key == "WaitForChild" then return function() return nil end end
            return proxy
        end
        mt.__newindex = function(_, key, value) rawset(proxy, key, value) end
        mt.__call = function() return proxy end
        mt.__tostring = function() return "game." .. label end
        mt.__len = function() return 0 end
        return setmetatable(proxy, mt)
    end
    if type(game) == "table" then
        for _, childName in ipairs(proxyGameChildren) do
            if game[childName] == nil then
                game[childName] = makeProxy(childName)
            end
        end
    end
    local results
    if vmArgMode == "script" then
        results = table.pack(pcall(fn, script))
    elseif vmArgMode == "game" then
        results = table.pack(pcall(fn, game))
    elseif vmArgMode == "source" then
        results = table.pack(pcall(fn, tableSrc))
    elseif vmArgMode == "encoded" then
        results = table.pack(pcall(fn, encoded))
    elseif vmArgMode == "decoded" then
        results = table.pack(pcall(fn, decoded))
    elseif vmArgMode == "chunk" then
        results = table.pack(pcall(fn, unpacked))
    else
        results = table.pack(pcall(fn))
    end
    capture("moonveil_vm_execute_status", tostring(results[1]) .. "\\n" .. tostring(results[2]), ".txt")
    captureValues("moonveil_vm_return", table.unpack(results, 2, results.n))
else
    return fn
end
"""


def run_runtime(runtime: Path, driver: Path, out_dir: Path, timeout: int, *, execute: bool) -> dict:
    cmd = [
        str(runtime),
        "--profile",
        "executor-client",
        "--network-policy",
        "offline",
        "--timeout",
        str(timeout),
        "--capture-min",
        "1",
        "--no-capture-string-hooks",
        "--luau-opt-level",
        "0",
        "--luau-debug-level",
        "2",
        "--out",
        str(out_dir),
    ]

    if execute:
        cmd.extend(["--trace-pcall-errors", "--luraph-mode", "off"])
    else:
        cmd.extend(["--luraph-mode", "force", "--no-luraph-stop-after-exact-source"])

    cmd.append(str(driver))

    proc = subprocess.run(cmd, cwd=Path.cwd(), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    write_text(out_dir / ("execute_stdout.log" if execute else "extract_stdout.log"), proc.stdout)
    write_text(out_dir / ("execute_stderr.log" if execute else "extract_stderr.log"), proc.stderr)
    return {
        "command": cmd,
        "returncode": proc.returncode,
        "stdout_bytes": len(proc.stdout.encode()),
        "stderr_bytes": len(proc.stderr.encode()),
    }


def load_capture_index(out_dir: Path) -> list[dict]:
    path = out_dir / "capture_index.jsonl"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"raw": line})
    return rows


def quarantine_false_exact(out_dir: Path) -> str | None:
    exact = out_dir / "original_luau_exact.lua"
    if not exact.exists():
        return None
    data = exact.read_bytes()
    ok, reason = looks_like_luau_source(data)
    text = data.decode("utf-8", errors="replace")
    if ok and "MoonVeil" not in text:
        return "kept"
    renamed = out_dir / "moonveil_wrapper_not_original.lua"
    shutil.move(str(exact), str(renamed))
    return f"moved_to_{renamed.name}:{reason}"


def analyze_outputs(out_dir: Path) -> dict:
    captures = load_capture_index(out_dir)
    capture_kind_by_path = {row.get("path"): row.get("kind") for row in captures if isinstance(row, dict)}
    source_candidates = []
    binaries = []
    for path in sorted(out_dir.iterdir()):
        if not path.is_file():
            continue
        data = path.read_bytes()
        if path.suffix in {".bin", ".lua", ".txt"}:
            ok, reason = looks_like_luau_source(data)
            kind = capture_kind_by_path.get(str(path))
            source_eligible = (
                kind is not None
                and (
                    kind.startswith("moonveil_vm_return")
                    or kind.startswith("loadstring_input")
                    or kind.startswith("loadstring_return")
                    or kind.startswith("main_return")
                    or kind.startswith("coroutine_")
                    or kind.startswith("moonveil_vm_string")
                )
                and not kind.startswith("pcall_error_snapshot")
            )
            item = {
                "path": str(path),
                "kind": kind,
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "printable_ratio": round(printable_ratio(data), 4),
                "classification": reason,
                "source_eligible": source_eligible,
            }
            if ok and source_eligible:
                source_candidates.append(item)
            elif path.suffix == ".bin" or printable_ratio(data) < 0.8:
                strings = extract_printable_strings(data, 4)
                item["printable_strings_seen"] = len(strings)
                item["printable_strings_sample"] = strings[:40]
                binaries.append(item)
    return {"captures": captures, "source_candidates": source_candidates, "binary_artifacts": binaries}


def extract_vm_ir_from_dump(out_dir: Path) -> dict | None:
    dump_path = out_dir / "luraph_function_dump.json"
    if not dump_path.exists():
        return None

    data = json.loads(dump_path.read_text(encoding="utf-8", errors="replace"))
    main_dumps = [d for d in data.get("dumps", []) if d.get("label") == "main_return_1"]
    if not main_dumps:
        return None

    functions = main_dumps[-1].get("functions", [])
    if not functions:
        return None

    upvalues = functions[0].get("upvalues", [])
    state_upvalue = next((uv for uv in upvalues if uv.get("index") == 2 and uv.get("type") == "table"), None)
    if not state_upvalue:
        return None

    candidates = []

    def walk(value, path="root"):
        if isinstance(value, dict):
            if value.get("value_type") == "table" and value.get("table_entries_seen") == 303 and len(value.get("preview", [])) == 303:
                child_previews = sum(1 for child in value.get("preview", []) if child.get("preview"))
                candidates.append((child_previews, path, value))
            for key, child in value.items():
                walk(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")

    walk(state_upvalue.get("preview", []))
    if not candidates:
        return None

    _, table_path, instruction_table = sorted(candidates, reverse=True)[0]
    rows = []
    field_keys = set()
    for entry in sorted(instruction_table.get("preview", []), key=lambda item: int(float(item.get("numeric_key", item.get("key"))))):
        fields = {}
        for child in entry.get("preview", []):
            key = str(child.get("key"))
            field_keys.add(key)
            fields[VM_FIELD_ALIASES.get(key, key)] = {
                "raw_key": key,
                "type": child.get("value_type"),
                "value": child.get("value"),
                "bytes": child.get("bytes"),
                "hex": child.get("hex"),
                "key_hex": child.get("key_hex"),
                "entries": child.get("table_entries_seen"),
            }
        rows.append({"pc": int(float(entry["numeric_key"])), "fields": fields})

    ordered_keys = sorted(field_keys, key=lambda item: int(item))
    ordered_aliases = [VM_FIELD_ALIASES.get(key, key) for key in ordered_keys]

    stats = {}
    for alias in ordered_aliases:
        values = [str(row["fields"].get(alias, {}).get("value")) for row in rows if alias in row["fields"]]
        counts = {}
        for value in values:
            counts[value] = counts.get(value, 0) + 1
        stats[alias] = {
            "unique_values": len(counts),
            "most_common": sorted(counts.items(), key=lambda item: item[1], reverse=True)[:20],
        }

    ir = {
        "source_dump": str(dump_path),
        "table_path": table_path,
        "field_keys": ordered_keys,
        "field_aliases": {key: VM_FIELD_ALIASES.get(key, key) for key in ordered_keys},
        "field_stats": stats,
        "instruction_count": len(rows),
        "instructions": rows,
    }

    ir_path = out_dir / "moonveil_vm_ir.json"
    write_text(ir_path, json.dumps(ir, indent=2))

    pseudo_lines = [
        "-- MoonVeil VM IR fallback.",
        "-- This is not original source. It is the decoded VM program table with obfuscated field names mapped to hex keys.",
        f"-- instruction_count={len(rows)}",
        "",
    ]
    for row in rows:
        parts = []
        for alias in ordered_aliases:
            field = row["fields"].get(alias)
            if not field:
                continue
            value = field.get("value")
            if field.get("type") == "string":
                value = repr(value)
            parts.append(f"{alias}={value}")
        pseudo_lines.append(f"-- pc {row['pc']:03d}: " + ", ".join(parts))
    pseudo_path = out_dir / "moonveil_vm_ir_fallback.lua"
    write_text(pseudo_path, "\n".join(pseudo_lines) + "\n")

    return {
        "path": str(ir_path),
        "fallback_path": str(pseudo_path),
        "instruction_count": len(rows),
        "table_path": table_path,
        "field_aliases": ir["field_aliases"],
    }


def _is_vm_instruction_row(value: object) -> bool:
    if not isinstance(value, dict) or value.get("value_type") != "table":
        return False
    keys = {str(child.get("key")) for child in value.get("preview", []) if isinstance(child, dict)}
    return VM_FIELD_KEYS.issubset(keys)


def _vm_instruction_row_to_fields(value: dict) -> dict:
    fields = {}
    for child in value.get("preview", []):
        if not isinstance(child, dict):
            continue
        key = str(child.get("key"))
        if key not in VM_FIELD_KEYS:
            continue
        fields[VM_FIELD_ALIASES.get(key, key)] = {
            "raw_key": key,
            "type": child.get("value_type"),
            "value": child.get("value"),
            "bytes": child.get("bytes"),
            "hex": child.get("hex"),
            "key_hex": child.get("key_hex"),
            "entries": child.get("table_entries_seen"),
        }
    return fields


def extract_vm_programs_from_dump(out_dir: Path) -> dict | None:
    dump_path = out_dir / "luraph_function_dump.json"
    if not dump_path.exists():
        return None

    data = json.loads(dump_path.read_text(encoding="utf-8", errors="replace"))
    main_dumps = [d for d in data.get("dumps", []) if d.get("label") == "main_return_1"]
    if not main_dumps:
        return None
    functions = main_dumps[-1].get("functions", [])
    if not functions:
        return None
    upvalues = functions[0].get("upvalues", [])
    state_upvalue = next((uv for uv in upvalues if uv.get("index") == 2 and uv.get("type") == "table"), None)
    if not state_upvalue:
        return None

    found = []

    def walk(value, path="root"):
        if isinstance(value, dict):
            preview = value.get("preview", [])
            if (
                value.get("value_type") == "table"
                and preview
                and all(_is_vm_instruction_row(child) for child in preview)
            ):
                rows = []
                for child in preview:
                    pc = int(float(child.get("numeric_key", child.get("key"))))
                    rows.append({"pc": pc, "fields": _vm_instruction_row_to_fields(child)})
                rows.sort(key=lambda row: row["pc"])
                found.append({"path": path, "instruction_count": len(rows), "instructions": rows})

            for key, child in value.items():
                walk(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")

    walk(state_upvalue.get("preview", []))
    if not found:
        return None

    unique = {}
    for program in found:
        signature = sha256_bytes(json.dumps(program["instructions"], sort_keys=True).encode("utf-8"))
        if signature not in unique:
            unique[signature] = {
                "program_id": f"prog_{len(unique):03d}",
                "sha256": signature,
                "instruction_count": program["instruction_count"],
                "occurrences": [],
                "instructions": program["instructions"],
            }
        unique[signature]["occurrences"].append(program["path"])

    programs = sorted(unique.values(), key=lambda item: (-item["instruction_count"], item["program_id"]))
    output = {
        "source_dump": str(dump_path),
        "program_count": len(programs),
        "programs": programs,
    }

    programs_path = out_dir / "moonveil_vm_programs.json"
    write_text(programs_path, json.dumps(output, indent=2))

    lines = [
        "-- Unique MoonVeil VM programs/prototypes.",
        "-- This is not original source; it is static IR recovered from the decoded VM closure graph.",
        f"-- program_count={len(programs)}",
        "",
    ]
    ordered_aliases = [VM_FIELD_ALIASES[key] for key in sorted(VM_FIELD_ALIASES, key=int)]
    for program in programs:
        lines.append(f"-- {program['program_id']} rows={program['instruction_count']} occurrences={len(program['occurrences'])} sha256={program['sha256'][:16]}")
        for row in program["instructions"]:
            parts = []
            for alias in ordered_aliases:
                field = row["fields"].get(alias)
                if not field:
                    continue
                value = field.get("value")
                if field.get("type") == "string":
                    value = repr(value)
                    if field.get("hex"):
                        value = f"{value} hex={field.get('hex')}"
                parts.append(f"{alias}={value}")
            lines.append(f"--   pc {row['pc']:03d}: " + ", ".join(parts))
        lines.append("")
    fallback_path = out_dir / "moonveil_vm_programs_fallback.lua"
    write_text(fallback_path, "\n".join(lines))

    return {
        "path": str(programs_path),
        "fallback_path": str(fallback_path),
        "program_count": len(programs),
        "programs": [
            {
                "program_id": program["program_id"],
                "instruction_count": program["instruction_count"],
                "occurrences": len(program["occurrences"]),
                "sha256": program["sha256"],
            }
            for program in programs
        ],
    }


def analyze_dispatch_trace(out_dir: Path) -> dict | None:
    files = sorted(out_dir.glob("moonveil_dispatch_trace_*.txt"))
    if not files:
        return None

    rows = []
    for path in files:
        item = {"path": str(path)}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            item[key] = value
        rows.append(item)

    def as_int(value: object) -> int | None:
        try:
            return int(str(value))
        except (TypeError, ValueError):
            return None

    final = rows[-1]
    empty_return_files = sorted(out_dir.glob("moonveil_empty_proto_return_*.txt"))
    final_program_len = as_int(final.get("program_len"))
    final_row_type = final.get("row_type")
    empty_program_reached = (final_program_len == 0 and final_row_type == "nil") or bool(empty_return_files)
    final_wrapper = None
    for item in reversed(rows):
        if as_int(item.get("program_len")) == 8 and item.get("op") in {"106", "209"}:
            final_wrapper = item
            break

    op_counts: dict[str, int] = {}
    for item in rows:
        op = str(item.get("op"))
        if op and op != "None":
            op_counts[op] = op_counts.get(op, 0) + 1

    watched_keys = [f"r{i}" for i in range(1, 129)]
    watched_keys += [f"hidden_{name}" for name in ["n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "m", "i"]]
    diffs = []
    for prev, cur in zip(rows, rows[1:]):
        changed = {}
        for key in watched_keys:
            if key in prev or key in cur:
                old = prev.get(key)
                new = cur.get(key)
                if old != new:
                    changed[key] = {"from": old, "to": new}
        if changed:
            diffs.append({
                "after_trace": prev.get("trace"),
                "after_pc": prev.get("pc"),
                "after_op": prev.get("op"),
                "next_trace": cur.get("trace"),
                "next_pc": cur.get("pc"),
                "changed": changed,
            })

    diff_path = out_dir / "moonveil_dispatch_diff.json"
    write_text(diff_path, json.dumps({"diff_count": len(diffs), "diffs": diffs}, indent=2))

    trace_path = out_dir / "moonveil_dispatch_summary.json"
    summary = {
        "trace_count": len(rows),
        "last_trace": final,
        "empty_program_reached": empty_program_reached,
        "empty_proto_return_files": [str(path) for path in empty_return_files],
        "final_wrapper_trace": final_wrapper,
        "diff_path": str(diff_path),
        "op_counts": dict(sorted(op_counts.items(), key=lambda kv: int(kv[0]) if kv[0].lstrip("-").isdigit() else 999999)),
    }
    write_text(trace_path, json.dumps(summary, indent=2))
    summary["path"] = str(trace_path)
    return summary


def run_static_lifter(programs_path: str | None, out_dir: Path) -> dict | None:
    if not programs_path:
        return None
    input_path = Path(programs_path)
    if not input_path.exists():
        return None
    lifter = Path(__file__).with_name("lift_moonveil_vm.py")
    if not lifter.exists():
        return {"status": "skipped", "reason": f"missing {lifter}"}

    lua_out = out_dir / "moonveil_lifted_fallback.lua"
    summary_out = out_dir / "moonveil_lifted_summary.json"
    cmd = [
        sys.executable,
        str(lifter),
        str(input_path),
        "--lua-out",
        str(lua_out),
        "--summary-out",
        str(summary_out),
    ]
    proc = subprocess.run(cmd, cwd=Path.cwd(), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    write_text(out_dir / "moonveil_lifter_stdout.log", proc.stdout)
    write_text(out_dir / "moonveil_lifter_stderr.log", proc.stderr)
    return {
        "status": "ok" if proc.returncode == 0 else "failed",
        "command": cmd,
        "returncode": proc.returncode,
        "lua_path": str(lua_out) if lua_out.exists() else None,
        "summary_path": str(summary_out) if summary_out.exists() else None,
        "stdout_bytes": len(proc.stdout.encode()),
        "stderr_bytes": len(proc.stderr.encode()),
    }


def analyze_function_snapshot_strings(out_dir: Path) -> dict | None:
    captures = load_capture_index(out_dir)
    rows = [row for row in captures if isinstance(row, dict) and row.get("kind") == "function_snapshot_string"]
    if not rows:
        return None

    items = []
    source_candidates = []
    for row in rows:
        path = Path(row.get("path", ""))
        if not path.exists():
            path = out_dir / path.name
        if not path.exists():
            continue
        data = path.read_bytes()
        ok, reason = looks_like_luau_source(data)
        item = {
            "path": str(path),
            "label": row.get("label"),
            "bytes": len(data),
            "sha256": sha256_bytes(data),
            "printable_ratio": round(printable_ratio(data), 4),
            "classification": reason,
            "head_hex": data[:32].hex(),
        }
        if ok:
            source_candidates.append(item)
        items.append(item)

    largest = sorted(items, key=lambda item: item["bytes"], reverse=True)[:40]
    call_base_3_items = [
        item for item in items
        if isinstance(item.get("label"), str) and "call_base=3" in item["label"]
    ]
    summary = {
        "string_count": len(items),
        "source_candidate_count": len(source_candidates),
        "source_candidates": source_candidates,
        "largest": largest,
        "call_base_3_strings": sorted(call_base_3_items, key=lambda item: item["bytes"], reverse=True),
    }
    path = out_dir / "moonveil_raw_snapshot_strings.json"
    write_text(path, json.dumps(summary, indent=2))
    summary["path"] = str(path)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="MoonVeil 2.x extractor/decryption harness")
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, default=Path("work/mv-deobf"))
    parser.add_argument("--runtime", type=Path, default=Path("outputs/rbx_luau_runtime_macos_arm64"))
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--execute-vm", action="store_true", help="execute the returned MoonVeil VM function after extraction")
    parser.add_argument("--proxy-game-child", action="append", default=[], help="install a dummy game child before executing the VM; repeatable")
    parser.add_argument("--trace-vm-lookups", action="store_true", help="patch the MoonVeil VM to capture key constant-pool lookups during execution")
    parser.add_argument("--trace-vm-dispatch", action="store_true", help="patch the MoonVeil VM to capture dispatch pc/op/register traces during execution")
    parser.add_argument("--trace-vm-registers", type=int, default=24, help="number of VM registers to include in dispatch traces")
    parser.add_argument("--trace-vm-limit", type=int, default=2400, help="maximum number of dispatch traces to capture")
    parser.add_argument("--vm-arg-mode", choices=["none", "script", "game", "source", "encoded", "decoded", "chunk"], default="none", help="argument shape to pass when executing the recovered MoonVeil VM function")
    parser.add_argument("--empty-proto-returns", action="store_true", help="experimental: make zero-length MoonVeil child prototypes return nil instead of indexing g[1]")
    parser.add_argument("--moonveil-empty-proto-explore", action="store_true", help="capture sibling prototype/upvalue diagnostics when a zero-length MoonVeil child prototype is selected")
    parser.add_argument("--moonveil-brutecall-return-frame", action="store_true", help="experimental: pcall functions found in late VM return frames and capture their returns/errors")
    parser.add_argument("--moonveil-brutecall-min-trace", type=int, default=380, help="minimum dispatch trace for --moonveil-brutecall-return-frame")
    parser.add_argument("--moonveil-force-pc", type=parse_pc_jump, action="append", default=[], metavar="FROM=TO", help="experimental: when dispatch reaches FROM, capture state, set pc to TO, and continue; repeatable")
    parser.add_argument("--roblox-type-shim", action="store_true", help="make type(game)/type(Enum) report userdata and make game() raise a Roblox-like call error")
    parser.add_argument("--game-call-error", default="attempt to call a userdata value", help="error text raised when the type-shimmed game object is called")
    parser.add_argument("--no-vm-function-snapshots", action="store_true", help="disable native function/upvalue snapshots during VM dispatch tracing")
    parser.add_argument("--vm-snapshot-min-trace", type=int, default=0, help="only take VM function snapshots at or after this dispatch trace number")
    parser.add_argument("--capture-vm-strings", action="store_true", help="capture unique VM strings seen in traced registers, hidden state, and small table previews")
    parser.add_argument("--capture-vm-string-min", type=int, default=1, help="minimum length for --capture-vm-strings captures")
    parser.add_argument("--keep-drivers", action="store_true")
    args = parser.parse_args()

    source = read_text(args.input)
    info = find_moonveil_payload(source)
    raw_padded, decoded, pad_chars = moonveil_base85_decode(info["payload"])

    out_dir = args.out
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    write_text(out_dir / "moonveil_encoded_blob.txt", info["payload"])
    write_bytes(out_dir / "moonveil_base85_raw_padded.bin", raw_padded)
    write_bytes(out_dir / "moonveil_base85_decoded.bin", decoded)

    strings = extract_printable_strings(decoded, 4)
    write_text(out_dir / "moonveil_base85_decoded_strings.txt", "\n".join(strings) + ("\n" if strings else ""))

    extract_driver = out_dir / "moonveil_extract_layers.lua"
    execute_driver = out_dir / "moonveil_execute_vm.lua"
    trace_registers = max(1, min(args.trace_vm_registers, 128))
    trace_limit = max(1, min(args.trace_vm_limit, 100000))
    snapshot_calls = not args.no_vm_function_snapshots
    snapshot_min_trace = max(0, args.vm_snapshot_min_trace)
    capture_vm_string_min = max(1, args.capture_vm_string_min)
    write_text(extract_driver, make_driver(info["table_source"], info["payload"], info["init_order"], False, [], args.trace_vm_lookups, args.trace_vm_dispatch, args.vm_arg_mode, trace_registers, trace_limit, args.empty_proto_returns, args.roblox_type_shim, args.game_call_error, snapshot_calls, snapshot_min_trace, args.capture_vm_strings, capture_vm_string_min, args.moonveil_empty_proto_explore, args.moonveil_brutecall_return_frame, args.moonveil_brutecall_min_trace, args.moonveil_force_pc))
    write_text(execute_driver, make_driver(info["table_source"], info["payload"], info["init_order"], True, args.proxy_game_child, args.trace_vm_lookups, args.trace_vm_dispatch, args.vm_arg_mode, trace_registers, trace_limit, args.empty_proto_returns, args.roblox_type_shim, args.game_call_error, snapshot_calls, snapshot_min_trace, args.capture_vm_strings, capture_vm_string_min, args.moonveil_empty_proto_explore, args.moonveil_brutecall_return_frame, args.moonveil_brutecall_min_trace, args.moonveil_force_pc))

    if not args.runtime.exists():
        raise SystemExit(f"runtime not found: {args.runtime}")

    extract_run = run_runtime(args.runtime, extract_driver, out_dir, args.timeout, execute=False)
    execute_run = run_runtime(args.runtime, execute_driver, out_dir, args.timeout, execute=True) if args.execute_vm else None

    false_exact = quarantine_false_exact(out_dir)
    analysis = analyze_outputs(out_dir)
    vm_ir = extract_vm_ir_from_dump(out_dir)
    vm_programs = extract_vm_programs_from_dump(out_dir)
    dispatch_summary = analyze_dispatch_trace(out_dir)
    static_lift = run_static_lifter(vm_programs.get("path") if vm_programs else None, out_dir)
    raw_snapshot_strings = analyze_function_snapshot_strings(out_dir)

    vm_chunk = next((Path(row["path"]) for row in analysis["captures"] if row.get("kind") == "moonveil_vm_chunk"), None)
    if vm_chunk and vm_chunk.exists():
        vm_data = vm_chunk.read_bytes()
        write_text(
            out_dir / "moonveil_vm_chunk_strings.txt",
            "\n".join(extract_printable_strings(vm_data, 4)) + "\n",
        )
        vm_chunk_info = {
            "path": str(vm_chunk),
            "bytes": len(vm_data),
            "sha256": sha256_bytes(vm_data),
            "printable_ratio": round(printable_ratio(vm_data), 4),
            "head_hex": vm_data[:64].hex(),
        }
    else:
        vm_chunk_info = None

    exact_status = "unknown"
    exact_reason = "no source-like VM return was observed"
    if analysis["source_candidates"]:
        best = Path(analysis["source_candidates"][0]["path"])
        data = best.read_bytes()
        ok, reason = looks_like_luau_source(data)
        if ok:
            write_bytes(out_dir / "original_luau_exact.lua", data)
            exact_status = "recovered"
            exact_reason = f"source-like captured text from {best.name}: {reason}"
    elif dispatch_summary and dispatch_summary.get("empty_program_reached"):
        exact_status = "blocked"
        exact_reason = "VM execution reached an empty MoonVeil child prototype before any source-like text was emitted"

    report = {
        "input": str(args.input),
        "version": info["version"],
        "entrypoint": info["entrypoint"],
        "entrypoint_offset": info["entrypoint_offset"],
        "init_order": info["init_order"],
        "payload_offset": info["payload_offset"],
        "payload_end": info["payload_end"],
        "payload_bytes": len(info["payload"]),
        "base85_padding_chars": pad_chars,
        "base85_raw_padded_bytes": len(raw_padded),
        "base85_decoded_bytes": len(decoded),
        "base85_decoded_sha256": sha256_bytes(decoded),
        "extract_run": extract_run,
        "execute_run": execute_run,
        "proxy_game_children": args.proxy_game_child,
        "vm_arg_mode": args.vm_arg_mode,
        "trace_vm_registers": trace_registers if args.trace_vm_dispatch else None,
        "trace_vm_limit": trace_limit if args.trace_vm_dispatch else None,
        "empty_proto_returns": args.empty_proto_returns,
        "moonveil_empty_proto_explore": args.moonveil_empty_proto_explore,
        "moonveil_brutecall_return_frame": args.moonveil_brutecall_return_frame,
        "moonveil_brutecall_min_trace": args.moonveil_brutecall_min_trace if args.moonveil_brutecall_return_frame else None,
        "moonveil_force_pc": [{"from": src, "to": dst} for src, dst in args.moonveil_force_pc],
        "roblox_type_shim": args.roblox_type_shim,
        "game_call_error": args.game_call_error,
        "vm_function_snapshots": snapshot_calls,
        "vm_snapshot_min_trace": snapshot_min_trace if snapshot_calls else None,
        "capture_vm_strings": args.capture_vm_strings,
        "capture_vm_string_min": capture_vm_string_min if args.capture_vm_strings else None,
        "false_exact_handling": false_exact,
        "vm_chunk": vm_chunk_info,
        "vm_ir": vm_ir,
        "vm_programs": vm_programs,
        "dispatch_summary": dispatch_summary,
        "static_lift": static_lift,
        "raw_snapshot_strings": raw_snapshot_strings,
        "exact_recovery_status": exact_status,
        "exact_recovery_reason": exact_reason,
        "analysis": analysis,
    }
    write_text(out_dir / "moonveil_recovery_report.json", json.dumps(report, indent=2))

    if not args.keep_drivers:
        # Keep them by default while this workflow is still being tuned? No: user output is cleaner.
        # The report records enough to regenerate, but leave the files if the caller asks.
        pass

    print(json.dumps({
        "out": str(out_dir),
        "version": info["version"],
        "payload_bytes": len(info["payload"]),
        "decoded_bytes": len(decoded),
        "vm_chunk_bytes": vm_chunk_info["bytes"] if vm_chunk_info else None,
        "exact_recovery_status": exact_status,
        "exact_recovery_reason": exact_reason,
    }, indent=2))
    return 0 if exact_status == "recovered" else 2


if __name__ == "__main__":
    sys.exit(main())
