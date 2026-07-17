#!/usr/bin/env python3
"""Inject a bounded, source-local trace into the captured Luraph v14.7 VM loop."""

from __future__ import annotations

import argparse
import pathlib


ACTIVATION_NEEDLE = "m=function(...)local j,P"
LOOP_NEEDLE = "while true do local w=(e[l]);"


def build_probe(source: str, start: int, end: int) -> str:
    if source.count(ACTIVATION_NEEDLE) != 1:
        raise ValueError("expected exactly one Luraph VM activation function")
    if source.count(LOOP_NEEDLE) != 1:
        raise ValueError("expected exactly one Luraph VM dispatch loop")

    activation = (
        "m=function(...)"
        "local __callerAid,__callerPc,__callerOp=_G.__curAid,_G.__curPc,_G.__curOp;"
        "_G.__lph_a=(_G.__lph_a or 0)+1;"
        "local __aid=_G.__lph_a;"
        "local j,P"
    )
    source = source.replace(ACTIVATION_NEEDLE, activation, 1)

    marker = (
        "while true do local w=(e[l]);"
        "_G.__vmc=(_G.__vmc or 0)+1;"
        "_G.__curAid=__aid;_G.__curPc=l;_G.__curOp=w;"
        f"if _G.__vmc>={start} and _G.__vmc<={end} then "
        "local __registers=type(j)==\"table\" and j or nil;"
        "local __qi=type(Q)==\"table\" and rawget(Q,l) or nil;"
        "local __ti=type(t)==\"table\" and rawget(t,l) or nil;"
        "local __ui=type(u)==\"table\" and rawget(u,l) or nil;"
        "local __q=__registers and __qi and rawget(__registers,__qi) or nil;"
        "local __q1=__registers and __qi and rawget(__registers,__qi+1) or nil;"
        "local __t=__registers and __ti and rawget(__registers,__ti) or nil;"
        "local __u=__registers and __ui and rawget(__registers,__ui) or nil;"
        "local __qt=type(__q);local __q1t=type(__q1);local __tt=type(__t);local __ut=type(__u);"
        "local __qv=(__qt==\"string\" or __qt==\"number\") and __q or __qt;"
        "local __q1v=(__q1t==\"string\" or __q1t==\"number\") and __q1 or __q1t;"
        "local __tv=(__tt==\"string\" or __tt==\"number\") and __t or __tt;"
        "local __uv=(__ut==\"string\" or __ut==\"number\") and __u or __ut;"
        "local __qn=__qt==\"function\" and debug.info(__q,\"n\") or \"\";"
        "local __q1n=__q1t==\"function\" and debug.info(__q1,\"n\") or \"\";"
        "local __tn=__tt==\"function\" and debug.info(__t,\"n\") or \"\";"
        "local __un=__ut==\"function\" and debug.info(__u,\"n\") or \"\";"
        "print(\"@@LPH_VM@@\",_G.__vmc,__aid,__callerAid,__callerPc,__callerOp,l,w,"
        "__qi,__qt,__qv,__qn,__q1t,__q1v,__q1n,__ti,__tt,__tv,__tn,__ui,__ut,__uv,__un,"
        "type(f)==\"table\" and rawget(f,l) or nil,type(T)==\"table\" and rawget(T,l) or nil,type(x)==\"table\" and rawget(x,l) or nil);"
        "if l==1 then local __args={...};local __parts={};"
        "for __i=1,math.min(select(\"#\",...),8) do local __v=__args[__i];"
        "local __vt=type(__v);local __vv=(__vt==\"string\" or __vt==\"number\") and __v or __vt;"
        "__parts[#__parts+1]=tostring(__i)..\":\"..__vt..\":\"..tostring(__vv);end;"
        "print(\"@@LPH_ACTIVATION@@\",_G.__vmc,__aid,__callerAid,__callerPc,__callerOp,select(\"#\",...),table.concat(__parts,\"|\"));end;"
        "end;"
    )
    return source.replace(LOOP_NEEDLE, marker, 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--end", type=int, required=True)
    args = parser.parse_args()
    if args.start < 1 or args.end < args.start:
        parser.error("trace range must satisfy 1 <= start <= end")

    source = args.input.read_text(encoding="utf-8")
    probe = build_probe(source, args.start, args.end)
    args.output.write_text(probe, encoding="utf-8")
    print(f"wrote Luraph trace probe: {args.output} ({args.start}..{args.end})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
