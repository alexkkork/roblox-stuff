#!/usr/bin/env python3
"""Structural regression for the bounded Luraph VM trace injector."""

from __future__ import annotations

import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from luraph_trace_probe import ACTIVATION_NEEDLE, LOOP_NEEDLE, build_probe  # noqa: E402


def main() -> int:
    fixture = ROOT / "tests" / "fixtures" / "luraph" / "subject_1b642e9523c1.luau"
    source = fixture.read_text(encoding="utf-8")
    probe = build_probe(source, 363000, 364100)
    assert ACTIVATION_NEEDLE not in probe
    assert probe.count(LOOP_NEEDLE) == 1
    assert probe.count("@@LPH_VM@@") == 1
    assert probe.count("@@LPH_ACTIVATION@@") == 1
    assert "_G.__vmc>=363000 and _G.__vmc<=364100" in probe
    assert len(probe) > len(source)
    print("Luraph trace probe injector OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
