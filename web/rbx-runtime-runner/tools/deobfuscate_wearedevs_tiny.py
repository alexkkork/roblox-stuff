#!/usr/bin/env python3
"""Static unpacker for the small WeAreDevs-style sample.

This handles the two string layers used by the attached sample:
decimal-escaped Lua strings followed by a custom base64 alphabet and table
permutation.  It then rewrites x(<constant expression>) lookups to literal
strings so the switch/state tree can be inspected and patched.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import operator
import re
from pathlib import Path


LOOKUP_OFFSET = 35386


BINOPS: dict[type[ast.AST], object] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

UNARYOPS: dict[type[ast.AST], object] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def eval_const_expr(expr: str) -> int:
    expr = expr.strip().replace("^", "**")
    tree = ast.parse(expr, mode="eval")

    def walk(node: ast.AST) -> float:
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.UnaryOp) and type(node.op) in UNARYOPS:
            return UNARYOPS[type(node.op)](walk(node.operand))  # type: ignore[index,operator]
        if isinstance(node, ast.BinOp) and type(node.op) in BINOPS:
            return BINOPS[type(node.op)](walk(node.left), walk(node.right))  # type: ignore[index,operator]
        raise ValueError(f"unsupported expression: {expr!r}")

    value = walk(tree)
    if abs(value - round(value)) > 1e-9:
        raise ValueError(f"non-integer expression: {expr!r} -> {value!r}")
    return int(round(value))


def lua_quote(value: str) -> str:
    out = ["'"]
    for ch in value:
        code = ord(ch)
        if ch == "'":
            out.append("\\'")
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 32 or code == 127:
            out.append(f"\\{code:03d}")
        else:
            out.append(ch)
    out.append("'")
    return "".join(out)


def decode_lua_short_string(src: str, start: int) -> tuple[str, int]:
    quote = src[start]
    assert quote in "'\""
    i = start + 1
    out: list[str] = []
    while i < len(src):
        ch = src[i]
        if ch == quote:
            return "".join(out), i + 1
        if ch == "\\":
            i += 1
            if i >= len(src):
                break
            esc = src[i]
            if esc.isdigit():
                digits = [esc]
                j = i + 1
                while j < len(src) and len(digits) < 3 and src[j].isdigit():
                    digits.append(src[j])
                    j += 1
                out.append(chr(int("".join(digits))))
                i = j
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
            continue
        out.append(ch)
        i += 1
    raise ValueError(f"unterminated string at byte {start}")


def decode_lua_strings(src: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(src):
        ch = src[i]
        if ch in "'\"":
            value, end = decode_lua_short_string(src, i)
            out.append(lua_quote(value))
            i = end
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def find_balanced(src: str, open_pos: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    i = open_pos
    while i < len(src):
        ch = src[i]
        if ch in "'\"":
            _, i = decode_lua_short_string(src, i)
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError(f"unbalanced {open_ch}{close_ch} starting at {open_pos}")


def parse_quoted_values(src: str) -> list[str]:
    values: list[str] = []
    i = 0
    while i < len(src):
        if src[i] in "'\"":
            value, end = decode_lua_short_string(src, i)
            values.append(value)
            i = end
            continue
        i += 1
    return values


def extract_initial_table(src: str) -> tuple[int, int, str, list[str]]:
    m = re.search(r"return\s*\(function\(\.\.\.\)\s*local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", src)
    if not m:
        raise ValueError("initial encoded table not found")
    table_name = m.group(1)
    marker = f"local {table_name}="
    start = src.index(marker, m.start())
    brace = src.index("{", start)
    end = find_balanced(src, brace, "{", "}")
    return brace, end, table_name, parse_quoted_values(src[brace + 1 : end])


def extract_ranges(src: str) -> list[tuple[int, int]]:
    m = re.search(r"ipairs\(\{(.*?)\}\)do", src, re.S)
    if not m:
        return []
    ranges: list[tuple[int, int]] = []
    for a, b in re.findall(r"\{([^{};,]+)[;,]([^{}]+?)\}", m.group(1)):
        ranges.append((eval_const_expr(a), eval_const_expr(b)))
    return ranges


def apply_reversals(values: list[str], ranges: list[tuple[int, int]]) -> list[str]:
    values = values[:]
    for left, right in ranges:
        left -= 1
        right -= 1
        while left < right:
            values[left], values[right] = values[right], values[left]
            left += 1
            right -= 1
    return values


def extract_lookup(src: str, table_name: str) -> tuple[str, int]:
    minus_pattern = re.compile(
        r"local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*"
        r"\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*return\s+"
        + re.escape(table_name)
        + r"\s*\[\s*\2\s*-\s*\((.*?)\)\s*\]\s*end",
        re.S,
    )
    m = minus_pattern.search(src)
    if m:
        return m.group(1), eval_const_expr(m.group(3))

    plus_pattern = re.compile(
        r"local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*"
        r"\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*return\s+"
        + re.escape(table_name)
        + r"\s*\[\s*\2\s*\+\s*\((.*?)\)\s*\]\s*end",
        re.S,
    )
    m = plus_pattern.search(src)
    if m:
        # The rest of the unpacker computes index as call_expr - offset.
        # For table[arg + K], use a negative offset so call_expr - (-K)
        # becomes call_expr + K.
        return m.group(1), -eval_const_expr(m.group(3))

    raise ValueError("lookup function not found")


def extract_alphabet(src: str) -> tuple[str, dict[str, int]]:
    alphabet: dict[str, int] = {}
    token_re = re.compile(r"(?:\['([^']+)'\]|([A-Za-z_][A-Za-z0-9_]*))\s*=\s*([^,;{}]+)")
    for m in re.finditer(r"local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{", src):
        name = m.group(1)
        brace = src.index("{", m.end() - 1)
        try:
            end = find_balanced(src, brace, "{", "}")
        except ValueError:
            continue
        body = src[brace + 1 : end]
        candidate: dict[str, int] = {}
        try:
            for match in token_re.finditer(body):
                key = match.group(1) if match.group(1) is not None else match.group(2)
                value = eval_const_expr(match.group(3))
                candidate[key] = value
        except Exception:
            continue
        if len(candidate) == 64 and sorted(candidate.values()) == list(range(64)):
            alphabet = candidate
            return name, alphabet
    raise ValueError("custom alphabet table not found")


def custom_b64_decode(text: str, alphabet: dict[str, int]) -> str:
    out = bytearray()
    accum = 0
    count = 0
    pos = 0
    while pos < len(text):
        ch = text[pos]
        if ch in alphabet:
            accum += alphabet[ch] * (64 ** (3 - count))
            count += 1
            if count == 4:
                out.extend(((accum // 65536) & 0xFF, ((accum % 65536) // 256) & 0xFF, accum & 0xFF))
                accum = 0
                count = 0
        elif ch == "=":
            out.append((accum // 65536) & 0xFF)
            if pos >= len(text) - 1 or text[pos + 1] != "=":
                out.append(((accum % 65536) // 256) & 0xFF)
            break
        pos += 1
    return out.decode("latin1")


def replace_lookup_calls(src: str, constants: list[str], lookup_name: str, offset: int) -> tuple[str, list[dict[str, object]]]:
    out: list[str] = []
    replacements: list[dict[str, object]] = []
    i = 0
    while i < len(src):
        if src.startswith(lookup_name + "(", i):
            end = find_balanced(src, i + 1, "(", ")")
            expr = src[i + len(lookup_name) + 1 : end]
            try:
                index = eval_const_expr(expr) - offset
                if 1 <= index <= len(constants):
                    literal = constants[index - 1]
                    out.append(lua_quote(literal))
                    replacements.append({"byte": i, "expr": expr, "index": index, "value": literal})
                    i = end + 1
                    continue
            except Exception:
                pass
        out.append(src[i])
        i += 1
    return "".join(out), replacements


def strip_decode_prelude(src: str) -> str:
    # Keep the real function call, but remove the now-unneeded string decoder
    # and table shuffler to leave a smaller artifact for manual analysis.
    matches = list(re.finditer(r"return\s*\(function\(", src))
    if len(matches) < 2:
        return src
    compact = src[matches[-1].start() :]
    # The slice starts inside the outer return(function(...)) wrapper, so the
    # original wrapper's closing "end)(...)" is no longer paired with anything.
    if compact.endswith("end)(...)"):
        compact = compact[: -len("end)(...)")]
    return "-- decoded constants inserted by tools/deobfuscate_wearedevs_tiny.py\n" + compact


def instrument_dispatcher(src: str) -> str:
    needle_match = re.search(r"while\s+([A-Za-z_][A-Za-z0-9_]*)\s+do\s+if", src)
    if not needle_match:
        return src
    state_name = needle_match.group(1)
    needle = needle_match.group(0)
    inject = (
        f"local __wd_state_count=0 while {state_name} do __wd_state_count=__wd_state_count+1 "
        f"if __wd_state_count<=2000 then print('[WD_STATE]',{state_name}) end if"
    )
    pos = needle_match.start()
    if pos == -1:
        return src
    return src[:pos] + inject + src[pos + len(needle) :]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--out-dir", type=Path, default=Path("outputs"))
    parser.add_argument("--stem", default="wearedevs_tiny")
    args = parser.parse_args()

    raw = args.input.read_text()
    decoded_literals = decode_lua_strings(raw)
    table_start, table_end, table_name, initial_values = extract_initial_table(decoded_literals)
    lookup_name, lookup_offset = extract_lookup(decoded_literals, table_name)
    ranges = extract_ranges(decoded_literals)
    permuted = apply_reversals(initial_values, ranges)
    alphabet_name, alphabet = extract_alphabet(decoded_literals)
    constants = [custom_b64_decode(value, alphabet) for value in permuted]
    constants_lua = "local P={\n" + "\n".join(f"  [{i}]={lua_quote(v)};" for i, v in enumerate(constants, 1)) + "\n}\n"

    replaced, replacements = replace_lookup_calls(decoded_literals, constants, lookup_name, lookup_offset)
    compact = strip_decode_prelude(replaced)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stem = args.stem
    paths = {
        "decoded_literals": args.out_dir / f"{stem}_decoded_literals.lua",
        "constants_lua": args.out_dir / f"{stem}_constants.lua",
        "constants_json": args.out_dir / f"{stem}_constants.json",
        "x_rewritten": args.out_dir / f"{stem}_x_rewritten.lua",
        "compact": args.out_dir / f"{stem}_compact.lua",
        "instrumented": args.out_dir / f"{stem}_instrumented.lua",
        "report": args.out_dir / f"{stem}_report.json",
    }
    paths["decoded_literals"].write_text(decoded_literals)
    paths["constants_lua"].write_text(constants_lua)
    paths["constants_json"].write_text(json.dumps(constants, indent=2))
    paths["x_rewritten"].write_text(replaced)
    paths["compact"].write_text(compact)
    paths["instrumented"].write_text(instrument_dispatcher(compact))

    report = {
        "input": str(args.input),
        "sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "initial_string_count": len(initial_values),
        "initial_table_name": table_name,
        "lookup_function_name": lookup_name,
        "lookup_offset": lookup_offset,
        "alphabet_table_name": alphabet_name,
        "reversal_ranges": ranges,
        "constant_count": len(constants),
        "x_replacement_count": len(replacements),
        "constants": constants,
        "artifacts": {name: str(path) for name, path in paths.items() if name != "report"},
        "sample_replacements": replacements[:20],
    }
    paths["report"].write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
