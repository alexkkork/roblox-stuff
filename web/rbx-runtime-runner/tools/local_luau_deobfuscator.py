#!/usr/bin/env python3
"""Small local Luau deobfuscator for paste-sized snippets.

This is intentionally local/static.  It does not call an API or execute the
target code.  It peels common source-visible layers that show up in simple
Roblox snippets:

* decimal/hex/unicode Lua string escapes
* loadstring("...") wrappers
* string.char(...) builders
* string.reverse("...")
* table.concat({"a", "b"})
* adjacent literal concatenation with ..
* light formatting for simple local assignments
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import operator
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent

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


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def slugify(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    value = value.strip("._-")
    return value or "local_luau"


def lua_quote(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
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
    out.append('"')
    return "".join(out)


def eval_const_expr(expr: str) -> int:
    expr = expr.strip().replace("^", "**")
    if not re.fullmatch(r"[0-9A-Fa-fxXbBoO_+\-*/%^(). \t]+", expr):
        raise ValueError(f"not a numeric expression: {expr!r}")
    tree = ast.parse(expr.replace("_", ""), mode="eval")

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
        raise ValueError(f"non-integer expression: {expr!r}")
    return int(round(value))


def skip_space(src: str, i: int) -> int:
    while i < len(src) and src[i].isspace():
        i += 1
    return i


def decode_lua_short_string(src: str, start: int) -> tuple[str, int]:
    quote = src[start]
    if quote not in "'\"":
        raise ValueError("not a Lua short string")
    i = start + 1
    out: list[str] = []
    while i < len(src):
        ch = src[i]
        if ch == quote:
            return "".join(out), i + 1
        if ch != "\\":
            out.append(ch)
            i += 1
            continue

        i += 1
        if i >= len(src):
            out.append("\\")
            break
        esc = src[i]
        if esc.isdigit():
            digits = [esc]
            j = i + 1
            while j < len(src) and len(digits) < 3 and src[j].isdigit():
                digits.append(src[j])
                j += 1
            out.append(chr(int("".join(digits)) % 256))
            i = j
            continue
        if esc == "x" and i + 2 < len(src) and re.fullmatch(r"[0-9A-Fa-f]{2}", src[i + 1 : i + 3]):
            out.append(chr(int(src[i + 1 : i + 3], 16)))
            i += 3
            continue
        if esc == "u" and i + 1 < len(src) and src[i + 1] == "{":
            end = src.find("}", i + 2)
            if end != -1:
                try:
                    out.append(chr(int(src[i + 2 : end], 16)))
                    i = end + 1
                    continue
                except ValueError:
                    pass
        if esc == "z":
            i += 1
            while i < len(src) and src[i].isspace():
                i += 1
            continue
        if esc in "\r\n":
            i += 1
            if esc == "\r" and i < len(src) and src[i] == "\n":
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
    raise ValueError(f"unterminated Lua string at byte {start}")


def read_literal_text(text: str) -> str:
    value, end = decode_lua_short_string(text, 0)
    if text[end:].strip():
        raise ValueError("extra text after string literal")
    return value


def rewrite_short_strings(src: str) -> tuple[str, int]:
    out: list[str] = []
    changed = 0
    i = 0
    while i < len(src):
        ch = src[i]
        if ch in "'\"":
            try:
                value, end = decode_lua_short_string(src, i)
            except ValueError:
                out.append(ch)
                i += 1
                continue
            replacement = lua_quote(value)
            original = src[i:end]
            if replacement != original:
                changed += 1
            out.append(replacement)
            i = end
            continue
        out.append(ch)
        i += 1
    return "".join(out), changed


def find_matching_paren(src: str, open_pos: int) -> int:
    depth = 0
    i = open_pos
    while i < len(src):
        ch = src[i]
        if ch in "'\"":
            _, i = decode_lua_short_string(src, i)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced parentheses")


def split_top_level_commas(src: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(src):
        ch = src[i]
        if ch in "'\"":
            _, i = decode_lua_short_string(src, i)
            continue
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(src[start:i].strip())
            start = i + 1
        i += 1
    tail = src[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def extract_loadstring_literal(src: str) -> str | None:
    text = src.strip()
    if text.startswith("return "):
        text = text[7:].strip()
    m = re.match(r"(?:loadstring|load)\s*\(", text)
    if not m:
        return None
    open_pos = m.end() - 1
    try:
        close_pos = find_matching_paren(text, open_pos)
    except ValueError:
        return None
    args = text[open_pos + 1 : close_pos].strip()
    first_arg = split_top_level_commas(args)[0] if args else ""
    if not first_arg or first_arg[0] not in "'\"":
        return None
    try:
        literal = read_literal_text(first_arg)
    except ValueError:
        return None
    suffix = text[close_pos + 1 :].strip()
    if suffix in {"", "()", "();"}:
        return literal
    if re.fullmatch(r"\(\s*\)\s*;?", suffix):
        return literal
    return None


def fold_string_char_calls(src: str) -> tuple[str, int]:
    changed = 0
    pattern = re.compile(r"(?:string\.)?char\s*\(")
    out: list[str] = []
    pos = 0
    while True:
        m = pattern.search(src, pos)
        if not m:
            out.append(src[pos:])
            break
        open_pos = m.end() - 1
        try:
            close_pos = find_matching_paren(src, open_pos)
        except ValueError:
            pos = m.end()
            continue
        args = split_top_level_commas(src[open_pos + 1 : close_pos])
        try:
            value = "".join(chr(eval_const_expr(arg) % 256) for arg in args)
        except Exception:
            pos = m.end()
            continue
        out.append(src[pos : m.start()])
        out.append(lua_quote(value))
        changed += 1
        pos = close_pos + 1
    return "".join(out), changed


def fold_string_reverse_calls(src: str) -> tuple[str, int]:
    changed = 0
    pattern = re.compile(r"(?:string\.)?reverse\s*\(")
    out: list[str] = []
    pos = 0
    while True:
        m = pattern.search(src, pos)
        if not m:
            out.append(src[pos:])
            break
        open_pos = m.end() - 1
        try:
            close_pos = find_matching_paren(src, open_pos)
        except ValueError:
            pos = m.end()
            continue
        args = split_top_level_commas(src[open_pos + 1 : close_pos])
        if len(args) != 1 or not args[0] or args[0][0] not in "'\"":
            pos = m.end()
            continue
        try:
            value = read_literal_text(args[0])
        except ValueError:
            pos = m.end()
            continue
        out.append(src[pos : m.start()])
        out.append(lua_quote(value[::-1]))
        changed += 1
        pos = close_pos + 1
    return "".join(out), changed


def fold_table_concat_literals(src: str) -> tuple[str, int]:
    changed = 0
    pattern = re.compile(r"table\.concat\s*\(")
    out: list[str] = []
    pos = 0
    while True:
        m = pattern.search(src, pos)
        if not m:
            out.append(src[pos:])
            break
        open_pos = m.end() - 1
        try:
            close_pos = find_matching_paren(src, open_pos)
        except ValueError:
            pos = m.end()
            continue
        args = split_top_level_commas(src[open_pos + 1 : close_pos])
        if not args or not args[0].strip().startswith("{") or not args[0].strip().endswith("}"):
            pos = m.end()
            continue
        body = args[0].strip()[1:-1]
        parts = split_top_level_commas(body)
        values: list[str] = []
        try:
            for part in parts:
                if not part or part[0] not in "'\"":
                    raise ValueError("not a literal")
                values.append(read_literal_text(part))
        except ValueError:
            pos = m.end()
            continue
        sep = ""
        if len(args) >= 2:
            if not args[1] or args[1][0] not in "'\"":
                pos = m.end()
                continue
            sep = read_literal_text(args[1])
        out.append(src[pos : m.start()])
        out.append(lua_quote(sep.join(values)))
        changed += 1
        pos = close_pos + 1
    return "".join(out), changed


def fold_literal_concat(src: str) -> tuple[str, int]:
    changed = 0
    pattern = re.compile(r"('(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")\s*\.\.\s*('(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")")
    while True:
        m = pattern.search(src)
        if not m:
            return src, changed
        try:
            left = read_literal_text(m.group(1))
            right = read_literal_text(m.group(2))
        except ValueError:
            return src, changed
        src = src[: m.start()] + lua_quote(left + right) + src[m.end() :]
        changed += 1


def format_simple_local_assignments(src: str) -> tuple[str, int]:
    changed = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal changed
        before = match.group(0)
        after = f"{match.group(1)}local {match.group(2)} = {match.group(3).strip()}"
        if before != after:
            changed += 1
        return after

    lines = []
    for line in src.splitlines():
        if re.fullmatch(r"\s*local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]+;?\s*", line):
            line = re.sub(r"^(\s*)local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);?\s*$", repl, line)
        lines.append(line)
    return "\n".join(lines), changed


def deobfuscate_text(source: str) -> dict[str, Any]:
    current = source.rstrip("\n")
    changes: list[dict[str, Any]] = []
    unwrapped = 0

    for _ in range(12):
        before_round = current
        literal = extract_loadstring_literal(current)
        if literal is not None:
            current = literal
            unwrapped += 1
            changes.append({"pass": "unwrap_loadstring", "length": len(current)})

        current, count = rewrite_short_strings(current)
        if count:
            changes.append({"pass": "decode_lua_string_escapes", "count": count})

        for name, fn in (
            ("fold_string_char", fold_string_char_calls),
            ("fold_string_reverse", fold_string_reverse_calls),
            ("fold_table_concat", fold_table_concat_literals),
            ("fold_literal_concat", fold_literal_concat),
        ):
            current, count = fn(current)
            if count:
                changes.append({"pass": name, "count": count})

        literal = extract_loadstring_literal(current)
        if literal is not None:
            current = literal
            unwrapped += 1
            changes.append({"pass": "unwrap_loadstring", "length": len(current)})

        if current == before_round:
            break

    current, count = format_simple_local_assignments(current)
    if count:
        changes.append({"pass": "format_simple_local_assignment", "count": count})

    output = current.strip()
    if output:
        output += "\n"
    return {
        "output": output,
        "changes": changes,
        "unwrapped_loadstrings": unwrapped,
        "changed": output.rstrip("\n") != source.rstrip("\n"),
    }


def looks_like_wearedevs(source: str) -> bool:
    head = source[:4096].lower()
    return "wearedevs.net/obfuscator" in head or ("return(function(...)" in head and "local function" in head)


def write_manifest(out_dir: Path) -> Path:
    manifest = out_dir / "SHA256SUMS.txt"
    lines = []
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.name != manifest.name:
            lines.append(f"{sha256_path(path)}  {path.relative_to(out_dir)}")
    manifest.write_text("\n".join(lines) + "\n")
    return manifest


def open_in_finder(path: Path) -> None:
    if sys.platform == "darwin":
        subprocess.run(["open", str(path)], check=False)
    else:
        opener = shutil.which("xdg-open")
        if opener:
            subprocess.run([opener, str(path)], check=False)


def deobfuscate_file(input_path: Path, output_root: Path, open_output: bool = False) -> dict[str, Any]:
    input_path = input_path.expanduser().resolve()
    source = input_path.read_text(errors="replace")
    timestamp = time.strftime("%Y%m%d_%H%M%S") + f"_{time.time_ns() % 1_000_000_000:09d}"
    out_dir = (output_root / f"{slugify(input_path.stem)}_{timestamp}").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    result = deobfuscate_text(source)
    final_source = out_dir / "deobfuscated.luau"
    final_source.write_text(result["output"])
    report = {
        "input": str(input_path),
        "input_sha256": sha256_path(input_path),
        "output_dir": str(out_dir),
        "final_kind": "local_static_luau_deobfuscation" if result["changed"] else "local_static_luau_passthrough",
        "final_source": str(final_source),
        "final_source_sha256": sha256_path(final_source),
        "semantic_recovery_status": "static_deobfuscated" if result["changed"] else "unchanged",
        "verified_same_return": None,
        "verified_same_behavior": None,
        "verified_same_stdout": None,
        "exact_recovery_status": "not_checked_static_only",
        "changes": result["changes"],
        "unwrapped_loadstrings": result["unwrapped_loadstrings"],
        "mode": "local",
    }
    report_path = out_dir / "local_luau_deobfuscation_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    report["report_path"] = str(report_path)
    report["manifest"] = str(write_manifest(out_dir))

    if open_output:
        open_in_finder(out_dir)
    return report


def write_pasted_input(source: str, output_root: Path) -> Path:
    paste_dir = output_root / "_pasted_inputs"
    paste_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S") + f"_{time.time_ns() % 1_000_000_000:09d}"
    path = paste_dir / f"pasted_local_luau_{timestamp}.lua"
    path.write_text(source.rstrip("\n") + "\n")
    return path


def read_multiline_paste() -> str:
    print("Paste the script now. End with __END__ on its own line, or press Ctrl-D.")
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "__END__":
            break
        lines.append(line)
    source = "\n".join(lines)
    if not source.strip():
        raise ValueError("no script was pasted")
    return source


def input_path_or_paste(raw: str, output_root: Path) -> Path:
    raw = raw.strip()
    if raw in {"-", ""}:
        source = sys.stdin.read()
        if not source.strip():
            raise ValueError("stdin was empty")
        return write_pasted_input(source, output_root)
    if raw.lower() in {"p", "paste", "--paste"}:
        return write_pasted_input(read_multiline_paste(), output_root)

    path_text = raw.strip('"').strip("'").replace("\\ ", " ")
    if path_text.startswith("file://"):
        path_text = path_text.removeprefix("file://")
    candidate = Path(path_text).expanduser()
    if len(path_text) < 1024:
        try:
            if candidate.exists():
                return candidate
        except OSError:
            pass
    return write_pasted_input(raw, output_root)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local static Luau snippet deobfuscator")
    parser.add_argument("input", nargs="?", help="File path, '-' for stdin, or pasted one-line source")
    parser.add_argument("--out-root", type=Path, default=PROJECT_ROOT / "outputs" / "local_luau_deobf")
    parser.add_argument("--paste", action="store_true", help="Paste multiline source until __END__")
    parser.add_argument("--open", action="store_true", help="Open the output folder when done")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.paste:
        input_path = write_pasted_input(read_multiline_paste(), args.out_root)
    elif args.input is None:
        print("Paste a file path OR paste a one-line script, then press Enter.")
        print("For multiline scripts, type P and press Enter.")
        input_path = input_path_or_paste(input("> "), args.out_root)
    else:
        input_path = input_path_or_paste(args.input, args.out_root)

    report = deobfuscate_file(input_path, args.out_root, open_output=args.open)
    print(f"Output Luau: {report['final_source']}")
    print(f"Report: {report['report_path']}")
    print(f"Final kind: {report['final_kind']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
