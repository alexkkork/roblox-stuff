#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Optional


M32 = 4294967296


def parse_lua_string_bytes(content: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(content):
        ch = content[i]
        if ch != "\\":
            out.extend(ch.encode("latin1", errors="replace"))
            i += 1
            continue

        i += 1
        if i >= len(content):
            out.append(92)
            break

        ch = content[i]
        if ch in ("x", "X") and i + 2 < len(content):
            digits = content[i + 1 : i + 3]
            if re.fullmatch(r"[0-9a-fA-F]{2}", digits):
                out.append(int(digits, 16))
                i += 3
                continue
        if ch.isdigit():
            digits = []
            while i < len(content) and content[i].isdigit() and len(digits) < 3:
                digits.append(content[i])
                i += 1
            out.append(int("".join(digits)) & 0xFF)
            continue

        escapes = {
            "a": 7,
            "b": 8,
            "f": 12,
            "n": 10,
            "r": 13,
            "t": 9,
            "v": 11,
            "\\": 92,
            '"': 34,
            "'": 39,
        }
        out.append(escapes.get(ch, ord(ch) & 0xFF))
        i += 1
    return bytes(out)


def lua_quote(text: str) -> str:
    pieces = ['"']
    for ch in text:
        c = ord(ch)
        if ch == "\\":
            pieces.append("\\\\")
        elif ch == '"':
            pieces.append('\\"')
        elif ch == "\n":
            pieces.append("\\n")
        elif ch == "\r":
            pieces.append("\\r")
        elif ch == "\t":
            pieces.append("\\t")
        elif 32 <= c <= 126:
            pieces.append(ch)
        else:
            pieces.append(f"\\{c:03d}")
    pieces.append('"')
    return "".join(pieces)


def safe_eval_int(expr: str) -> int:
    expr = expr.replace("mO", str(M32))
    expr = expr.replace("Ir", str(M32))
    if not re.fullmatch(r"[0-9a-fA-FxX+\-*/%() ]+", expr):
        raise ValueError(f"unsupported arithmetic expression: {expr}")
    value = eval(expr, {"__builtins__": {}}, {})
    return int(value)


def bxor8(a: int, b: int) -> int:
    return (a & 0xFF) ^ (b & 0xFF)


class WynStringDecoder:
    def __init__(self, source: str):
        self.source = source
        self.mI = self._extract_mi()
        self.mz = ((68 * 3846 + 134 * 6349 - 1056998) % M32)
        self.mT = 0
        self.Wg = 1664525
        self.Wm = 1013904223
        self.WW = 256
        self.Wk = ((99 * 3846 + 138 * 6349 - 1219203) % M32)
        self.Ww = ((55 * 3846 + 142 * 6349 - 1112911) % M32)
        self.WS = ((64 * 3846 + 126 * 6349 - 1045902) % M32)
        self.Wu = ((37 * 3846 + 122 * 6349 - 916861) % M32)
        self.WI = ((102 * 3846 + 132 * 6349 + 1874398214) % M32)
        self.WE = ((50 * 3846 + 136 * 6349 - 1016222) % M32)
        self.Wz = ((90 * 3846 + 74 * 6349 - 796388) % M32)

    def _extract_mi(self) -> bytes:
        match = re.search(r"local\s+md\s*=\s*\{(.*?)\}\s*local\s+mI\s*=", self.source, re.S)
        if not match:
            raise ValueError("could not find wYnFuscate md byte table")
        parts: dict[int, bytes] = {}
        for item in re.finditer(r"\[(\d+)\]\s*=\s*\"((?:\\.|[^\"\\])*)\"", match.group(1), re.S):
            parts[int(item.group(1))] = parse_lua_string_bytes(item.group(2))
        if not parts:
            raise ValueError("md table did not contain byte string shards")
        return b"".join(parts.get(i, b"") for i in range(1, max(parts) + 1))

    def _byte(self, one_based: int) -> int:
        if 1 <= one_based <= len(self.mI):
            return self.mI[one_based - 1]
        return 0

    def _header(self, pos: int, skip_index: int) -> tuple[int, int]:
        m7 = self._byte(pos) + self._byte(pos + 1) * self.WW
        wc = (self.mz + self.mT + (skip_index * self.WS) + (m7 % 65536) + self.Wk) % M32
        wc = ((wc * self.Wg) + self.Wm + (skip_index * self.WE) + ((self.mz % 65536) * self.Wz)) % M32
        if wc == 0:
            wc = (self.mz + 1) % M32
        wc = ((wc * self.Wg) + self.Wm + (skip_index * self.WS) + self.WI + (m7 % 65536)) % M32
        wt = wc % self.WW
        wo = ((wc - wt) // self.WW) % self.WW
        wq = ((wc - (wc % 65536)) // 65536) % self.WW
        wq2 = ((wc - (wc % 16777216)) // 16777216) % self.WW
        if pos + 2 > len(self.mI):
            return wc, 0
        length = bxor8(self._byte(pos + 2), bxor8(bxor8(wt, wo), bxor8(wq, (wq2 + skip_index) % self.WW)))
        return wc, length

    def decode(self, index: int, tweak: int) -> str:
        pos = 1
        skip_index = 0
        for _ in range(index):
            _, length = self._header(pos, skip_index)
            pos += 3 + length
            skip_index += 1

        m7 = self._byte(pos) + self._byte(pos + 1) * self.WW
        wc, length = self._header(pos, skip_index)
        out = bytearray()
        for n in range(1, length + 1):
            wc = (
                (wc * self.Wg)
                + self.Wm
                + (skip_index * self.WS)
                + (n * self.Ww)
                + (length * self.Wu)
                + (m7 % 65536)
                + self.WI
            ) % M32
            wt = wc % self.WW
            wo = ((wc - wt) // self.WW) % self.WW
            wq = ((wc - (wc % 65536)) // 65536) % self.WW
            wq2 = ((wc - (wc % 16777216)) // 16777216) % self.WW
            k = (tweak + (n * 37) + (length * 13) + (skip_index * 17) + (((tweak - (tweak % 257)) // 257) % self.WW)) % self.WW
            out.append(bxor8(self._byte(pos + 2 + n), bxor8(bxor8(bxor8(wt, (wo + n) % self.WW), bxor8(wq, (wq2 + skip_index + length) % self.WW)), k)))
        return out.decode("latin1")


def replace_string_resolver(source: str, decoder: WynStringDecoder) -> tuple[str, list[dict[str, object]]]:
    decoded: list[dict[str, object]] = []
    pattern = re.compile(r"mE\((\d+),(\(\([^)]*\)%(?:mO|Ir)\))\)")

    def repl(match: re.Match[str]) -> str:
        index = int(match.group(1))
        tweak = safe_eval_int(match.group(2))
        text = decoder.decode(index, tweak)
        decoded.append({"index": index, "tweak": tweak, "value": text})
        return lua_quote(text)

    return pattern.sub(repl, source), decoded


def simplify_obvious_arithmetic(source: str) -> str:
    # Keep this intentionally conservative: only standalone numeric parenthesized expressions.
    simple = re.compile(r"\(\((\d+)\)-\((\d+)\)\)")
    source = simple.sub(lambda m: str(int(m.group(1)) - int(m.group(2))), source)
    simple2 = re.compile(r"\(\((\d+)\+(\d+)\)-(\d+)\)")
    source = simple2.sub(lambda m: str(int(m.group(1)) + int(m.group(2)) - int(m.group(3))), source)
    return source


def extract_lua_string(source: str, var_name: str, last: bool = False) -> Optional[str]:
    matches = list(re.finditer(r"\blocal\s+" + re.escape(var_name) + r"\s*=\s*\"((?:\\.|[^\"\\])*)\"", source, re.S))
    if not matches:
        return None
    match = matches[-1] if last else matches[0]
    return parse_lua_string_bytes(match.group(1)).decode("latin1")


def extract_id_map(source: str) -> dict[int, int]:
    match = re.search(r"\blocal\s+ID\s*=\s*\{(.*?)\}\s*local\s+Id\b", source, re.S)
    if not match:
        return {}
    out: dict[int, int] = {}
    for key, value in re.findall(r"\[(\d+)\]\s*=\s*(\d+)", match.group(1)):
        out[int(key)] = int(value)
    return out


def decode_base91_payload(text: str, id_map: dict[int, int]) -> list[int]:
    out: list[int] = []
    pending = -1
    acc = 0
    bits = 0
    for ch in text:
        value = id_map.get(ord(ch))
        if value is None:
            continue
        if pending < 0:
            pending = value
            continue
        pending += value * 91
        acc += pending * (2**bits)
        if (pending % 8192) > 88:
            bits += 13
        else:
            bits += 14
        while bits >= 8:
            out.append(acc % 256)
            acc //= 256
            bits -= 8
        pending = -1
    if pending >= 0:
        acc += pending * (2**bits)
        bits += 7
        while bits >= 8:
            out.append(acc % 256)
            acc //= 256
            bits -= 8
    return out


def decode_varints(byte_values: list[int]) -> list[int]:
    out: list[int] = []
    acc = 0
    bits = 0
    for value in byte_values:
        acc += (value % 128) * (2**bits)
        if value >= 128:
            bits += 7
        else:
            out.append(acc)
            acc = 0
            bits = 0
    return out


def decode_cumulative_varints(byte_values: list[int], limit: Optional[int] = None) -> list[int]:
    out: list[int] = []
    total = 0
    acc = 0
    bits = 0
    for value in byte_values:
        acc += (value % 128) * (2**bits)
        if value >= 128:
            bits += 7
        else:
            total += acc
            out.append(total)
            acc = 0
            bits = 0
            if limit is not None and len(out) >= limit:
                break
    return out


def bxor_int(a: int, b: int) -> int:
    result = 0
    bit = 1
    while a > 0 or b > 0:
        aa = a % 2
        bb = b % 2
        if aa != bb:
            result += bit
        a = (a - aa) // 2
        b = (b - bb) // 2
        bit *= 2
    return result


def build_gk_map(gt_values: list[int], g5: int) -> dict[int, int]:
    i4 = 2147483647
    ew = [102, 96, 104, 83]
    es = [91694149, 836872680, 1374422365, 558404521]
    eu = 1152144892
    for idx in [0, 2, 1, 3]:
        eu = ((eu * 14684) + (bxor_int(es[idx], 1824232944) % i4) + 334493201) % i4
    ee: list[int] = []
    ez = eu
    ec = (eu + 59591) % i4
    for pos, value in enumerate(ew, start=1):
        et = ((ez % 256) + ((ec % 256) * 5) + pos * 2341 + 59591) % 256
        eo = bxor_int(value, et)
        ee.append(eo)
        ez = (bxor_int(ez, eo) + 59591 + (ec * 2341)) % i4
        ec = (((ec + value) * 24828) + 59591 + pos) % i4
    em = (((ee[3] * 256 + ee[2]) * 256 + ee[1]) * 256 + ee[0]) % i4
    if em == 0:
        em = 1
    seed = (bxor_int(em, g5) + 0x9E3779B9) % i4
    occupied: set[int] = set()
    gk: dict[int, int] = {}
    for value in gt_values:
        seed = (seed * 48271 + 1) % i4
        candidate = (seed % 65536) + 1
        probe = 0
        slot = candidate
        while slot in occupied:
            probe += 1
            if probe > 65536:
                for fallback in range(1, 65537):
                    if fallback not in occupied:
                        slot = fallback
                        break
                break
            slot = ((candidate - 1 + probe * probe) % 65536) + 1
        occupied.add(slot)
        gk[value] = slot
    return gk


def extract_base85_alphabet(source: str) -> Optional[str]:
    match = re.search(r"\bzQ\s*=\s*\"((?:\\.|[^\"\\])*)\"\s*for\s+zs\s*=\s*1\s*,\s*85\b", source, re.S)
    if not match:
        return None
    return parse_lua_string_bytes(match.group(1)).decode("latin1")


def decode_g3_map(g9: str, alphabet: str) -> dict[int, int]:
    lookup = {ord(ch): idx for idx, ch in enumerate(alphabet)}
    g3: dict[int, int] = {}
    pos = 0
    while pos < len(g9):
        chunk = g9[pos : pos + 5]
        if not chunk:
            break
        value = 0
        for ch in chunk:
            value = value * 85 + lookup.get(ord(ch), 0)
        pos += 5
        a = (value // 16777216) % 256
        b = (value // 65536) % 256
        c = (value // 256) % 256
        d = value % 256
        g3[a * 256 + b] = c * 256 + d
    return g3


def lz_bit_decompress(values: list[int], wanted: int) -> list[int]:
    out: list[int] = []
    src = 0
    while len(out) < wanted:
        if src >= len(values):
            break
        flags = values[src]
        src += 1
        for bit in range(8):
            if len(out) >= wanted:
                break
            literal = (flags % 2) == 1
            flags //= 2
            if literal:
                if src >= len(values):
                    break
                lo = values[src]
                hi = values[src + 1] if src + 1 < len(values) else 0
                src += 2
                high_nibble = hi // 16
                distance = high_nibble * 256 + lo
                if high_nibble == 15:
                    ext = values[src] if src < len(values) else 0
                    src += 1
                    distance = ext * 256 + lo
                low_nibble = hi - high_nibble * 16
                length = low_nibble + 3
                if low_nibble == 15:
                    extra = 0
                    while True:
                        ext = values[src] if src < len(values) else 0
                        src += 1
                        extra += ext
                        if ext != 255:
                            break
                    length = 18 + extra
                back = len(out) - (distance + 1)
                for offset in range(length):
                    if len(out) >= wanted:
                        break
                    if 0 <= back + offset < len(out):
                        out.append(out[back + offset])
                    else:
                        out.append(0)
            else:
                out.append(values[src] if src < len(values) else 0)
                src += 1
    return out


def extract_parser_base91_alphabet(source: str) -> Optional[str]:
    match = re.search(
        r"\blocal\s+Oz\s*=\s*\(function\(\)local\s+zq\s*=\s*\{\}local\s+zQ\s*=\s*\"((?:\\.|[^\"\\])*)\""
        r"\s*for\s+zs\s*=\s*1\s*,\s*91\b",
        source,
        re.S,
    )
    if not match:
        return None
    return parse_lua_string_bytes(match.group(1)).decode("latin1")


def decode_base91_with_alphabet(text: str, alphabet: str) -> list[int]:
    lookup = {ord(ch): index for index, ch in enumerate(alphabet)}
    out: list[int] = []
    pending = -1
    acc = 0
    bits = 0
    for ch in text:
        value = lookup.get(ord(ch))
        if value is None:
            continue
        if pending < 0:
            pending = value
            continue
        pending += value * 91
        acc += pending * (2**bits)
        bits += 13 if (pending % 8192) > 88 else 14
        while bits >= 8:
            out.append(acc % 256)
            acc //= 256
            bits -= 8
        pending = -1
    if pending >= 0:
        acc += pending * (2**bits)
        bits += 7
        while bits >= 8:
            out.append(acc % 256)
            acc //= 256
            bits -= 8
    return out


def build_rolling_cipher_constants() -> list[int]:
    encrypted = [
        143, 24, 208, 51, 90, 228, 25, 61, 196, 172, 240, 189, 1, 202, 6, 85,
        163, 46, 11, 94, 189, 29, 67, 213, 190, 112, 26, 236, 54, 51, 83, 135,
        231, 68, 129, 72, 156, 44, 247, 65, 105, 33, 136, 160, 55, 80, 52, 206,
        46, 253, 49, 195, 177, 231, 20, 20, 245, 98, 138, 73, 96, 194, 184, 15,
        247, 224, 198, 31,
    ]
    state = 1414912043
    for index in range(1, len(encrypted) + 1):
        state = ((state * 24492) + 1882184674 + (index * 19)) % 2147483647
        encrypted[index - 1] = (encrypted[index - 1] + 256 - (state % 256)) % 256
    return [
        sum(encrypted[offset + byte] << (byte * 8) for byte in range(4)) % M32
        for offset in range(0, len(encrypted), 4)
    ]


def rolling_cipher_decode(values: list[int], key: int) -> list[int]:
    modulus = 2147483647
    gx = build_rolling_cipher_constants()
    state = key
    ol = ((state % modulus) + ((len(values) % modulus) * gx[0]) + gx[1]) % modulus or 1
    oe = (((state % modulus) * gx[2]) + ((len(values) % modulus) * gx[3]) + gx[4]) % modulus or 1
    oo = (bxor_int(ol, oe) + ((state % modulus) * gx[5]) + gx[6]) % modulus or 1
    oc = ((oo * gx[7]) + bxor_int(((len(values) % modulus) + gx[8]) % modulus, ol) + gx[9]) % modulus or 1
    oh = ((oc * gx[10]) + (oe * gx[11]) + bxor_int(oo, gx[12]) + gx[13]) % modulus or 1
    out: list[int] = []

    for position, encrypted in enumerate(values, start=1):
        plain = bxor_int(encrypted, state % 256)
        out.append(plain)
        branch = (
            bxor_int(bxor_int(ol, (plain + gx[7]) % modulus), (position + gx[8]) % modulus) + gx[9]
        ) % 3
        if branch == 1:
            ol = ((bxor_int(ol, oc) * gx[6]) + (plain * gx[7]) + (position * gx[8]) + oo + gx[9]) % modulus or 1
            oe = ((oe * gx[14]) + (oe * gx[15]) + bxor_int(oc, (plain + position + gx[0]) % modulus) + gx[1]) % modulus or 1
            oo = ((oh * gx[10]) + bxor_int(oo, (oc + plain + gx[11]) % modulus) + (position * gx[12]) + gx[13]) % modulus or 1
            oc = (oc + bxor_int(ol, (position + gx[14]) % modulus) + (oh * gx[15]) + (plain * gx[0]) + gx[1]) % modulus or 1
            oe = ((oh * gx[2]) + bxor_int(oe, (oe + plain + gx[3]) % modulus) + (position * gx[4]) + gx[5]) % modulus or 1
            oh = ((bxor_int(oh, (plain + gx[2]) % modulus) * gx[3]) + bxor_int(oo, ol) + (position * gx[4]) + gx[5]) % modulus or 1
        elif branch == 2:
            oc = ((bxor_int(oc, (plain + gx[11]) % modulus) * gx[12]) + bxor_int(ol, oc) + (position * gx[13]) + gx[14]) % modulus or 1
            oo = (oo + bxor_int(oh, (position + gx[7]) % modulus) + (oo * gx[8]) + (plain * gx[9]) + gx[10]) % modulus or 1
            oe = (bxor_int(oe, (oh + gx[14]) % modulus) + (oe * gx[15]) + (plain * gx[0]) + position + gx[1]) % modulus or 1
            oh = ((oh * gx[15]) + (oo * gx[0]) + bxor_int(oh, (plain + position + gx[1]) % modulus) + gx[2]) % modulus or 1
            ol = (bxor_int(ol, (ol + gx[3]) % modulus) + (oc * gx[4]) + (plain * gx[5]) + position + gx[6]) % modulus or 1
            oe = (oe + bxor_int(ol, (position + gx[2]) % modulus) + (oe * gx[3]) + (plain * gx[4]) + gx[5]) % modulus or 1
        else:
            oo = ((bxor_int(oo, oh) * gx[13]) + (plain * gx[14]) + (position * gx[15]) + oh + gx[0]) % modulus or 1
            oh = ((oo * gx[5]) + bxor_int(oh, (oo + plain + gx[6]) % modulus) + (position * gx[7]) + gx[8]) % modulus or 1
            ol = ((ol * gx[9]) + bxor_int(oc, ((plain * gx[10]) + position) % modulus) + oc + gx[11]) % modulus or 1
            oe = ((bxor_int(oe, oc) * gx[2]) + (plain * gx[3]) + (position * gx[4]) + oe + gx[5]) % modulus or 1
            oe = ((bxor_int(oe, (plain + gx[14]) % modulus) * gx[15]) + bxor_int(oe, oo) + (position * gx[0]) + gx[1]) % modulus or 1
            oc = ((ol * gx[1]) + bxor_int(oc, (ol + plain + gx[2]) % modulus) + (position * gx[3]) + gx[4]) % modulus or 1

        skips = ((oh + bxor_int(oo, oo) + (oh * gx[12]) + (plain * gx[13]) + (position * gx[14]) + gx[6]) % modulus) % 3
        state = (state * 48271 + 81) % modulus
        if skips >= 1:
            state = (state * 48271 + 81) % modulus
        if skips >= 2:
            state = (state * 48271 + 81) % modulus
    return out


def build_final_vm_key_candidates() -> list[dict[str, int]]:
    modulus = 2147483647
    hc1 = [
        47, 172, 45, 38, 224, 243, 83, 180, 191, 244, 1, 16, 239, 0, 141, 84,
        26, 221, 202, 27, 246, 79, 163, 183, 2, 220, 132, 161, 180, 49, 200, 21,
    ]
    encrypted = [
        8, 19, 113, 53, 161, 147, 142, 111, 125, 175, 255, 154, 133, 167, 25, 124,
        39, 154, 3, 136, 9, 208, 3, 92, 116, 110, 13, 192, 233, 31, 43, 3,
        231, 19, 243, 0, 55, 37, 224, 247, 8, 147, 62, 232, 164, 26, 75, 224,
        61, 208, 98, 52, 164, 95, 240, 173, 231, 198, 49, 151, 91, 71, 22, 175,
        116, 11, 222, 190, 100, 202, 139, 204, 243, 33, 170, 232, 3, 167, 211, 210,
        232, 67, 162, 65, 101, 124, 187, 32, 116, 157, 1, 196, 177, 8, 70, 213,
        38, 11, 136, 61,
    ]
    state = 1509033022
    for index in range(1, len(encrypted) + 1):
        state = ((state * 33461) + 892747601 + (index * 164)) % modulus
        encrypted[index - 1] = (encrypted[index - 1] + 256 - (state % 256)) % 256
    h20 = [
        sum(encrypted[offset + byte] << (byte * 8) for byte in range(4)) % M32
        for offset in range(0, len(encrypted), 4)
    ]
    h3 = h20[:8]
    h4 = h20[8]
    for selected, mode in [(h3[7], 0), (h3[2], 1), (h3[5], 1), (h3[5], 2), (h3[0], 3), (h3[3], 1), (h3[3], 2), (h3[7], 2)]:
        if mode == 0:
            h4 = (((h4 + ((selected + h20[17]) % modulus) + h20[10]) * h20[9]) + h20[12]) % modulus
        elif mode == 1:
            extra_index = 18 if selected == h3[2] else (19 if selected == h3[5] else 22)
            h4 = (((h4 + h20[10]) * h20[9]) + (((selected + h20[extra_index]) % modulus) * h20[12])) % modulus
        elif mode == 2:
            tail = h20[20] if selected == h3[5] else (h20[23] if selected == h3[3] else h20[24])
            h4 = (h4 + ((selected + h20[10]) % modulus) * h20[9] + tail) % modulus
        else:
            h4 = ((h4 * h20[9]) + (bxor_int(selected, h20[11]) % modulus) + h20[21]) % modulus
    decoded: list[int] = []
    left = h4
    right = (h4 + h20[14]) % modulus
    for index, encrypted_byte in enumerate(hc1, start=1):
        value = bxor_int((left + h20[14] + index * ((h20[13] % 251) + 3)) % 256, (right + h20[15]) % 256) % 256
        value = bxor_int(encrypted_byte, value)
        decoded.append(value)
        left = (left + value * h20[13] + bxor_int(right, encrypted_byte) + h20[14]) % modulus
        right = (((right + value + index) * ((h20[15] % 60000) + 257)) + encrypted_byte) % modulus

    def u32(position: int) -> int:
        return sum(decoded[position - 1 + byte] << (byte * 8) for byte in range(4)) % modulus

    expected, h11, h13, h12, h14, h19, h18, h10 = [u32(position) for position in (1, 5, 9, 13, 17, 21, 25, 29)]
    check = (bxor_int(h10, h11) + bxor_int(h12, h13) + bxor_int(h14, h20[16]) + bxor_int(h18, h20[11]) + bxor_int(h19, h20[15])) % modulus
    if check != expected:
        h10 = (h10 + 1) % modulus
    a2_base = (bxor_int(h10, h11) + h12) % modulus
    a2_extra = (447 + (22 * 7) + (597 % 97)) % modulus

    def a2(value: int) -> int:
        return ((bxor_int(a2_base, (value * 40503) % modulus) + a2_extra) % modulus * 48271) % modulus

    hc17 = a2(h13) % modulus or 1
    g4 = 1618920062
    candidates: list[dict[str, int]] = []
    for vector_available in (0, 1):
        vector_fingerprint = 476010 if vector_available else 0
        for debug_line in (0, 1):
            for game_userdata in (0, 1):
                for instance_function in (0, 1):
                    for players_userdata in (0, 1):
                        fingerprint = g4 % modulus
                        fingerprint = (fingerprint * 48271 + debug_line + 81) % modulus
                        fingerprint = (fingerprint * 48271 + game_userdata * 11 + 81) % modulus
                        fingerprint = (fingerprint * 48271 + instance_function * 17 + 81) % modulus
                        fingerprint = (fingerprint * 48271 + players_userdata * 23 + 81) % modulus
                        if not (game_userdata and instance_function and players_userdata and vector_available):
                            fallback = (
                                (g4 * 48271)
                                + (game_userdata * 17)
                                + (instance_function * 31)
                                + (players_userdata * 43)
                                + vector_fingerprint
                                + 97
                            ) % modulus or 1
                            fingerprint = (fingerprint + fallback) % modulus
                        fingerprint = (fingerprint * 48271 + vector_fingerprint + 81) % modulus or 1
                        intermediate = a2(bxor_int(hc17, h14) % modulus) % modulus or 1
                        mixed = bxor_int(bxor_int(hc17, intermediate), fingerprint) % modulus
                        key = a2(mixed) % modulus
                        if key % 256 == 0:
                            key += 1
                        candidates.append(
                            {
                                "debug_line": debug_line,
                                "vector_available": vector_available,
                                "game_userdata": game_userdata,
                                "instance_function": instance_function,
                                "players_userdata": players_userdata,
                                "fingerprint": fingerprint,
                                "key": key,
                            }
                        )
    return candidates


def recover_final_vm_stream(values: list[int]) -> tuple[list[int], dict[str, int]]:
    for candidate in build_final_vm_key_candidates():
        decoded = rolling_cipher_decode(values, candidate["key"])
        if len(decoded) < 5 or decoded[:3] != [85, 27, 53] or decoded[3] not in range(50, 56):
            continue
        expected_marker = (candidate["fingerprint"] % 251) + 1
        if decoded[4] == expected_marker:
            return decoded, candidate
    raise ValueError("could not derive a valid final VM key from the Roblox persona candidates")


def decode_base85_bytes(values: list[int], alphabet: str) -> str:
    out: list[str] = []
    full = len(values) // 4
    for group in range(full):
        offset = group * 4
        packed = (
            values[offset] * 16777216
            + values[offset + 1] * 65536
            + values[offset + 2] * 256
            + values[offset + 3]
        )
        digits = [0] * 5
        for index in range(4, -1, -1):
            digits[index] = packed % 85
            packed //= 85
        out.extend(alphabet[index] for index in digits)
    remainder = len(values) - full * 4
    if remainder:
        packed = 0
        offset = full * 4
        for index in range(4):
            packed = packed * 256 + (values[offset + index] if index < remainder else 0)
        digits = [0] * 5
        for index in range(4, -1, -1):
            digits[index] = packed % 85
            packed //= 85
        out.extend(alphabet[index] for index in digits[: remainder + 1])
    return "".join(out)


def parse_mode52_prototypes(values: list[int], base85_alphabet: str) -> dict[str, object]:
    if len(values) < 6 or values[:3] != [85, 27, 53] or values[3] != 52:
        raise ValueError("final VM stream is not a mode-52 prototype bundle")
    position = 5
    virtual_zero_reads = 0

    def byte() -> int:
        nonlocal position, virtual_zero_reads
        value = values[position] if position < len(values) else 0
        if position >= len(values):
            virtual_zero_reads += 1
        position += 1
        return value

    def varint() -> int:
        result = 0
        factor = 1
        while True:
            value = byte()
            result += (value % 128) * factor
            if value < 128:
                return result
            factor *= 128

    count = varint()
    prototypes: list[dict[str, object]] = []
    for prototype_id in range(count):
        instruction_count = varint()
        first_line = varint()
        bytecode_id = varint()
        flags = varint()
        integrity_token = varint()
        capture_count = varint()
        capture_slots: list[int] = []
        capture_slot = 0
        for _ in range(capture_count):
            capture_slot += varint()
            capture_slots.append(capture_slot)

        opcodes = [byte() for _ in range(instruction_count)]
        upvalues = [{"from_parent": byte() == 1, "index": byte()} for _ in range(byte())]
        instruction_capsule_size = varint()
        # Mode 52 deliberately advertises oversized capsules and relies on nil
        # table reads becoming zero. Only ceil(instruction_count * 8 / 5)
        # packed groups can affect the instruction stream used by the VM.
        useful_packed_bytes = min(
            instruction_capsule_size,
            ((instruction_count * 8 + 4) // 5) * 4,
        )
        instruction_capsule = decode_base85_bytes(
            [byte() for _ in range(useful_packed_bytes)],
            base85_alphabet,
        )[: instruction_count * 8]
        position += instruction_capsule_size - useful_packed_bytes

        line_entry_count = varint()
        line_pcs: list[int] = []
        line_pc = 0
        for _ in range(line_entry_count):
            line_pc += varint()
            line_pcs.append(line_pc)
        line_values = [varint() for _ in range(line_entry_count)]
        line_flags = [byte() for _ in range(line_entry_count)]

        instruction_offsets: list[int] = []
        offset = 0
        for _ in range(instruction_count):
            offset += varint()
            instruction_offsets.append(offset)
        edge_count = varint()
        edges: dict[int, int] = {}
        edge_pc = 0
        edge_target = 0
        for _ in range(edge_count):
            edge_pc += varint()
            edge_target += varint()
            edges[edge_pc] = edge_target
        stack_size = byte()
        parameter_count = byte()
        is_vararg = byte() == 1

        sparse_count = varint()
        sparse_map = {varint(): varint() for _ in range(sparse_count)}
        remap_count = varint()
        remap: dict[int, int] = {}
        remap_base_key = 5231 + ((4327 + prototype_id * 211) % 8209)
        remap_base_value = 7411 + ((1153 + prototype_id * 397) % 12301)
        key_bias = 23 + ((3319490523 + prototype_id * 149 + 37) % 1009)
        value_bias = 43 + (((975476772 // 1009) + prototype_id * 269 + 83) % 1013)
        encoded_key_base = remap_base_key + key_bias
        encoded_value_base = remap_base_value + value_bias
        target_bias = 1301 + ((2738 + prototype_id * 337) % 4093)
        target_mix = (2147 + prototype_id * 211 + 977) % 4099
        for _ in range(remap_count):
            encoded_key = varint()
            encoded_value = varint()
            decoded_key = encoded_key - encoded_key_base
            decoded_value = encoded_value - encoded_value_base
            decoded_value -= target_bias + (((decoded_key * 37) + target_mix) % 4099)
            remap[decoded_key] = decoded_value

        prototypes.append(
            {
                "id": prototype_id,
                "instruction_count": instruction_count,
                "first_line": first_line,
                "bytecode_id": bytecode_id,
                "flags": flags,
                "integrity_token": integrity_token,
                "capture_slots": capture_slots,
                "opcodes": opcodes,
                "upvalues": upvalues,
                "instruction_capsule_size": instruction_capsule_size,
                "instruction_capsule": instruction_capsule,
                "line_pcs": line_pcs,
                "line_values": line_values,
                "line_flags": line_flags,
                "instruction_offsets": instruction_offsets,
                "edges": edges,
                "stack_size": stack_size,
                "parameter_count": parameter_count,
                "is_vararg": is_vararg,
                "sparse_map": sparse_map,
                "remap": remap,
            }
        )
    return {
        "magic": values[:3],
        "mode": values[3],
        "fingerprint_marker": values[4],
        "prototype_count": count,
        "cursor_position": position,
        "physical_bytes_consumed": min(position, len(values)),
        "virtual_zero_reads": virtual_zero_reads,
        "stream_bytes": len(values),
        "trailing_bytes": max(0, len(values) - position),
        "prototypes": prototypes,
    }


def ch_integrity_values() -> list[int]:
    ch = [137, 219, 111, 9, 0, 118, 203, 102, 74, 25, 101, 202]
    cu = 1582520166
    for idx in range(len(ch)):
        cu = ((cu * 49512) + 1154301203 + ((idx + 1) * 17)) % 2147483647
        ch[idx] = bxor_int(ch[idx], cu % 256)
    out: list[int] = []
    for base in [0, 4, 8]:
        out.append(((((ch[base + 3] * 256 + ch[base + 2]) * 256 + ch[base + 1]) * 256 + ch[base]) % M32))
    return out


def decode_constant_bank(stream: list[int], offsets: list[int], c9_key: int) -> dict[int, str]:
    integrity = ch_integrity_values()

    def get(pos: int) -> int:
        if 1 <= pos <= len(stream):
            return stream[pos - 1]
        return 0

    def u32(pos: int) -> int:
        return get(pos) + get(pos + 1) * 256 + get(pos + 2) * 65536 + get(pos + 3) * 16777216

    constants: dict[int, str] = {}
    for wp, offset in enumerate(offsets, start=1):
        size = u32(offset)
        if size < 0 or size > 100000:
            continue
        q_u = (c9_key + (wp * 257) + (size * 131) + (integrity[0] % 65536) + (integrity[1] % 65536) + 21417) % M32
        q_u = ((q_u * 1664525) + 1013904223 + (wp * 40503) + (size * 11117)) % M32
        if q_u == 0:
            q_u = (c9_key + 1) % M32
        pos = offset + 4
        raw = bytearray()
        for index in range(1, size + 1):
            encrypted = get(pos)
            pos += 1
            q_u = ((q_u * 1664525) + 1013904223 + (wp * 257) + (index * 131) + (size * 17) + 1831565813) % M32
            qj = q_u % 256
            qv = ((q_u - qj) // 256) % 256
            qr = ((q_u - (q_u % 65536)) // 65536) % 256
            qy = ((q_u - (q_u % 16777216)) // 16777216) % 256
            key = bxor_int(bxor_int(qj, (qv + index) % 256), bxor_int(qr, (qy + wp + size) % 256))
            raw.append(bxor_int(encrypted, key) & 0xFF)
        constants[wp] = raw.decode("latin1")
    return constants


def replace_constant_lookups(source: str, constants: dict[int, str], q7_values: Optional[list[int]] = None) -> str:
    def decode_expr(expr: str) -> Optional[int]:
        if q7_values:
            def repl_q7(match: re.Match[str]) -> str:
                q7_index = safe_eval_int(match.group(1))
                if not (1 <= q7_index <= len(q7_values)):
                    raise ValueError(f"q7 index out of range: {q7_index}")
                return str(q7_values[q7_index - 1])

            expr = re.sub(r"q7\[((?:[^\[\]]|\([^()]*\))+)\]", repl_q7, expr)
        try:
            return safe_eval_int(expr)
        except Exception:
            return None

    def skip_short_string(pos: int) -> int:
        quote = source[pos]
        pos += 1
        while pos < len(source):
            if source[pos] == "\\":
                pos += 2
                continue
            if source[pos] == quote:
                return pos + 1
            pos += 1
        return pos

    def skip_long_bracket(pos: int) -> Optional[int]:
        if source[pos] != "[":
            return None
        end = pos + 1
        while end < len(source) and source[end] == "=":
            end += 1
        if end >= len(source) or source[end] != "[":
            return None
        close = "]" + ("=" * (end - pos - 1)) + "]"
        found = source.find(close, end + 1)
        return len(source) if found < 0 else found + len(close)

    def parse_call(pos: int) -> Optional[tuple[str, int]]:
        if pos >= len(source) or source[pos] != "(":
            return None
        depth = 1
        start = pos + 1
        pos += 1
        while pos < len(source):
            ch = source[pos]
            if ch == '"' or ch == "'":
                pos = skip_short_string(pos)
                continue
            if ch == "[":
                skipped = skip_long_bracket(pos)
                if skipped is not None:
                    pos = skipped
                    continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return source[start:pos], pos + 1
            pos += 1
        return None

    def split_top_level_comma(text: str) -> Optional[tuple[str, str]]:
        depth = 0
        pos = 0
        while pos < len(text):
            ch = text[pos]
            if ch == '"' or ch == "'":
                quote = ch
                pos += 1
                while pos < len(text):
                    if text[pos] == "\\":
                        pos += 2
                        continue
                    if text[pos] == quote:
                        break
                    pos += 1
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                return text[:pos], text[pos + 1 :]
            pos += 1
        return None

    def trailing_guard(end: int) -> int:
        match = re.match(r"\s*and\s*qQ\s*or\s*nil", source[end:])
        return end + match.end() if match else end

    def decode_call(start: int, call_open: int) -> Optional[tuple[int, str]]:
        parsed = parse_call(call_open)
        if parsed is None:
            return None
        args, end = parsed
        parts = split_top_level_comma(args)
        if parts is None:
            return None
        expr, second = parts
        if second.strip() != "zh":
            return None
        index = decode_expr(expr.strip())
        if index is None or index not in constants:
            return None
        return trailing_guard(end), lua_quote(constants[index])

    out: list[str] = []
    last = 0
    pos = 0
    while pos < len(source):
        ch = source[pos]
        if ch == '"' or ch == "'":
            pos = skip_short_string(pos)
            continue
        if ch == "[":
            skipped = skip_long_bracket(pos)
            if skipped is not None:
                pos = skipped
                continue
        if source.startswith("--", pos):
            end = source.find("\n", pos + 2)
            pos = len(source) if end < 0 else end + 1
            continue

        replacement: Optional[tuple[int, str]] = None
        if source.startswith("B(", pos) and (pos == 0 or not (source[pos - 1].isalnum() or source[pos - 1] == "_")):
            replacement = decode_call(pos, pos + 1)
        elif source.startswith("at[(60696)](", pos):
            replacement = decode_call(pos, pos + len("at[(60696)]"))
        elif source.startswith("at[60696](", pos):
            replacement = decode_call(pos, pos + len("at[60696]"))

        if replacement is None:
            pos += 1
            continue

        end, text = replacement
        out.append(source[last:pos])
        out.append(text)
        last = end
        pos = end

    out.append(source[last:])
    return "".join(out)


def resolve_map_indexes(source: str, gk: dict[int, int], g3: dict[int, int]) -> str:
    def repl_g3(match: re.Match[str]) -> str:
        value = int(match.group(1))
        return f"({g3.get(value, value)})"

    def repl_gk(match: re.Match[str]) -> str:
        value = int(match.group(1))
        return f"({gk.get(value, value)})"

    # Resolve inner g3 first, then the gK that commonly wraps it.
    out = re.sub(r"g3\[\(?(\d+)\)?\]", repl_g3, source)
    out = re.sub(r"gK\[\(?(\d+)\)?\]", repl_gk, out)
    return out


def build_runtime_probe(
    source: str,
    *,
    capture_environment: bool = False,
    capture_fingerprint_details: bool = False,
    separate_shared_global: bool = False,
    force_global_environment: bool = False,
    force_roblox_fingerprint: bool = False,
    capture_patch_key: bool = False,
    capture_vm_registers: bool = False,
    capture_fail_traps: bool = False,
) -> str:
    entry = "return(function"
    if source.count(entry) < 1:
        raise ValueError("could not find the wYnFuscate outer entry point")
    prefix = (
        "local __WYN_CAPTURE=__rbx_capture_text;"
        "local __WYN_TOSTRING=tostring;"
        "local __WYN_TYPE=type;"
        "local __WYN_RAWGET=rawget;"
        "local __WYN_CONCAT=table.concat;"
        "local __WYN_PAIRS=pairs;"
        "local __WYN_ERROR=error;"
        "local __WYN_TRACEBACK=debug and debug.traceback;"
        "local __WYN_GLOBAL=_G;"
    )
    if separate_shared_global:
        prefix += "_G={};"
    result = source.replace(entry, prefix + entry, 1)

    environment_pattern = re.compile(
        r"local S1=\(function\(\)local S3=\{\}local S9=.*?return S6 end\)\(\)",
        re.S,
    )
    environment_match = environment_pattern.search(result)
    if (capture_environment or force_global_environment) and not environment_match:
        raise ValueError("could not find the captured S1 environment")
    if environment_match:
        additions = ""
        if force_global_environment:
            additions += "S1=__WYN_GLOBAL or S1;"
        if capture_environment:
            additions += (
                "do local __g=__WYN_RAWGET(S1,'game');"
                "local __i=__WYN_RAWGET(S1,'Instance');"
                "local __v=__WYN_RAWGET(S1,'Vector3int16');"
                "local __pok,__p=pcall(function()return __g and __g:GetService('Players')end);"
                "local __vok,__vv=pcall(function()return __v and __v.new(1,2,3)end);"
                "__WYN_CAPTURE('wyn_environment',__WYN_CONCAT({"
                "__WYN_TYPE(S1),__WYN_TOSTRING(S1==__WYN_GLOBAL),"
                "__WYN_TYPE(__g),__WYN_TYPE(__i),__WYN_TYPE(__i and __i.new),"
                "__WYN_TOSTRING(__pok),__WYN_TYPE(__p),"
                "__WYN_TOSTRING(__vok),__WYN_TYPE(__vv),"
                "__WYN_TOSTRING(__vv and __vv.X),__WYN_TOSTRING(__vv and __vv.Y),"
                "__WYN_TOSTRING(__vv and __vv.Z)},':'),'.txt');end;"
            )
        insertion = environment_match.end()
        result = result[:insertion] + additions + result[insertion:]

    if capture_fingerprint_details:
        bootstrap_marker = "mT=(mT+W7)%mc if W7~=0 then mq=mq+1 end"
        if result.count(bootstrap_marker) != 1:
            raise ValueError("could not uniquely find the initial Roblox persona checksum")
        bootstrap_capture = (
            bootstrap_marker
            + ";__WYN_CAPTURE('wyn_bootstrap_persona',__WYN_CONCAT({"
            "'Mg='..__WYN_TOSTRING(Mg),'Mm='..__WYN_TOSTRING(Mm),"
            "'MW='..__WYN_TOSTRING(MW),'MM='..__WYN_TOSTRING(MM),"
            "'Ww='..__WYN_TOSTRING(Ww),'W8='..__WYN_TOSTRING(W8),"
            "'W7='..__WYN_TOSTRING(W7),'mT='..__WYN_TOSTRING(mT),"
            "'game='..__WYN_TYPE(Wc)..':'..__WYN_TOSTRING(Wc and Wc.ClassName),"
            "'instance='..__WYN_TYPE(WH)..':'..__WYN_TYPE(WH and WH.new),"
            "'vector='..__WYN_TYPE(Wi),"
            "'type='..__WYN_TOSTRING(W4)},'|'),'.txt')"
        )
        result = result.replace(bootstrap_marker, bootstrap_capture, 1)

        checkpoint_markers = [
            ("shape", "do local MU=0 local Mc=me"),
            ("basic_debug", "do local MR=0 local MP=0"),
            ("deep_debug", "local k9=WD(Wv,"),
            ("dump_checks", "g2(mw,((164)*(2)+(1)),"),
            ("structure_noise", "local wM=WD(Wv,"),
            ("metatable", "local wH=(function()"),
            ("executor_scan", "g2(a1,((136)*(4)+(3)),"),
            ("helper_map", "local SE=(function()"),
            ("native_functions", "local Si=(function()"),
            ("getfenv_upvalues", "do local SK=0"),
            ("identity", "local S1=(function()"),
        ]
        for label, marker in checkpoint_markers:
            if result.count(marker) != 1:
                raise ValueError(f"could not uniquely find anti-debug checkpoint: {label}")
            capture = (
                f"__WYN_CAPTURE('wyn_checkpoint_{label}',"
                f"__WYN_TOSTRING(mT)..':'..__WYN_TOSTRING(mq)..':'.."
                f"__WYN_TOSTRING(mz),'.txt');"
            )
            result = result.replace(marker, capture + marker, 1)

    if force_roblox_fingerprint or capture_fingerprint_details:
        fingerprint_marker = "a3[0x25]=uZ end"
        if result.count(fingerprint_marker) != 1:
            raise ValueError("could not uniquely find the Roblox fingerprint assignment")
        fingerprint_value = "1756835848" if force_roblox_fingerprint else "uZ"
        fingerprint_capture = ""
        if capture_fingerprint_details:
            fingerprint_capture = (
                ";do local __tf=(a1[g0(226,g5,5)]or mn or type);"
                "__WYN_CAPTURE('wyn_fingerprint_details',__WYN_CONCAT({"
                "'debug='..__WYN_TOSTRING(uG),"
                "'decoder_state='..__WYN_TOSTRING(mT)..','..__WYN_TOSTRING(mq),"
                "'lookup_names='..mE(84,((85*3846+152*6349-1243745)%mO))..','.."
                "mE(98,((70*3846+142*6349-1136412)%mO))..','.."
                "mE(102,((54*3846+80*6349-665250)%mO))..','.."
                "mE(76,((81*3846+92*6349-873957)%mO))..','.."
                "mE(104,((54*3846+112*6349-860220)%mO)),"
                "'u1_native='..__WYN_TYPE(u1),'u1_vm='..__WYN_TOSTRING(__tf(u1)),"
                "'table_vm='..__WYN_TOSTRING(__tf({})),'u1='..__WYN_TOSTRING(u1),"
                "'u3_native='..__WYN_TYPE(u3),'new_native='..__WYN_TYPE(u3 and u3.new),"
                "'new_vm='..__WYN_TOSTRING(__tf(u3 and u3.new)),"
                "'getservice_native='..__WYN_TYPE(u9),"
                "'players_ok='..__WYN_TOSTRING(uX),'players_native='..__WYN_TYPE(u6),"
                "'players_vm='..__WYN_TOSTRING(__tf(u6)),"
                "'vector_ctor_native='..__WYN_TYPE(uy),"
                "'vector_ok='..__WYN_TOSTRING(uX),'vector_native='..__WYN_TYPE(up),"
                "'vector_xyz='..__WYN_TOSTRING(up and up.X)..','.."
                "__WYN_TOSTRING(up and up.Y)..','..__WYN_TOSTRING(up and up.Z),"
                "'flags='..__WYN_TOSTRING(ud)..','..__WYN_TOSTRING(uK)..','.."
                "__WYN_TOSTRING(ut)..','..__WYN_TOSTRING(uF),"
                "'vector_hash='..__WYN_TOSTRING(ux),'fingerprint='..__WYN_TOSTRING(uZ),"
                "'type_helper_is_native='..__WYN_TOSTRING(__tf==mn)},'|'),'.txt');end"
            )
        result = result.replace(
            fingerprint_marker,
            f"a3[0x25]={fingerprint_value}{fingerprint_capture} end",
            1,
        )

    if capture_patch_key:
        patch_marker = "end)()do local Uo"
        if result.count(patch_marker) != 1:
            raise ValueError("could not uniquely find the authenticated patch-loader boundary")
        wrapper = (
            "end)();local __WYN_PATCH_LOADER=at[gK[24496]];"
            "at[gK[24496]]=function(iF,iZ)"
            "__WYN_CAPTURE('wyn_patch_key',__WYN_CONCAT({__WYN_TOSTRING(iF),"
            "__WYN_TYPE(iZ),__WYN_TOSTRING(iZ)},':'),'.txt');"
            "return __WYN_PATCH_LOADER(iF,iZ)end;do local Uo"
        )
        result = result.replace(patch_marker, wrapper, 1)

    if capture_vm_registers:
        vm_marker = "local vI=true while vI do if VK>ca then"
        if result.count(vm_marker) != 1:
            raise ValueError("could not uniquely find the main VM dispatch loop")
        vm_probe = (
            "local __WYN_VM_SEEN={};local __WYN_VM_STRING_COUNT=0;"
            "local __WYN_VM_ITER=0;local __WYN_VM_LAST_PC=-1;local __WYN_VM_SAME_PC=0;"
            "local vI=true while vI do __WYN_VM_ITER=__WYN_VM_ITER+1;"
            "if VK==__WYN_VM_LAST_PC then __WYN_VM_SAME_PC=__WYN_VM_SAME_PC+1 "
            "else __WYN_VM_LAST_PC=VK;__WYN_VM_SAME_PC=0 end;"
            "if __WYN_VM_ITER==1 or __WYN_VM_ITER%64==0 then "
            "for __rk,__rv in __WYN_PAIRS(YL)do "
            "if __WYN_TYPE(__rv)=='string' and #__rv>=16 and #__rv<=128 and "
            "not __WYN_VM_SEEN[__rv] and __WYN_VM_STRING_COUNT<300 then "
            "__WYN_VM_SEEN[__rv]=true;__WYN_VM_STRING_COUNT=__WYN_VM_STRING_COUNT+1;"
            "__WYN_CAPTURE((#__rv==64 and 'wyn_vm_string64' or 'wyn_vm_string'),"
            "__WYN_TOSTRING(__rk)..':'..__WYN_TOSTRING(VK)..':'..__rv,'.bin')end end end;"
            "if __WYN_VM_ITER==1 or __WYN_VM_ITER==1000 or __WYN_VM_ITER==10000 or "
            "__WYN_VM_ITER==100000 or __WYN_VM_ITER==1000000 or "
            "__WYN_VM_SAME_PC==100000 then "
            "__WYN_CAPTURE('wyn_vm_progress',__WYN_CONCAT({__WYN_TOSTRING(__WYN_VM_ITER),"
            "__WYN_TOSTRING(VK),__WYN_TOSTRING(ca),__WYN_TOSTRING(__WYN_VM_SAME_PC),"
            "__WYN_TOSTRING(s3[5431]or 0)},':'),'.txt')end;"
            "if VK>ca then"
        )
        result = result.replace(vm_marker, vm_probe, 1)

    if capture_fail_traps:
        trap_body = "function(IL)repeat IL=(IL*48271+1)%IY if IL==0 then IL=1 end until IL==0 end"
        trap_count = result.count(trap_body)
        if trap_count < 1:
            raise ValueError("could not find a wYnFuscate fail loop")
        trap_probe = (
            "function(IL)local __tb='';"
            "if __WYN_TRACEBACK then local __ok,__value=pcall(__WYN_TRACEBACK);"
            "if __ok and __value then __tb=__value end end;"
            "__WYN_CAPTURE('wyn_fail_trap',__WYN_TOSTRING(IL)..'\\n'..__tb,'.txt');"
            "return __WYN_ERROR('wYnFuscate fail trap '..__WYN_TOSTRING(IL),0)end"
        )
        result = result.replace(trap_body, trap_probe)
    return result


def deobfuscate(input_path: Path, out_root: Path, c9_key: Optional[int] = None) -> dict[str, object]:
    source = input_path.read_text(encoding="utf-8", errors="replace")
    stamp = time.strftime("%Y%m%d_%H%M%S")
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", input_path.stem).strip("_") or "script"
    out_dir = out_root / f"{name}_{stamp}_{time.time_ns() % 1000000000:09d}"
    out_dir.mkdir(parents=True, exist_ok=True)

    decoder = WynStringDecoder(source)
    resolved, decoded = replace_string_resolver(source, decoder)

    id_map = extract_id_map(resolved)
    gt_text = extract_lua_string(resolved, "gt")
    g9_text = extract_lua_string(resolved, "g9", last=True)
    g5 = ((65 * 3846 + 107 * 6349 - 887861) % M32)
    gt_bytes = decode_base91_payload(gt_text or "", id_map) if id_map and gt_text is not None else []
    gt_values = decode_varints(gt_bytes)
    gk_map = build_gk_map(gt_values, g5) if gt_values else {}
    base85_alphabet = extract_base85_alphabet(resolved)
    g3_map = decode_g3_map(g9_text or "", base85_alphabet) if g9_text is not None and base85_alphabet else {}
    resolved_maps = resolve_map_indexes(resolved, gk_map, g3_map) if gk_map or g3_map else resolved

    ar_text = extract_lua_string(resolved, "ar")
    vm_stream = []
    vm_offsets = []
    q7_stream = []
    q7_values = []
    main_vm_payload_bytes = []
    if ar_text and id_map:
        vm_stream = lz_bit_decompress(decode_base91_payload(ar_text[:3772], id_map), 3249)
        vm_offsets = decode_cumulative_varints(decode_base91_payload(ar_text[3772:4077], id_map), 248)
        q7_stream = lz_bit_decompress(decode_base91_payload(ar_text[4077:4648], id_map), 724)
        q7_values = decode_varints(q7_stream)
        main_vm_payload_bytes = decode_base91_payload(ar_text[4648:6159], id_map)
    constants = decode_constant_bank(vm_stream, vm_offsets, c9_key) if c9_key is not None and vm_stream and vm_offsets else {}
    resolved_constants = replace_constant_lookups(resolved_maps, constants, q7_values) if constants else resolved_maps

    unique = sorted({str(item["value"]) for item in decoded})
    stage1 = out_dir / "stage1_resolved_strings.luau"
    stage2 = out_dir / "stage2_resolved_map_indexes.luau"
    stage3 = out_dir / "stage3_resolved_constants.luau"
    strings_path = out_dir / "decoded_strings.txt"
    mi_path = out_dir / "wyn_md_stream.bin"
    maps_path = out_dir / "decoded_maps.json"
    vm_stream_path = out_dir / "vm_stream_3249.bin"
    vm_offsets_path = out_dir / "vm_offsets.json"
    q7_stream_path = out_dir / "q7_stream_724.bin"
    q7_values_path = out_dir / "q7_values.json"
    main_vm_payload_path = out_dir / "main_vm_payload_base91.bin"
    constants_path = out_dir / "decoded_vm_constants.json"
    constants_text_path = out_dir / "decoded_vm_constants.txt"
    report_path = out_dir / "wynfuscate_deobfuscation_report.json"

    stage1.write_text(resolved, encoding="utf-8", errors="replace")
    stage2.write_text(resolved_maps, encoding="utf-8", errors="replace")
    if constants:
        stage3.write_text(resolved_constants, encoding="utf-8", errors="replace")
    strings_path.write_text("\n".join(unique) + "\n", encoding="utf-8", errors="replace")
    mi_path.write_bytes(decoder.mI)
    maps_path.write_text(
        json.dumps(
            {
                "gt_byte_count": len(gt_bytes),
                "gt_value_count": len(gt_values),
                "gk_count": len(gk_map),
                "g3_count": len(g3_map),
                "gk": {str(k): v for k, v in sorted(gk_map.items())},
                "g3": {str(k): v for k, v in sorted(g3_map.items())},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    if vm_stream:
        vm_stream_path.write_bytes(bytes(vm_stream))
    if vm_offsets:
        vm_offsets_path.write_text(json.dumps(vm_offsets, indent=2), encoding="utf-8")
    if q7_stream:
        q7_stream_path.write_bytes(bytes(q7_stream))
    if q7_values:
        q7_values_path.write_text(json.dumps(q7_values, indent=2), encoding="utf-8")
    if main_vm_payload_bytes:
        main_vm_payload_path.write_bytes(bytes(main_vm_payload_bytes))
    if constants:
        constants_path.write_text(json.dumps({str(k): v for k, v in sorted(constants.items())}, indent=2), encoding="utf-8")
        lines = []
        for key, value in sorted(constants.items()):
            printable = "".join(ch if 32 <= ord(ch) < 127 else f"\\x{ord(ch):02x}" for ch in value)
            lines.append(f"{key:03d} len={len(value):03d} {printable}")
        constants_text_path.write_text("\n".join(lines) + "\n", encoding="utf-8", errors="replace")

    report = {
        "input": str(input_path),
        "input_sha256": hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest(),
        "output_dir": str(out_dir),
        "stage1_source": str(stage1),
        "stage2_source": str(stage2),
        "stage3_source": str(stage3) if constants else None,
        "decoded_strings_path": str(strings_path),
        "md_stream_path": str(mi_path),
        "decoded_maps_path": str(maps_path),
        "vm_stream_path": str(vm_stream_path) if vm_stream else None,
        "vm_offsets_path": str(vm_offsets_path) if vm_offsets else None,
        "q7_stream_path": str(q7_stream_path) if q7_stream else None,
        "q7_values_path": str(q7_values_path) if q7_values else None,
        "main_vm_payload_path": str(main_vm_payload_path) if main_vm_payload_bytes else None,
        "decoded_constants_path": str(constants_path) if constants else None,
        "decoded_constants_text_path": str(constants_text_path) if constants else None,
        "c9_key": c9_key,
        "decoded_call_count": len(decoded),
        "unique_decoded_strings": len(unique),
        "md_stream_bytes": len(decoder.mI),
        "gt_values": len(gt_values),
        "gk_entries": len(gk_map),
        "g3_entries": len(g3_map),
        "vm_stream_bytes": len(vm_stream),
        "vm_offsets": len(vm_offsets),
        "q7_stream_bytes": len(q7_stream),
        "q7_values": len(q7_values),
        "main_vm_payload_bytes": len(main_vm_payload_bytes),
        "decoded_constants": len(constants),
        "exact_recovery_status": "not_recovered",
        "notes": [
            "Resolved the deterministic wYnFuscate mE string table.",
            "Decoded the custom Base91 gt stream, randomized gK map, Base85 g3 map, and first compressed VM byte stream when present.",
            "The sample still contains VM/control-flow machinery; no exact original source text was exposed by this pass.",
        ],
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Static first-pass deobfuscator for this wYnFuscate Luau family.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--out-root", type=Path, default=Path("outputs/wynfuscate_deobf"))
    parser.add_argument("--c9-key", type=lambda value: int(value, 0), default=None)
    parser.add_argument("--emit-runtime-probe", type=Path)
    parser.add_argument("--probe-capture-environment", action="store_true")
    parser.add_argument("--probe-capture-fingerprint-details", action="store_true")
    parser.add_argument("--probe-separate-shared-global", action="store_true")
    parser.add_argument("--probe-force-global-environment", action="store_true")
    parser.add_argument("--probe-force-roblox-fingerprint", action="store_true")
    parser.add_argument("--probe-capture-patch-key", action="store_true")
    parser.add_argument("--probe-capture-vm-registers", action="store_true")
    parser.add_argument("--probe-capture-fail-traps", action="store_true")
    args = parser.parse_args()
    if args.emit_runtime_probe:
        source = args.input.read_text(encoding="utf-8", errors="replace")
        probe = build_runtime_probe(
            source,
            capture_environment=args.probe_capture_environment,
            capture_fingerprint_details=args.probe_capture_fingerprint_details,
            separate_shared_global=args.probe_separate_shared_global,
            force_global_environment=args.probe_force_global_environment,
            force_roblox_fingerprint=args.probe_force_roblox_fingerprint,
            capture_patch_key=args.probe_capture_patch_key,
            capture_vm_registers=args.probe_capture_vm_registers,
            capture_fail_traps=args.probe_capture_fail_traps,
        )
        args.emit_runtime_probe.parent.mkdir(parents=True, exist_ok=True)
        args.emit_runtime_probe.write_text(probe, encoding="utf-8", errors="replace")
        print(f"Runtime probe: {args.emit_runtime_probe}")
        return 0
    report = deobfuscate(args.input, args.out_root, c9_key=args.c9_key)
    print(f"Stage 1: {report['stage1_source']}")
    print(f"Stage 2: {report['stage2_source']}")
    if report.get("stage3_source"):
        print(f"Stage 3: {report['stage3_source']}")
    print(f"Strings: {report['decoded_strings_path']}")
    print(f"Maps: {report['decoded_maps_path']}")
    if report.get("decoded_constants_text_path"):
        print(f"Constants: {report['decoded_constants_text_path']}")
    print(f"Report: {Path(report['output_dir']) / 'wynfuscate_deobfuscation_report.json'}")
    print(
        "Decoded strings: "
        f"{report['unique_decoded_strings']} unique from {report['decoded_call_count']} calls; "
        f"gK={report['gk_entries']} g3={report['g3_entries']} vm_stream={report['vm_stream_bytes']} bytes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
