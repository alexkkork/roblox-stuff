#!/usr/bin/env python3
"""Stream compact summaries from large, pretty-printed Luraph IR artifacts.

The native deobfuscator deliberately preserves detailed runtime observations in
its JSON artifacts.  Those arrays are useful evidence, but loading a complete
artifact just to inspect semantic coverage can consume several times the file's
size.  This tool reads fixed-size chunks, skips evidence payloads that do not
affect the summary, and retains only prototype/opcode counters.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, TextIO


SEMANTIC_CLASSES = (
    "static_semantic",
    "runtime_validated_observational_semantic",
    "trace_evidence_only",
    "unresolved",
)
DEFAULT_CHUNK_SIZE = 64 * 1024


class SummaryError(ValueError):
    """Raised when an artifact cannot be summarized truthfully."""


class StreamingJsonReader:
    """A small strict JSON reader whose input buffer has a fixed upper bound."""

    def __init__(self, stream: TextIO, *, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        self.stream = stream
        self.chunk_size = chunk_size
        self.buffer = ""
        self.position = 0
        self.consumed = 0
        self.eof = False

    @property
    def offset(self) -> int:
        return self.consumed + self.position

    def _error(self, message: str) -> SummaryError:
        return SummaryError(f"{message} at character {self.offset}")

    def _fill(self) -> bool:
        if self.position < len(self.buffer):
            return True
        self.consumed += self.position
        self.buffer = ""
        self.position = 0
        if self.eof:
            return False
        chunk = self.stream.read(self.chunk_size)
        if not isinstance(chunk, str):
            raise TypeError("JSON stream must be opened in text mode")
        if not chunk:
            self.eof = True
            return False
        self.buffer = chunk
        return True

    def _peek_raw(self) -> str:
        return self.buffer[self.position] if self._fill() else ""

    def _take_raw(self) -> str:
        if not self._fill():
            raise self._error("unexpected end of JSON input")
        character = self.buffer[self.position]
        self.position += 1
        return character

    def skip_whitespace(self) -> None:
        while True:
            character = self._peek_raw()
            if not character or character not in " \t\r\n":
                return
            self.position += 1

    def peek(self) -> str:
        self.skip_whitespace()
        return self._peek_raw()

    def expect(self, expected: str) -> None:
        self.skip_whitespace()
        actual = self._take_raw()
        if actual != expected:
            raise self._error(f"expected {expected!r}, found {actual!r}")

    def read_string(self) -> str:
        self.skip_whitespace()
        if self._take_raw() != '"':
            raise self._error("expected a JSON string")
        raw: list[str] = []
        while True:
            character = self._take_raw()
            if character == '"':
                try:
                    return json.loads('"' + "".join(raw) + '"')
                except json.JSONDecodeError as error:
                    raise self._error(f"invalid JSON string: {error.msg}") from error
            if ord(character) < 0x20:
                raise self._error("unescaped control character in JSON string")
            raw.append(character)
            if character == "\\":
                escape = self._take_raw()
                if escape not in '"\\/bfnrtu':
                    raise self._error(f"invalid JSON escape {escape!r}")
                raw.append(escape)
                if escape == "u":
                    digits = "".join(self._take_raw() for _ in range(4))
                    if any(digit not in "0123456789abcdefABCDEF" for digit in digits):
                        raise self._error("invalid JSON unicode escape")
                    raw.extend(digits)

    def skip_string(self) -> None:
        self.skip_whitespace()
        if self._take_raw() != '"':
            raise self._error("expected a JSON string")
        while True:
            character = self._take_raw()
            if character == '"':
                return
            if ord(character) < 0x20:
                raise self._error("unescaped control character in JSON string")
            if character == "\\":
                escape = self._take_raw()
                if escape not in '"\\/bfnrtu':
                    raise self._error(f"invalid JSON escape {escape!r}")
                if escape == "u":
                    digits = "".join(self._take_raw() for _ in range(4))
                    if any(digit not in "0123456789abcdefABCDEF" for digit in digits):
                        raise self._error("invalid JSON unicode escape")

    def read_scalar(self) -> Any:
        self.skip_whitespace()
        first = self._peek_raw()
        if first == '"':
            return self.read_string()
        if first and first in "-0123456789":
            characters: list[str] = []
            while True:
                character = self._peek_raw()
                if not character or character in " \t\r\n,]}":
                    break
                characters.append(self._take_raw())
            encoded = "".join(characters)
            try:
                value = json.loads(encoded)
            except json.JSONDecodeError as error:
                raise self._error(f"invalid JSON number {encoded!r}") from error
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise self._error(f"invalid JSON number {encoded!r}")
            if isinstance(value, float) and not math.isfinite(value):
                raise self._error("non-finite JSON number")
            return value
        for encoded, value in (("true", True), ("false", False), ("null", None)):
            if first == encoded[0]:
                actual = "".join(self._take_raw() for _ in encoded)
                if actual != encoded:
                    raise self._error(f"expected {encoded!r}, found {actual!r}")
                return value
        raise self._error(f"expected a JSON value, found {first!r}")

    def skip_value(self) -> None:
        marker = self.peek()
        if marker == "{":
            for _ in self.object_items():
                self.skip_value()
        elif marker == "[":
            for _ in self.array_items():
                self.skip_value()
        elif marker == '"':
            self.skip_string()
        else:
            self.read_scalar()

    def object_items(self) -> Iterable[str]:
        self.expect("{")
        if self.peek() == "}":
            self.expect("}")
            return
        while True:
            key = self.read_string()
            self.expect(":")
            yield key
            delimiter = self.peek()
            if delimiter == "}":
                self.expect("}")
                return
            if delimiter != ",":
                raise self._error(f"expected ',' or '}}', found {delimiter!r}")
            self.expect(",")

    def array_items(self) -> Iterable[int]:
        self.expect("[")
        if self.peek() == "]":
            self.expect("]")
            return
        index = 0
        while True:
            yield index
            index += 1
            delimiter = self.peek()
            if delimiter == "]":
                self.expect("]")
                return
            if delimiter != ",":
                raise self._error(f"expected ',' or ']', found {delimiter!r}")
            self.expect(",")

    def finish(self) -> None:
        self.skip_whitespace()
        if self._peek_raw():
            raise self._error("trailing data after top-level JSON value")


def _read_scalar_or_skip(reader: StreamingJsonReader) -> Any:
    if reader.peek() in "{[":
        reader.skip_value()
        return None
    return reader.read_scalar()


def _read_selected_object(reader: StreamingJsonReader, fields: set[str]) -> dict[str, Any]:
    if reader.peek() != "{":
        reader.skip_value()
        return {}
    selected: dict[str, Any] = {}
    for key in reader.object_items():
        if key in fields:
            selected[key] = _read_scalar_or_skip(reader)
        else:
            reader.skip_value()
    return selected


def _read_nested_selection(reader: StreamingJsonReader, spec: dict[str, Any]) -> dict[str, Any]:
    if reader.peek() != "{":
        reader.skip_value()
        return {}
    result: dict[str, Any] = {}
    for key in reader.object_items():
        selection = spec.get(key)
        if selection is True:
            result[key] = _read_scalar_or_skip(reader)
        elif isinstance(selection, dict):
            result[key] = _read_nested_selection(reader, selection)
        else:
            reader.skip_value()
    return result


def _sort_key(value: Any) -> tuple[int, Any]:
    if isinstance(value, bool):
        return (2, str(value).lower())
    if isinstance(value, (int, float)):
        return (0, value)
    if value is None:
        return (2, "")
    return (1, str(value))


def _blank_classes() -> dict[str, int]:
    return {name: 0 for name in SEMANTIC_CLASSES}


@dataclass
class UnresolvedGroup:
    count: int = 0
    sample_pcs: list[Any] = field(default_factory=list)
    reasons: collections.Counter[str] = field(default_factory=collections.Counter)

    def add(self, pc: Any, reason: str | None, *, sample_limit: int) -> None:
        self.count += 1
        if pc not in self.sample_pcs:
            self.sample_pcs.append(pc)
            self.sample_pcs.sort(key=_sort_key)
            del self.sample_pcs[sample_limit:]
        if reason:
            self.reasons[reason] += 1

    def merge(self, other: "UnresolvedGroup", *, sample_limit: int) -> None:
        self.count += other.count
        self.sample_pcs = sorted(set(self.sample_pcs + other.sample_pcs), key=_sort_key)[:sample_limit]
        self.reasons.update(other.reasons)


@dataclass
class SemanticAccumulator:
    top_unresolved: int
    totals: collections.Counter[str] = field(default_factory=collections.Counter)
    by_opcode: dict[Any, collections.Counter[str]] = field(default_factory=dict)
    by_prototype_opcode: dict[tuple[Any, Any], collections.Counter[str]] = field(default_factory=dict)
    unresolved: dict[tuple[Any, Any], UnresolvedGroup] = field(default_factory=dict)
    materialized: int = 0

    def add(
        self,
        prototype: Any,
        opcode: Any,
        semantic_class: str,
        pc: Any,
        reason: str | None,
    ) -> None:
        self.materialized += 1
        self.totals[semantic_class] += 1
        self.by_opcode.setdefault(opcode, collections.Counter())[semantic_class] += 1
        key = (prototype, opcode)
        self.by_prototype_opcode.setdefault(key, collections.Counter())[semantic_class] += 1
        if semantic_class == "unresolved":
            group = self.unresolved.setdefault(key, UnresolvedGroup())
            group.add(pc, reason, sample_limit=max(1, min(self.top_unresolved, 5)))

    def merge_prototype(self, prototype: Any, local: "SemanticAccumulator") -> None:
        self.materialized += local.materialized
        self.totals.update(local.totals)
        for opcode, counts in local.by_opcode.items():
            self.by_opcode.setdefault(opcode, collections.Counter()).update(counts)
            self.by_prototype_opcode.setdefault((prototype, opcode), collections.Counter()).update(counts)
        for (_, opcode), group in local.unresolved.items():
            target = self.unresolved.setdefault((prototype, opcode), UnresolvedGroup())
            target.merge(group, sample_limit=max(1, min(self.top_unresolved, 5)))


@dataclass
class InstructionFacts:
    pc: Any = None
    opcode: Any = None
    explicit_class: str | None = None
    semantic_operation: bool = False
    semantic_operation_unresolved: bool = False
    observational_operation: bool = False
    guard_replay_effect: bool = False
    trace_operation: bool = False
    reason: str | None = None

    def semantic_class(self) -> str:
        if self.explicit_class is not None:
            if self.explicit_class not in SEMANTIC_CLASSES:
                raise SummaryError(f"unknown semantic_coverage_class {self.explicit_class!r}")
            return self.explicit_class
        if self.semantic_operation and not self.semantic_operation_unresolved:
            return "static_semantic"
        if self.observational_operation or self.guard_replay_effect:
            return "runtime_validated_observational_semantic"
        if self.trace_operation:
            return "trace_evidence_only"
        return "unresolved"


def _inspect_operation(reader: StreamingJsonReader) -> tuple[bool, bool, str | None]:
    if reader.peek() == "n":
        reader.read_scalar()
        return False, False, None
    if reader.peek() != "{":
        reader.skip_value()
        return True, False, None
    selected = _read_selected_object(
        reader,
        {"kind", "$kind", "reason", "source_kind", "sourceKind"},
    )
    kind = selected.get("kind", selected.get("$kind"))
    unresolved = kind == "unresolved"
    reason = selected.get("reason") or selected.get("source_kind") or selected.get("sourceKind")
    return True, unresolved, str(reason) if reason is not None else None


def _parse_instruction(reader: StreamingJsonReader) -> InstructionFacts:
    facts = InstructionFacts()
    if reader.peek() != "{":
        raise reader._error("instruction entry must be an object")
    for key in reader.object_items():
        if key == "pc":
            facts.pc = _read_scalar_or_skip(reader)
        elif key == "opcode":
            facts.opcode = _read_scalar_or_skip(reader)
        elif key == "semantic_coverage_class":
            value = _read_scalar_or_skip(reader)
            facts.explicit_class = str(value) if value is not None else None
        elif key == "semantic_operation":
            present, unresolved, reason = _inspect_operation(reader)
            facts.semantic_operation = present
            facts.semantic_operation_unresolved = unresolved
            facts.reason = facts.reason or reason
        elif key == "observational_semantic_operation":
            present, _, _ = _inspect_operation(reader)
            facts.observational_operation = present
        elif key == "guard_replay_validated_effect":
            present, _, _ = _inspect_operation(reader)
            facts.guard_replay_effect = present
        elif key == "trace_specialized_operation":
            present, _, _ = _inspect_operation(reader)
            facts.trace_operation = present
        elif key in {"unresolved_reason", "reason", "selection_status"}:
            value = _read_scalar_or_skip(reader)
            if value is not None and facts.reason is None:
                facts.reason = str(value)
        else:
            reader.skip_value()
    return facts


def _parse_instructions(
    reader: StreamingJsonReader,
    accumulator: SemanticAccumulator,
    prototype: Any,
) -> None:
    if reader.peek() != "[":
        raise reader._error("prototype instructions must be an array")
    for _ in reader.array_items():
        facts = _parse_instruction(reader)
        accumulator.add(
            prototype,
            facts.opcode,
            facts.semantic_class(),
            facts.pc,
            facts.reason,
        )


def _parse_semantic_prototype(
    reader: StreamingJsonReader,
    target: SemanticAccumulator,
) -> None:
    prototype: Any = None
    local = SemanticAccumulator(top_unresolved=target.top_unresolved)
    if reader.peek() != "{":
        raise reader._error("prototype entry must be an object")
    for key in reader.object_items():
        if key in {"runtime_id", "prototype", "id"}:
            prototype = _read_scalar_or_skip(reader)
        elif key == "instructions":
            _parse_instructions(reader, local, None)
        else:
            reader.skip_value()
    target.merge_prototype(prototype, local)


def _parse_flat_scalars(reader: StreamingJsonReader) -> dict[str, Any]:
    if reader.peek() != "{":
        reader.skip_value()
        return {}
    result: dict[str, Any] = {}
    for key in reader.object_items():
        result[key] = _read_scalar_or_skip(reader)
    return result


def _class_rows(mapping: dict[Any, collections.Counter[str]], label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value, counts in sorted(mapping.items(), key=lambda item: _sort_key(item[0])):
        classes = {name: counts.get(name, 0) for name in SEMANTIC_CLASSES}
        rows.append({label: value, "total": sum(classes.values()), "classes": classes})
    return rows


def _prototype_rows(
    mapping: dict[tuple[Any, Any], collections.Counter[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    prototypes: dict[Any, collections.Counter[str]] = {}
    matrix: list[dict[str, Any]] = []
    for (prototype, opcode), counts in sorted(
        mapping.items(), key=lambda item: (_sort_key(item[0][0]), _sort_key(item[0][1]))
    ):
        prototypes.setdefault(prototype, collections.Counter()).update(counts)
        classes = {name: counts.get(name, 0) for name in SEMANTIC_CLASSES}
        matrix.append(
            {
                "prototype": prototype,
                "opcode": opcode,
                "total": sum(classes.values()),
                "classes": classes,
            }
        )
    return _class_rows(prototypes, "prototype"), matrix


def _top_unresolved_rows(
    groups: dict[tuple[Any, Any], UnresolvedGroup],
    limit: int,
) -> list[dict[str, Any]]:
    ranked = sorted(
        groups.items(),
        key=lambda item: (-item[1].count, _sort_key(item[0][0]), _sort_key(item[0][1])),
    )[:limit]
    rows: list[dict[str, Any]] = []
    for (prototype, opcode), group in ranked:
        common_reason = None
        if group.reasons:
            common_reason = sorted(group.reasons.items(), key=lambda item: (-item[1], item[0]))[0][0]
        rows.append(
            {
                "prototype": prototype,
                "opcode": opcode,
                "occurrences": group.count,
                "sample_pcs": group.sample_pcs,
                "reason": common_reason,
            }
        )
    return rows


def summarize_semantic_stream(
    stream: TextIO,
    *,
    source: str = "<stream>",
    top_unresolved: int = 20,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> dict[str, Any]:
    """Summarize one semantic IR stream without materializing its JSON tree."""

    if top_unresolved < 0:
        raise ValueError("top_unresolved must be non-negative")
    reader = StreamingJsonReader(stream, chunk_size=chunk_size)
    accumulator = SemanticAccumulator(top_unresolved=top_unresolved)
    metadata: dict[str, Any] = {}
    declared_partition: dict[str, Any] = {}
    if reader.peek() != "{":
        raise reader._error("semantic IR top level must be an object")
    scalar_fields = {
        "version",
        "kind",
        "scope",
        "instruction_count",
        "declared_instruction_count",
        "observed_instruction_count",
        "prototype_count",
    }
    for key in reader.object_items():
        if key == "prototypes":
            if reader.peek() != "[":
                raise reader._error("semantic IR prototypes must be an array")
            for _ in reader.array_items():
                _parse_semantic_prototype(reader, accumulator)
        elif key == "semantic_coverage_partition":
            declared_partition = _parse_flat_scalars(reader)
        elif key in scalar_fields:
            metadata[key] = _read_scalar_or_skip(reader)
        else:
            reader.skip_value()
    reader.finish()

    totals = {name: accumulator.totals.get(name, 0) for name in SEMANTIC_CLASSES}
    prototype_rows, matrix = _prototype_rows(accumulator.by_prototype_opcode)
    derived_sum = sum(totals.values())
    declared_total = declared_partition.get("total")
    declared_sum = declared_partition.get("partition_sum")
    unresolved_delta = None
    if isinstance(declared_partition.get("unresolved"), int):
        unresolved_delta = declared_partition["unresolved"] - totals["unresolved"]
    declared_matches = None
    if declared_partition:
        declared_matches = all(
            declared_partition.get(name) == totals[name]
            for name in SEMANTIC_CLASSES[:-1]
        ) and (unresolved_delta is None or unresolved_delta >= 0)
        if isinstance(declared_sum, int) and isinstance(declared_total, int):
            declared_matches = declared_matches and declared_sum == declared_total

    return {
        "source": source,
        "metadata": metadata,
        "classes": list(SEMANTIC_CLASSES),
        "materialized_total": accumulator.materialized,
        "totals": totals,
        "disjoint": derived_sum == accumulator.materialized,
        "by_prototype": prototype_rows,
        "by_opcode": _class_rows(accumulator.by_opcode, "opcode"),
        "by_prototype_opcode": matrix,
        "top_unresolved_sites": _top_unresolved_rows(
            accumulator.unresolved, top_unresolved
        ),
        "declared_partition": declared_partition or None,
        "structurally_missing_unresolved": unresolved_delta,
        "declared_partition_consistent": declared_matches,
    }


def summarize_semantic_file(
    path: Path,
    *,
    top_unresolved: int = 20,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        return summarize_semantic_stream(
            stream,
            source=str(path),
            top_unresolved=top_unresolved,
            chunk_size=chunk_size,
        )


CFG_COUNT_FIELDS = (
    "prototype_count",
    "instruction_count",
    "reachable_instructions",
    "block_count",
    "reachable_blocks",
    "edge_count",
    "cyclic_regions",
    "irreducible_regions",
    "invalid_edges",
    "reachable_invalid_edges",
    "observed_edge_sites",
)


def _parse_cfg_prototype(reader: StreamingJsonReader) -> dict[str, Any]:
    row: dict[str, Any] = {}
    for key in reader.object_items():
        if key in {"runtime_id", "prototype", "id", *CFG_COUNT_FIELDS}:
            row[key] = _read_scalar_or_skip(reader)
        else:
            reader.skip_value()
    if "prototype" not in row:
        row["prototype"] = row.pop("runtime_id", row.pop("id", None))
    else:
        row.pop("runtime_id", None)
        row.pop("id", None)
    return row


def summarize_cfg_stream(
    stream: TextIO,
    *,
    source: str = "<stream>",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> dict[str, Any]:
    reader = StreamingJsonReader(stream, chunk_size=chunk_size)
    metadata: dict[str, Any] = {}
    totals: dict[str, Any] = {}
    prototypes: list[dict[str, Any]] = []
    for key in reader.object_items():
        if key == "prototypes":
            for _ in reader.array_items():
                prototypes.append(_parse_cfg_prototype(reader))
        elif key in CFG_COUNT_FIELDS:
            totals[key] = _read_scalar_or_skip(reader)
        elif key in {"version", "kind", "scope"}:
            metadata[key] = _read_scalar_or_skip(reader)
        else:
            reader.skip_value()
    reader.finish()
    prototypes.sort(key=lambda row: _sort_key(row.get("prototype")))

    consistency: dict[str, bool] = {}
    for field_name in CFG_COUNT_FIELDS:
        total = totals.get(field_name)
        values = [row.get(field_name) for row in prototypes]
        if isinstance(total, int) and values and all(isinstance(value, int) for value in values):
            consistency[field_name] = sum(values) == total
    return {
        "available": True,
        "source": source,
        "metadata": metadata,
        "totals": totals,
        "by_prototype": prototypes,
        "prototype_sums_match_totals": consistency,
    }


def summarize_cfg_file(path: Path, *, chunk_size: int = DEFAULT_CHUNK_SIZE) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        return summarize_cfg_stream(stream, source=str(path), chunk_size=chunk_size)


REPORT_SELECTION = {
    "status": True,
    "exact_source": True,
    "artifacts": {"source": True, "candidate": True, "semantic_candidate": True},
    "verification": {
        "source_claim_accepted": True,
        "semantic_lift_verified": True,
        "candidate": {
            "available": True,
            "compiled": True,
            "differentially_verified": True,
            "source_claim": True,
        },
        "semantic_candidate": {
            "available": True,
            "compiled": True,
            "differentially_verified": True,
            "fully_rendered": True,
            "source_claim": True,
        },
    },
    "payload_evidence": {"source_claim": True},
}


def _source_claim_summary(source: str, selected: dict[str, Any]) -> dict[str, Any]:
    artifacts = selected.get("artifacts") or {}
    verification = selected.get("verification") or {}
    candidate = verification.get("candidate") or {}
    semantic_candidate = verification.get("semantic_candidate") or {}
    payload_evidence = selected.get("payload_evidence") or {}
    accepted = verification.get("source_claim_accepted")
    exact_source = selected.get("exact_source")
    source_artifact = artifacts.get("source")
    payload_claim = payload_evidence.get("source_claim")

    if accepted is True:
        claim_status = "accepted"
    elif accepted is False or payload_claim == "none":
        claim_status = "withheld"
    elif exact_source is True or source_artifact is not None:
        claim_status = "reported_without_acceptance_flag"
    else:
        claim_status = "not_reported"

    contradictions: list[str] = []
    if accepted is True and source_artifact is None:
        contradictions.append("accepted claim has no source artifact")
    if exact_source is True and accepted is False:
        contradictions.append("exact_source is true while source_claim_accepted is false")
    if payload_claim == "none" and accepted is True:
        contradictions.append("payload evidence withholds source while verification accepts it")

    return {
        "available": True,
        "source": source,
        "claim_status": claim_status,
        "report_status": selected.get("status"),
        "exact_source": exact_source,
        "accepted": accepted,
        "source_artifact": source_artifact,
        "candidate_source_claim": candidate.get("source_claim"),
        "semantic_candidate_source_claim": semantic_candidate.get("source_claim"),
        "semantic_candidate_fully_rendered": semantic_candidate.get("fully_rendered"),
        "semantic_lift_verified": verification.get("semantic_lift_verified"),
        "payload_evidence_source_claim": payload_claim,
        "consistent": not contradictions,
        "contradictions": contradictions,
    }


def summarize_report_stream(
    stream: TextIO,
    *,
    source: str = "<stream>",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> dict[str, Any]:
    reader = StreamingJsonReader(stream, chunk_size=chunk_size)
    selected = _read_nested_selection(reader, REPORT_SELECTION)
    reader.finish()
    return _source_claim_summary(source, selected)


def summarize_report_file(path: Path, *, chunk_size: int = DEFAULT_CHUNK_SIZE) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        return summarize_report_stream(stream, source=str(path), chunk_size=chunk_size)


@dataclass(frozen=True)
class ArtifactPaths:
    semantic_ir: Path
    cfg: Path | None
    report: Path | None


def discover_artifacts(
    input_path: Path,
    *,
    cfg: Path | None = None,
    report: Path | None = None,
) -> ArtifactPaths:
    if input_path.is_dir():
        directory = input_path
        semantic_candidates = (
            directory / "runtime_semantic_ir.json",
            directory / "payload_closure_ir.json",
            directory / "semantic_ir.json",
        )
        semantic_ir = next((path for path in semantic_candidates if path.is_file()), None)
        if semantic_ir is None:
            names = ", ".join(path.name for path in semantic_candidates)
            raise SummaryError(f"no semantic IR found in {directory}; tried {names}")
    else:
        semantic_ir = input_path
        directory = input_path.parent
    if not semantic_ir.is_file():
        raise SummaryError(f"semantic IR not found: {semantic_ir}")

    cfg_path = cfg if cfg is not None else directory / "cfg.json"
    report_path = report if report is not None else directory / "deobfuscation_report.json"
    if cfg is not None and not cfg_path.is_file():
        raise SummaryError(f"CFG artifact not found: {cfg_path}")
    if report is not None and not report_path.is_file():
        raise SummaryError(f"report artifact not found: {report_path}")
    return ArtifactPaths(
        semantic_ir=semantic_ir,
        cfg=cfg_path if cfg_path.is_file() else None,
        report=report_path if report_path.is_file() else None,
    )


def summarize_bundle(
    semantic_ir: Path,
    *,
    cfg: Path | None = None,
    report: Path | None = None,
    top_unresolved: int = 20,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> dict[str, Any]:
    semantic = summarize_semantic_file(
        semantic_ir,
        top_unresolved=top_unresolved,
        chunk_size=chunk_size,
    )
    cfg_summary = (
        summarize_cfg_file(cfg, chunk_size=chunk_size)
        if cfg is not None
        else {"available": False}
    )
    source_claim = (
        summarize_report_file(report, chunk_size=chunk_size)
        if report is not None
        else {"available": False, "claim_status": "not_reported"}
    )
    return {
        "version": 1,
        "semantic": semantic,
        "cfg": cfg_summary,
        "source_claim": source_claim,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Stream a compact semantic/CFG/source-claim summary from Luraph JSON artifacts.",
    )
    parser.add_argument(
        "input",
        type=Path,
        help="artifact directory or a semantic IR JSON file",
    )
    parser.add_argument("--cfg", type=Path, help="CFG JSON (defaults to sibling cfg.json)")
    parser.add_argument(
        "--report",
        type=Path,
        help="deobfuscation report JSON (defaults to sibling deobfuscation_report.json)",
    )
    parser.add_argument(
        "--top-unresolved",
        type=int,
        default=20,
        metavar="N",
        help="number of unresolved prototype/opcode groups to retain (default: 20)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        metavar="BYTES",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("-o", "--output", type=Path, help="write JSON here instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.top_unresolved < 0:
        parser.error("--top-unresolved must be non-negative")
    if args.chunk_size < 1:
        parser.error("--chunk-size must be positive")
    try:
        paths = discover_artifacts(args.input, cfg=args.cfg, report=args.report)
        summary = summarize_bundle(
            paths.semantic_ir,
            cfg=paths.cfg,
            report=paths.report,
            top_unresolved=args.top_unresolved,
            chunk_size=args.chunk_size,
        )
    except (OSError, SummaryError, UnicodeError) as error:
        parser.exit(2, f"{parser.prog}: error: {error}\n")
    encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(encoded)
    else:
        args.output.write_text(encoded, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
