#!/usr/bin/env python3
"""Merge and measure local Luraph marker traces without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Sequence


MARKER_RE = re.compile(r"@@LPH_[A-Z0-9_]+@@")
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
STRUCTURE_MARKERS = {
    "@@LPH_PROTO_V1@@",
    "@@LPH_PROTO_OBJECT_V1@@",
    "@@LPH_INSN_V1@@",
    "@@LPH_LANE_TOP_V1@@",
    "@@LPH_LANE_TABLE_V1@@",
}
VM_COUNT_FIELDS = {
    "@@LPH_VM@@": 0,
    "@@LPH_ACTIVATION@@": 0,
    "@@LPH_CALL_V2@@": 0,
    "@@LPH_STEP_V1@@": 0,
    "@@LPH_RETURN_V1@@": 0,
    "@@LPH_ACT_PROTO_V1@@": 8,
    "@@LPH_ACT_PROTO_LIMIT_V1@@": 1,
    "@@LPH_GUARD_V1@@": 0,
    "@@LPH_GUARD_PATH_V1@@": 0,
}
EXECUTION_MARKERS = {"@@LPH_VM@@", "@@LPH_STEP_V1@@"}
STRUCTURE_HASH_SCHEMA = "lph-prototype-instruction-shape-v1"
GUARD_MARKER = "@@LPH_GUARD_V1@@"
GUARD_SCHEMA = "lph-guard-v1"
GUARD_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
GUARD_CONFLICT_EXAMPLE_LIMIT = 100
GUARD_PATH_MARKER = "@@LPH_GUARD_PATH_V1@@"
GUARD_PATH_SCHEMA = "lph-guard-path-v1"
GUARD_PATH_DECISION_LIMIT = 4096
GUARD_PATH_CONFLICT_EXAMPLE_LIMIT = 100
UINT64_MAX = (1 << 64) - 1
INT64_MAX = (1 << 63) - 1


class CampaignError(RuntimeError):
    """A trace campaign cannot be merged truthfully."""


@dataclass(frozen=True)
class Record:
    marker: str
    fields: tuple[str, ...]

    def as_tsv(self) -> str:
        return "\t".join((self.marker, *self.fields))

    def as_jsonl(self) -> str:
        return json.dumps(
            {"marker": self.marker, "fields": list(self.fields)},
            separators=(",", ":"),
            sort_keys=True,
        )


@dataclass(frozen=True)
class GuardObservation:
    vm_count: int
    activation: int
    pc: int
    opcode: int
    pairs: tuple[tuple[str, str], ...]

    @property
    def execution_key(self) -> tuple[int, int, int, int]:
        return (self.vm_count, self.activation, self.pc, self.opcode)

    @property
    def location_key(self) -> tuple[int, int, int]:
        return (self.vm_count, self.activation, self.pc)


@dataclass(frozen=True)
class GuardPathDecision:
    begin: int
    end: int
    decision: int


@dataclass(frozen=True)
class GuardPathObservation:
    vm_count: int
    activation: int
    pc: int
    opcode: int
    overflow: int
    decisions: tuple[GuardPathDecision, ...]

    @property
    def execution_key(self) -> tuple[int, int, int, int]:
        return (self.vm_count, self.activation, self.pc, self.opcode)

    @property
    def location_key(self) -> tuple[int, int, int]:
        return (self.vm_count, self.activation, self.pc)

    @property
    def path_key(self) -> tuple[Any, ...]:
        return (*self.execution_key, self.overflow, self.decisions)


@dataclass
class StructureShape:
    prototypes: dict[int, tuple[int, str]]
    instructions: dict[tuple[int, int], int]
    marker_records: int = 0


def _json_field(value: Any) -> str:
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def parse_record(line: str, *, location: str) -> Record | None:
    """Parse a native marker line or a {marker, fields} JSONL object."""

    text = line.rstrip("\r\n")
    if not text.strip():
        return None

    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as error:
            raise CampaignError(f"{location}: invalid JSONL record: {error.msg}") from error
        if not isinstance(payload, dict):
            raise CampaignError(f"{location}: JSONL record must be an object")
        if "line" in payload:
            if not isinstance(payload["line"], str):
                raise CampaignError(f"{location}: JSONL line must be a string")
            return parse_record(payload["line"], location=location)
        marker = payload.get("marker")
        fields = payload.get("fields", [])
        if marker is None:
            return None
        if not isinstance(marker, str) or not MARKER_RE.fullmatch(marker):
            raise CampaignError(f"{location}: invalid Luraph marker")
        if not isinstance(fields, list):
            raise CampaignError(f"{location}: JSONL fields must be an array")
        if marker == GUARD_PATH_MARKER and any(
            isinstance(value, bool) or value is None or not isinstance(value, (str, int))
            for value in fields
        ):
            raise CampaignError(
                f"{location}: guard-path JSONL fields must contain only strings or integers"
            )
        record = Record(marker, tuple(_json_field(value) for value in fields))
        if marker == GUARD_MARKER:
            parse_guard_record(record, location=location)
        elif marker == GUARD_PATH_MARKER:
            parse_guard_path_record(record, location=location)
        return record

    marker_match = MARKER_RE.search(text)
    if marker_match is None:
        return None
    marker_line = text[marker_match.start() :]
    parts = marker_line.split("\t")
    marker = parts[0]
    if not MARKER_RE.fullmatch(marker):
        raise CampaignError(f"{location}: malformed Luraph marker line")
    record = Record(marker, tuple(parts[1:]))
    if marker == GUARD_MARKER:
        parse_guard_record(record, location=location)
    elif marker == GUARD_PATH_MARKER:
        parse_guard_path_record(record, location=location)
    return record


def _parse_int(value: str, *, location: str, label: str, minimum: int = 0) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise CampaignError(f"{location}: {label} is not an integer") from error
    if parsed < minimum:
        raise CampaignError(f"{location}: {label} must be at least {minimum}")
    return parsed


def parse_guard_record(record: Record, *, location: str) -> GuardObservation | None:
    """Decode a guard snapshot without interpreting its encoded values."""

    if record.marker != GUARD_MARKER:
        return None
    if len(record.fields) < 5:
        raise CampaignError(
            f"{location}: guard marker needs VM count, activation, PC, opcode, and at least one name=value pair"
        )

    vm_count_value = _parse_int(record.fields[0], location=location, label="guard VM count", minimum=0)
    activation = _parse_int(record.fields[1], location=location, label="guard activation", minimum=1)
    pc = _parse_int(record.fields[2], location=location, label="guard PC", minimum=1)
    opcode = _parse_int(record.fields[3], location=location, label="guard opcode", minimum=0)
    pairs: list[tuple[str, str]] = []
    names: set[str] = set()
    for index, field in enumerate(record.fields[4:], 1):
        if "=" not in field:
            raise CampaignError(f"{location}: guard pair {index} is missing '='")
        name, value = field.split("=", 1)
        if not name:
            raise CampaignError(f"{location}: guard pair {index} has an empty name")
        if not GUARD_NAME_RE.fullmatch(name):
            raise CampaignError(f"{location}: guard pair {index} has an invalid name")
        if name in names:
            raise CampaignError(f"{location}: guard name {name!r} appears more than once")
        names.add(name)
        pairs.append((name, value))
    return GuardObservation(vm_count_value, activation, pc, opcode, tuple(pairs))


def _parse_guard_path_uint(
    value: str,
    *,
    location: str,
    label: str,
    minimum: int = 0,
    maximum: int = UINT64_MAX,
) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise CampaignError(f"{location}: {label} must be a canonical unsigned decimal integer")
    parsed = int(value, 10)
    if parsed < minimum or parsed > maximum:
        raise CampaignError(f"{location}: {label} must be between {minimum} and {maximum}")
    return parsed


def parse_guard_path_record(record: Record, *, location: str) -> GuardPathObservation | None:
    """Decode and strictly validate one ordered guard-decision path."""

    if record.marker != GUARD_PATH_MARKER:
        return None
    if len(record.fields) != 7:
        raise CampaignError(
            f"{location}: guard-path marker needs exactly VM count, activation, PC, opcode, "
            "decision count, overflow, and decision entries"
        )

    vm_count_value = _parse_guard_path_uint(
        record.fields[0], location=location, label="guard-path VM count", minimum=1
    )
    activation = _parse_guard_path_uint(
        record.fields[1], location=location, label="guard-path activation", minimum=1
    )
    pc = _parse_guard_path_uint(
        record.fields[2],
        location=location,
        label="guard-path PC",
        minimum=1,
        maximum=INT64_MAX,
    )
    opcode = _parse_guard_path_uint(
        record.fields[3], location=location, label="guard-path opcode", maximum=255
    )
    declared = _parse_guard_path_uint(
        record.fields[4],
        location=location,
        label="guard-path decision count",
        maximum=GUARD_PATH_DECISION_LIMIT,
    )
    overflow = _parse_guard_path_uint(
        record.fields[5], location=location, label="guard-path overflow", maximum=1
    )
    encoded = record.fields[6]
    if declared == 0:
        if encoded:
            raise CampaignError(f"{location}: zero-decision guard path must have an empty entry field")
        entries: list[str] = []
    else:
        if not encoded:
            raise CampaignError(f"{location}: non-empty guard path is missing its decision entries")
        entries = encoded.split("|")
        if any(not entry for entry in entries):
            raise CampaignError(f"{location}: guard-path decision entries cannot be empty")

    if len(entries) != declared:
        raise CampaignError(
            f"{location}: guard-path decision count declares {declared}, but {len(entries)} entries were provided"
        )

    decisions: list[GuardPathDecision] = []
    for ordinal, entry in enumerate(entries, 1):
        parts = entry.split(":")
        if len(parts) != 3:
            raise CampaignError(
                f"{location}: guard-path decision {ordinal} must be begin:end:decision"
            )
        begin = _parse_guard_path_uint(
            parts[0], location=location, label=f"guard-path decision {ordinal} begin"
        )
        end = _parse_guard_path_uint(
            parts[1], location=location, label=f"guard-path decision {ordinal} end"
        )
        decision = _parse_guard_path_uint(
            parts[2],
            location=location,
            label=f"guard-path decision {ordinal} value",
            maximum=1,
        )
        if begin >= end:
            raise CampaignError(f"{location}: guard-path decision {ordinal} begin must be less than end")
        decisions.append(GuardPathDecision(begin, end, decision))

    return GuardPathObservation(vm_count_value, activation, pc, opcode, overflow, tuple(decisions))


def _record_dedupe_key(record: Record) -> Any:
    """Treat reordered guard pairs as one snapshot while retaining the first row verbatim."""

    guard = parse_guard_record(record, location="merged guard record")
    if guard is not None:
        return (GUARD_MARKER, *guard.execution_key, tuple(sorted(guard.pairs)))
    guard_path = parse_guard_path_record(record, location="merged guard-path record")
    if guard_path is not None:
        return (GUARD_PATH_MARKER, *guard_path.path_key)
    return record


def _guard_summary(
    records: Sequence[Record],
    *,
    input_records: int | None = None,
    duplicates_removed: int | None = None,
) -> dict[str, Any]:
    parsed = [
        guard
        for record in records
        if (guard := parse_guard_record(record, location="guard summary")) is not None
    ]
    unique_observations: dict[Any, GuardObservation] = {}
    for guard in parsed:
        key = (*guard.execution_key, tuple(sorted(guard.pairs)))
        unique_observations.setdefault(key, guard)
    observations = list(unique_observations.values())
    if input_records is None:
        input_records = len(parsed)
    if duplicates_removed is None:
        duplicates_removed = len(parsed) - len(observations)

    values_by_execution_name: dict[tuple[int, int, int, int, str], set[str]] = defaultdict(set)
    opcodes_by_location: dict[tuple[int, int, int], set[int]] = defaultdict(set)
    executions_by_name: dict[str, set[tuple[int, int, int, int]]] = defaultdict(set)
    values_by_name: dict[str, set[str]] = defaultdict(set)
    records_by_name: Counter[str] = Counter()
    vm_counts_by_name: dict[str, set[int]] = defaultdict(set)
    executions_by_opcode: dict[int, set[tuple[int, int, int, int]]] = defaultdict(set)
    names_by_opcode: dict[int, set[str]] = defaultdict(set)
    pair_observations = 0

    for guard in observations:
        opcodes_by_location[guard.location_key].add(guard.opcode)
        executions_by_opcode[guard.opcode].add(guard.execution_key)
        for name, value in guard.pairs:
            pair_observations += 1
            records_by_name[name] += 1
            vm_counts_by_name[name].add(guard.vm_count)
            values_by_execution_name[(*guard.execution_key, name)].add(value)
            executions_by_name[name].add(guard.execution_key)
            values_by_name[name].add(value)
            names_by_opcode[guard.opcode].add(name)

    binding_conflicts = [
        {
            "kind": "binding",
            "vm_count": key[0],
            "activation": key[1],
            "pc": key[2],
            "opcode": key[3],
            "name": key[4],
            "values": sorted(values),
        }
        for key, values in sorted(values_by_execution_name.items())
        if len(values) > 1
    ]
    opcode_conflicts = [
        {
            "kind": "opcode",
            "vm_count": key[0],
            "activation": key[1],
            "pc": key[2],
            "opcodes": sorted(opcodes),
        }
        for key, opcodes in sorted(opcodes_by_location.items())
        if len(opcodes) > 1
    ]
    execution_keys = {guard.execution_key for guard in observations}
    event_keys = {guard.location_key for guard in observations}
    activation_sites = {(guard.activation, guard.pc, guard.opcode) for guard in observations}
    vm_counts = {guard.vm_count for guard in observations}
    execution_vm_counts = {
        count
        for record in records
        if record.marker in EXECUTION_MARKERS and (count := vm_count(record)) is not None and count > 0
    }
    guarded_execution_vm_counts = vm_counts & execution_vm_counts
    conflict_examples = sorted(
        (*binding_conflicts, *opcode_conflicts),
        key=lambda item: (
            item["vm_count"],
            item["activation"],
            item["pc"],
            item["kind"],
            item.get("opcode", -1),
            item.get("name", ""),
        ),
    )
    conflict_count = len(conflict_examples)

    return {
        "schema": GUARD_SCHEMA,
        "available": bool(observations),
        "input_records": input_records,
        "unique_records": len(observations),
        "duplicates_removed": duplicates_removed,
        "records": len(observations),
        "pair_observations": pair_observations,
        "execution_points": len(execution_keys),
        "unique_events": len(event_keys),
        "activation_sites": len(activation_sites),
        "unique_sites": len(activation_sites),
        "unique_vm_counts": len(vm_counts),
        "vm_count_min": min(vm_counts) if vm_counts else None,
        "vm_count_max": max(vm_counts) if vm_counts else None,
        "activations": len({guard.activation for guard in observations}),
        "unique_activations": len({guard.activation for guard in observations}),
        "pcs": len({guard.pc for guard in observations}),
        "opcodes": len({guard.opcode for guard in observations}),
        "unique_opcodes": len({guard.opcode for guard in observations}),
        "guard_names": len(executions_by_name),
        "unique_bindings": len(values_by_execution_name),
        "execution_vm_counts": len(execution_vm_counts),
        "execution_vm_counts_with_guards": len(guarded_execution_vm_counts),
        "execution_vm_count_coverage_ratio": (
            round(len(guarded_execution_vm_counts) / len(execution_vm_counts), 6)
            if execution_vm_counts
            else None
        ),
        "coverage_by_name": [
            {
                "name": name,
                "records": records_by_name[name],
                "execution_points": len(executions_by_name[name]),
                "unique_events": len({key[:3] for key in executions_by_name[name]}),
                "distinct_values": len(values_by_name[name]),
                "unique_values": len(values_by_name[name]),
                "vm_count_min": min(vm_counts_by_name[name]),
                "vm_count_max": max(vm_counts_by_name[name]),
            }
            for name in sorted(executions_by_name)
        ],
        "coverage_by_opcode": [
            {
                "opcode": opcode,
                "execution_points": len(executions_by_opcode[opcode]),
                "guard_names": sorted(names_by_opcode[opcode]),
            }
            for opcode in sorted(executions_by_opcode)
        ],
        "conflicts": {
            "present": bool(conflict_examples),
            "has_conflicts": bool(conflict_examples),
            "count": conflict_count,
            "binding_conflicts": len(binding_conflicts),
            "opcode_conflicts": len(opcode_conflicts),
            "examples": conflict_examples[:GUARD_CONFLICT_EXAMPLE_LIMIT],
            "examples_truncated": conflict_count > GUARD_CONFLICT_EXAMPLE_LIMIT,
        },
    }


def _guard_path_summary(
    records: Sequence[Record],
    *,
    input_records: int | None = None,
    duplicates_removed: int | None = None,
) -> dict[str, Any]:
    parsed = [
        path
        for record in records
        if (path := parse_guard_path_record(record, location="guard-path summary")) is not None
    ]
    unique_observations: dict[tuple[Any, ...], GuardPathObservation] = {}
    for path in parsed:
        unique_observations.setdefault(path.path_key, path)
    observations = list(unique_observations.values())
    if input_records is None:
        input_records = len(parsed)
    if duplicates_removed is None:
        duplicates_removed = len(parsed) - len(observations)

    paths_by_execution: dict[tuple[int, int, int, int], set[tuple[Any, ...]]] = defaultdict(set)
    completion_by_execution_path: dict[tuple[Any, ...], set[int]] = defaultdict(set)
    opcodes_by_location: dict[tuple[int, int, int], set[int]] = defaultdict(set)
    paths_by_opcode: dict[int, list[GuardPathObservation]] = defaultdict(list)
    outcomes_by_condition: dict[tuple[int, int], set[int]] = defaultdict(set)
    vm_counts: set[int] = set()
    decision_observations = 0

    for path in observations:
        signature = (path.overflow, path.decisions)
        paths_by_execution[path.execution_key].add(signature)
        completion_by_execution_path[(*path.execution_key, path.decisions)].add(path.overflow)
        opcodes_by_location[path.location_key].add(path.opcode)
        paths_by_opcode[path.opcode].append(path)
        vm_counts.add(path.vm_count)
        decision_observations += len(path.decisions)
        for decision in path.decisions:
            outcomes_by_condition[(decision.begin, decision.end)].add(decision.decision)

    path_conflicts = [
        {
            "kind": "path",
            "vm_count": key[0],
            "activation": key[1],
            "pc": key[2],
            "opcode": key[3],
            "paths": len(signatures),
        }
        for key, signatures in sorted(paths_by_execution.items())
        if len(signatures) > 1
    ]
    opcode_conflicts = [
        {
            "kind": "opcode",
            "vm_count": key[0],
            "activation": key[1],
            "pc": key[2],
            "opcodes": sorted(opcodes),
        }
        for key, opcodes in sorted(opcodes_by_location.items())
        if len(opcodes) > 1
    ]
    completion_conflicts = sum(
        len(overflow_values) > 1 for overflow_values in completion_by_execution_path.values()
    )
    conflict_examples = sorted(
        (*path_conflicts, *opcode_conflicts),
        key=lambda item: (
            item["vm_count"],
            item["activation"],
            item["pc"],
            item["kind"],
            item.get("opcode", -1),
        ),
    )
    execution_vm_counts = {
        count
        for record in records
        if record.marker in EXECUTION_MARKERS and (count := vm_count(record)) is not None and count > 0
    }
    guarded_execution_vm_counts = vm_counts & execution_vm_counts
    complete_paths = sum(path.overflow == 0 for path in observations)
    overflow_paths = len(observations) - complete_paths

    return {
        "schema": GUARD_PATH_SCHEMA,
        "available": bool(observations),
        "input_records": input_records,
        "unique_records": len(observations),
        "duplicates_removed": duplicates_removed,
        "records": len(observations),
        "decision_observations": decision_observations,
        "execution_points": len(paths_by_execution),
        "unique_events": len({path.location_key for path in observations}),
        "activation_sites": len({(path.activation, path.pc, path.opcode) for path in observations}),
        "unique_sites": len({(path.activation, path.pc, path.opcode) for path in observations}),
        "unique_vm_counts": len(vm_counts),
        "vm_count_min": min(vm_counts) if vm_counts else None,
        "vm_count_max": max(vm_counts) if vm_counts else None,
        "activations": len({path.activation for path in observations}),
        "unique_activations": len({path.activation for path in observations}),
        "pcs": len({path.pc for path in observations}),
        "unique_pcs": len({path.pc for path in observations}),
        "opcodes": len(paths_by_opcode),
        "unique_opcodes": len(paths_by_opcode),
        "complete_paths": complete_paths,
        "overflow_paths": overflow_paths,
        "complete_path_ratio": round(complete_paths / len(observations), 6) if observations else None,
        "unique_conditions": len(outcomes_by_condition),
        "unique_condition_spans": len(outcomes_by_condition),
        "conditions_with_both_outcomes": sum(len(outcomes) == 2 for outcomes in outcomes_by_condition.values()),
        "true_decisions": sum(
            decision.decision == 1 for path in observations for decision in path.decisions
        ),
        "false_decisions": sum(
            decision.decision == 0 for path in observations for decision in path.decisions
        ),
        "path_length_min": min((len(path.decisions) for path in observations), default=None),
        "path_length_max": max((len(path.decisions) for path in observations), default=None),
        "ordered": True,
        "manifest_validated": False,
        "execution_vm_counts": len(execution_vm_counts),
        "execution_vm_counts_with_guard_paths": len(guarded_execution_vm_counts),
        "execution_vm_count_coverage_ratio": (
            round(len(guarded_execution_vm_counts) / len(execution_vm_counts), 6)
            if execution_vm_counts
            else None
        ),
        "coverage_by_opcode": [
            {
                "opcode": opcode,
                "records": len(opcode_paths),
                "execution_points": len({path.execution_key for path in opcode_paths}),
                "decision_observations": sum(len(path.decisions) for path in opcode_paths),
                "unique_conditions": len(
                    {
                        (decision.begin, decision.end)
                        for path in opcode_paths
                        for decision in path.decisions
                    }
                ),
                "complete_paths": sum(path.overflow == 0 for path in opcode_paths),
                "overflow_paths": sum(path.overflow == 1 for path in opcode_paths),
            }
            for opcode, opcode_paths in sorted(paths_by_opcode.items())
        ],
        "conflicts": {
            "present": bool(conflict_examples),
            "has_conflicts": bool(conflict_examples),
            "count": len(conflict_examples),
            "path_conflicts": len(path_conflicts),
            "opcode_conflicts": len(opcode_conflicts),
            "completion_conflicts": completion_conflicts,
            "examples": conflict_examples[:GUARD_PATH_CONFLICT_EXAMPLE_LIMIT],
            "examples_truncated": len(conflict_examples) > GUARD_PATH_CONFLICT_EXAMPLE_LIMIT,
        },
    }


def structure_shape(records: Iterable[Record], *, label: str) -> StructureShape:
    shape = StructureShape({}, {})
    for record in records:
        if record.marker in STRUCTURE_MARKERS:
            shape.marker_records += 1
        if record.marker == "@@LPH_PROTO_V1@@":
            if len(record.fields) < 3:
                raise CampaignError(f"{label}: prototype marker is missing id, size, or lane schema")
            prototype = _parse_int(record.fields[0], location=label, label="prototype id", minimum=1)
            declared = _parse_int(record.fields[1], location=label, label="prototype instruction count", minimum=0)
            value = (declared, record.fields[2])
            previous = shape.prototypes.get(prototype)
            if previous is not None and previous != value:
                raise CampaignError(f"{label}: conflicting declaration for prototype {prototype}")
            shape.prototypes[prototype] = value
        elif record.marker == "@@LPH_INSN_V1@@":
            if len(record.fields) < 3:
                raise CampaignError(f"{label}: instruction marker is missing prototype, PC, or opcode")
            prototype = _parse_int(record.fields[0], location=label, label="instruction prototype", minimum=1)
            pc = _parse_int(record.fields[1], location=label, label="instruction PC", minimum=1)
            opcode = _parse_int(record.fields[2], location=label, label="instruction opcode", minimum=0)
            key = (prototype, pc)
            previous = shape.instructions.get(key)
            if previous is not None and previous != opcode:
                raise CampaignError(f"{label}: conflicting opcode for prototype {prototype}, PC {pc}")
            shape.instructions[key] = opcode
    return shape


def merge_shapes(target: StructureShape, incoming: StructureShape, *, label: str) -> None:
    target.marker_records += incoming.marker_records
    for prototype, declaration in incoming.prototypes.items():
        previous = target.prototypes.get(prototype)
        if previous is not None and previous != declaration:
            raise CampaignError(f"{label}: prototype {prototype} disagrees with another trace")
        target.prototypes[prototype] = declaration
    for site, opcode in incoming.instructions.items():
        previous = target.instructions.get(site)
        if previous is not None and previous != opcode:
            raise CampaignError(
                f"{label}: prototype {site[0]}, PC {site[1]} has conflicting opcodes {previous} and {opcode}"
            )
        target.instructions[site] = opcode


def shape_complete(shape: StructureShape) -> bool:
    if not shape.prototypes:
        return False
    if any(prototype not in shape.prototypes for prototype, _ in shape.instructions):
        return False
    if len(shape.instructions) != sum(declaration[0] for declaration in shape.prototypes.values()):
        return False
    return all(
        all((prototype, pc) in shape.instructions for pc in range(1, declaration[0] + 1))
        for prototype, declaration in shape.prototypes.items()
    )


def structure_hash(shape: StructureShape) -> str | None:
    if not shape.prototypes and not shape.instructions:
        return None
    digest = hashlib.sha256()
    digest.update((STRUCTURE_HASH_SCHEMA + "\n").encode("ascii"))
    for prototype, (declared, lanes) in sorted(shape.prototypes.items()):
        digest.update(f"P\t{prototype}\t{declared}\t{lanes}\n".encode("utf-8"))
    for (prototype, pc), opcode in sorted(shape.instructions.items()):
        digest.update(f"I\t{prototype}\t{pc}\t{opcode}\n".encode("ascii"))
    return digest.hexdigest()


def vm_count(record: Record) -> int | None:
    field = VM_COUNT_FIELDS.get(record.marker)
    if field is None or len(record.fields) <= field:
        return None
    try:
        value = int(record.fields[field], 10)
    except ValueError:
        return None
    return value if value >= 0 else None


def _marker_summary(records: Sequence[Record]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    counts_by_vm: dict[str, set[int]] = defaultdict(set)
    for record in records:
        counts[record.marker] += 1
        count = vm_count(record)
        if count is not None:
            counts_by_vm[record.marker].add(count)
    return [
        {
            "marker": marker,
            "records": counts[marker],
            "unique_vm_counts": len(counts_by_vm[marker]),
            "vm_count_min": min(counts_by_vm[marker]) if counts_by_vm[marker] else None,
            "vm_count_max": max(counts_by_vm[marker]) if counts_by_vm[marker] else None,
        }
        for marker in sorted(counts)
    ]


def _window_summary(records: Sequence[Record], size: int) -> list[dict[str, Any]]:
    windows: dict[int, list[Record]] = defaultdict(list)
    for record in records:
        count = vm_count(record)
        if count is None:
            continue
        index = 0 if count == 0 else (count - 1) // size
        windows[index].append(record)

    result: list[dict[str, Any]] = []
    for index in sorted(windows):
        bucket = windows[index]
        guards = _guard_summary(bucket)
        guard_paths = _guard_path_summary(bucket)
        start = 1 + index * size
        end = start + size - 1
        all_counts = {count for record in bucket if (count := vm_count(record)) is not None}
        execution_counts = {
            count
            for record in bucket
            if record.marker in EXECUTION_MARKERS and (count := vm_count(record)) is not None and count > 0
        }
        result.append(
            {
                "start": start,
                "end": end,
                "marker_records": len(bucket),
                "unique_vm_counts": len(all_counts),
                "execution_vm_counts": len(execution_counts),
                "execution_coverage_ratio": round(len(execution_counts) / size, 6),
                "guards": {
                    "records": guards["records"],
                    "execution_points": guards["execution_points"],
                    "guard_names": guards["guard_names"],
                    "conflicts": guards["conflicts"]["count"],
                },
                "guard_paths": {
                    "records": guard_paths["records"],
                    "execution_points": guard_paths["execution_points"],
                    "decisions": guard_paths["decision_observations"],
                    "complete_paths": guard_paths["complete_paths"],
                    "overflow_paths": guard_paths["overflow_paths"],
                    "conflicts": guard_paths["conflicts"]["count"],
                },
                "marker_types": _marker_summary(bucket),
            }
        )
    return result


def _read_input(path: pathlib.Path) -> tuple[list[Record], dict[str, Any], StructureShape]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise CampaignError(f"cannot read {path}: {error}") from error
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CampaignError(f"{path}: trace is not UTF-8 at byte {error.start}") from error

    records: list[Record] = []
    ignored = 0
    for number, line in enumerate(text.splitlines(), 1):
        record = parse_record(line, location=f"{path}:{number}")
        if record is None:
            ignored += 1
        else:
            records.append(record)
    shape = structure_shape(records, label=str(path))
    counts = [count for record in records if (count := vm_count(record)) is not None]
    stats = {
        "path": str(path),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "lines": len(text.splitlines()),
        "marker_records": len(records),
        "ignored_lines": ignored,
        "structure": {
            "marker_records": shape.marker_records,
            "prototypes": len(shape.prototypes),
            "instructions": len(shape.instructions),
            "complete": shape_complete(shape),
            "sha256": structure_hash(shape),
        },
        "vm_count_min": min(counts) if counts else None,
        "vm_count_max": max(counts) if counts else None,
        "guards": _guard_summary(records),
        "guard_paths": _guard_path_summary(records),
    }
    return records, stats, shape


def _write_atomic(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def run_campaign(
    inputs: Sequence[pathlib.Path],
    output: pathlib.Path,
    report_path: pathlib.Path,
    *,
    window_size: int = 5000,
    output_format: str = "tsv",
    expected_structure_hash: str | None = None,
) -> dict[str, Any]:
    if not inputs:
        raise CampaignError("at least one input trace is required")
    if window_size < 1:
        raise CampaignError("window size must be at least 1")
    if output_format not in {"tsv", "jsonl"}:
        raise CampaignError("output format must be tsv or jsonl")
    if expected_structure_hash is not None and not SHA256_RE.fullmatch(expected_structure_hash):
        raise CampaignError("expected structure hash must be 64 hexadecimal characters")

    output_resolved = output.resolve()
    report_resolved = report_path.resolve()
    for path in inputs:
        resolved = path.resolve()
        if resolved in {output_resolved, report_resolved}:
            raise CampaignError("an output path cannot overwrite an input trace")
    if output_resolved == report_resolved:
        raise CampaignError("merged trace and report paths must differ")

    all_records: list[Record] = []
    input_reports: list[dict[str, Any]] = []
    merged_shape = StructureShape({}, {})
    input_shape_hashes: list[dict[str, Any]] = []
    structureless_inputs = 0
    for path in inputs:
        records, stats, shape = _read_input(path)
        all_records.extend(records)
        input_reports.append(stats)
        if not shape.prototypes and not shape.instructions:
            structureless_inputs += 1
        fingerprint = structure_hash(shape)
        if fingerprint is not None:
            input_shape_hashes.append(
                {
                    "path": str(path),
                    "sha256": fingerprint,
                    "internally_complete": shape_complete(shape),
                    "prototypes": len(shape.prototypes),
                    "instructions": len(shape.instructions),
                }
            )
        merge_shapes(merged_shape, shape, label=str(path))

    seen: set[Any] = set()
    structure_records: list[Record] = []
    dynamic_records: list[Record] = []
    duplicate_markers: Counter[str] = Counter()
    for record in all_records:
        dedupe_key = _record_dedupe_key(record)
        if dedupe_key in seen:
            duplicate_markers[record.marker] += 1
            continue
        seen.add(dedupe_key)
        target = structure_records if record.marker in STRUCTURE_MARKERS else dynamic_records
        target.append(record)
    merged_records = structure_records + dynamic_records
    guard_input_records = sum(record.marker == GUARD_MARKER for record in all_records)
    guard_path_input_records = sum(record.marker == GUARD_PATH_MARKER for record in all_records)

    merged_hash = structure_hash(merged_shape)
    complete = shape_complete(merged_shape)
    exact_shape_inputs = sum(item["sha256"] == merged_hash for item in input_shape_hashes)
    subset_shape_inputs = len(input_shape_hashes) - exact_shape_inputs
    if expected_structure_hash is not None:
        expected = expected_structure_hash.lower()
        if not complete:
            raise CampaignError("cannot validate an expected structure hash from an incomplete structure corpus")
        if merged_hash != expected:
            raise CampaignError(f"structure hash mismatch: expected {expected}, got {merged_hash}")

    renderer = Record.as_tsv if output_format == "tsv" else Record.as_jsonl
    merged_text = "\n".join(renderer(record) for record in merged_records)
    if merged_text:
        merged_text += "\n"
    merged_bytes = merged_text.encode("utf-8")
    windows = _window_summary(merged_records, window_size)
    report = {
        "schema_version": 1,
        "offline": True,
        "inputs": input_reports,
        "merge": {
            "output": str(output),
            "format": output_format,
            "input_records": len(all_records),
            "unique_records": len(merged_records),
            "duplicates_removed": len(all_records) - len(merged_records),
            "duplicates_removed_by_marker": dict(sorted(duplicate_markers.items())),
            "guard_duplicates_removed": duplicate_markers[GUARD_MARKER],
            "guard_path_duplicates_removed": duplicate_markers[GUARD_PATH_MARKER],
            "bytes": len(merged_bytes),
            "sha256": hashlib.sha256(merged_bytes).hexdigest(),
        },
        "structure": {
            "schema": STRUCTURE_HASH_SCHEMA,
            "algorithm": "sha256",
            "sha256": merged_hash,
            "complete": complete,
            "consistent": True,
            "validated": complete and (expected_structure_hash is None or merged_hash == expected_structure_hash.lower()),
            "expected_sha256": expected_structure_hash.lower() if expected_structure_hash else None,
            "prototypes": len(merged_shape.prototypes),
            "instructions": len(merged_shape.instructions),
            "declared_instructions": sum(item[0] for item in merged_shape.prototypes.values()),
            "input_shape_hashes": input_shape_hashes,
            "exact_shape_inputs": exact_shape_inputs,
            "compatible_subset_inputs": subset_shape_inputs,
            "structureless_inputs": structureless_inputs,
            "all_inputs_independently_validated": (
                complete and structureless_inputs == 0 and subset_shape_inputs == 0
            ),
        },
        "marker_types": _marker_summary(merged_records),
        "guards": _guard_summary(
            merged_records,
            input_records=guard_input_records,
            duplicates_removed=duplicate_markers[GUARD_MARKER],
        ),
        "guard_paths": _guard_path_summary(
            merged_records,
            input_records=guard_path_input_records,
            duplicates_removed=duplicate_markers[GUARD_PATH_MARKER],
        ),
        "vm_windows": {
            "size": window_size,
            "alignment": "one_based",
            "windows": windows,
        },
    }

    _write_atomic(output, merged_bytes)
    report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_atomic(report_path, report_bytes)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Merge local Luraph marker traces, validate structure, and report VM-window coverage.",
    )
    parser.add_argument("traces", nargs="+", type=pathlib.Path, help="input .log or marker JSONL traces")
    parser.add_argument("-o", "--output", required=True, type=pathlib.Path, help="deduplicated merged trace")
    parser.add_argument("--report", type=pathlib.Path, help="coverage JSON (default: OUTPUT.report.json)")
    parser.add_argument("--window-size", type=int, default=5000, help="one-based VM-count window size (default: 5000)")
    parser.add_argument("--format", choices=("tsv", "jsonl"), default="tsv", help="merged trace format (default: tsv)")
    parser.add_argument("--expected-structure-hash", metavar="SHA256", help="require this complete structure fingerprint")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    report_path = args.report or args.output.with_name(args.output.name + ".report.json")
    try:
        report = run_campaign(
            args.traces,
            args.output,
            report_path,
            window_size=args.window_size,
            output_format=args.format,
            expected_structure_hash=args.expected_structure_hash,
        )
    except CampaignError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    structure = report["structure"]
    print(
        f"merged {report['merge']['unique_records']} records; "
        f"structure={structure['sha256'] or 'unavailable'}; "
        f"windows={len(report['vm_windows']['windows'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
