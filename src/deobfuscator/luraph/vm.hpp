#pragma once

#include "scan.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace alex::deobfuscator::luraph::vm
{

enum class ReferenceKind
{
    None,
    Constant,
    Prototype,
};

struct SideReference
{
    ReferenceKind kind = ReferenceKind::None;
    int64_t wrapper_index = 0;
    std::optional<size_t> metadata_index;
    bool valid = false;
};

struct OperandLane
{
    int64_t raw_word = 0;
    unsigned int residue = 0;
    int64_t quotient = 0;
    int64_t base_value = 0;
    SideReference side_reference;
};

struct NormalizedInstruction
{
    size_t metadata_index = 0;
    size_t pc = 1;
    int64_t opcode = 0;
    OperandLane D;
    OperandLane G;
    OperandLane p;
};

struct NormalizedPrototype
{
    size_t metadata_index = 0;
    size_t wrapper_index = 1;
    uint64_t register_capacity = 0;
    std::vector<NormalizedInstruction> instructions;
};

struct NormalizedContainer
{
    unsigned char constant_pool_mode = 0;
    uint64_t root_wrapper_index = 0;
    std::optional<size_t> root_metadata_index;
    bool root_valid = false;
    std::vector<NormalizedPrototype> prototypes;
};

struct CaptureDescriptorShape
{
    unsigned int kind_code = 0;
    uint64_t source_index = 0;

    bool operator==(const CaptureDescriptorShape&) const = default;
};

struct ClosureTargetShape
{
    size_t source_pc = 0;
    size_t target_instruction_count = 0;
    std::vector<CaptureDescriptorShape> target_captures;

    bool operator==(const ClosureTargetShape&) const = default;
};

struct InstructionShape
{
    size_t pc = 0;
    int64_t opcode = 0;
    std::array<int64_t, 3> lanes{};

    bool operator==(const InstructionShape&) const = default;
};

// This fingerprint contains only structure visible in both the verified static
// container and a complete runtime prototype record. Runtime identifiers and
// serialized prototype indices are deliberately excluded.
struct PrototypeStructuralFingerprint
{
    bool is_root = false;
    size_t instruction_count = 0;
    std::vector<InstructionShape> opcode_lanes;
    uint64_t opcode_lane_digest = 0;
    std::vector<CaptureDescriptorShape> captures;
    std::vector<ClosureTargetShape> closure_targets;
    uint64_t digest = 0;

    bool operator==(const PrototypeStructuralFingerprint&) const = default;
};

struct StaticPrototypeShape
{
    struct ClosureEdge
    {
        size_t source_pc = 0;
        size_t target_metadata_index = 0;

        bool operator==(const ClosureEdge&) const = default;
    };

    size_t metadata_index = 0;
    size_t wrapper_index = 1;
    std::optional<size_t> parent_metadata_index;
    std::optional<size_t> parent_closure_pc;
    std::vector<ClosureEdge> closure_edges;
    PrototypeStructuralFingerprint fingerprint;
};

struct StaticPrototypeIndex
{
    bool valid = false;
    std::optional<size_t> root_metadata_index;
    std::vector<StaticPrototypeShape> prototypes;
    std::string diagnostic;
};

struct RuntimeClosureEvidence
{
    size_t source_pc = 0;
    uint64_t target_runtime_id = 0;
    std::vector<CaptureDescriptorShape> captures;
    bool captures_complete = false;
};

struct RuntimePrototypeRecord
{
    uint64_t runtime_id = 0;
    size_t instruction_count = 0;
    // A complete sequence must contain every PC exactly once in ascending order.
    std::vector<InstructionShape> opcode_lanes;
    bool opcode_lanes_complete = false;
    // nullopt means the runtime observation did not establish root identity.
    std::optional<bool> is_root;
    std::optional<uint64_t> parent_runtime_id;
    std::optional<size_t> parent_closure_pc;
    std::vector<CaptureDescriptorShape> captures;
    bool captures_complete = false;
    std::vector<RuntimeClosureEvidence> closure_targets;
    // false means closure_targets is an observed subset, not an empty set.
    bool closure_targets_complete = false;
};

enum class CorrespondenceStatus
{
    Matched,
    Ambiguous,
    Unmatched,
    InvalidEvidence,
};

enum class CorrespondenceProof
{
    GraphRoot,
    UniqueInstructionCount,
    ExactOpcodeLaneFingerprint,
    ExactCaptureShape,
    CompleteStructuralFingerprint,
    ParentClosureEdge,
    ChildClosureEdge,
};

struct PrototypeCorrespondence
{
    uint64_t runtime_id = 0;
    CorrespondenceStatus status = CorrespondenceStatus::Unmatched;
    std::optional<size_t> static_metadata_index;
    std::vector<size_t> candidate_metadata_indices;
    std::vector<CorrespondenceProof> proof;
};

struct PrototypeCorrespondenceResult
{
    bool static_evidence_valid = false;
    bool runtime_evidence_valid = false;
    size_t matched_count = 0;
    size_t ambiguous_count = 0;
    size_t unmatched_count = 0;
    std::vector<PrototypeCorrespondence> records;
    std::string diagnostic;
};

OperandLane normalizeLane(int64_t rawWord, size_t pc, size_t constantCount, size_t prototypeCount);
NormalizedInstruction normalizeInstruction(
    const InstructionMetadata& instruction,
    size_t constantCount,
    size_t prototypeCount);
NormalizedContainer normalizeContainer(const ContainerAnalysis& container);

// Digests are stable summary values. Exact field equality, never a digest
// collision assumption, drives correspondence decisions.
uint64_t fingerprintDigest(const PrototypeStructuralFingerprint& fingerprint);
uint64_t opcodeLaneFingerprintDigest(const std::vector<InstructionShape>& instructions);
// Index construction fails unless the scanner has already proved one complete,
// rooted static graph and all referenced capture descriptors are in bounds.
StaticPrototypeIndex buildStaticPrototypeIndex(const ContainerAnalysis& container);
// A complete runtime fingerprint is available only when every local structural
// component needed for exact comparison was observed.
std::optional<PrototypeStructuralFingerprint> buildRuntimePrototypeFingerprint(
    const RuntimePrototypeRecord& prototype,
    const std::vector<RuntimePrototypeRecord>& runtimePrototypes);
// Singleton matches are produced by exact constraints and graph propagation.
// Non-unique candidates remain Ambiguous and contradictory evidence is rejected.
PrototypeCorrespondenceResult correlateRuntimePrototypes(
    const StaticPrototypeIndex& staticIndex,
    const std::vector<RuntimePrototypeRecord>& runtimePrototypes);
PrototypeCorrespondenceResult correlateRuntimePrototypes(
    const ContainerAnalysis& container,
    const std::vector<RuntimePrototypeRecord>& runtimePrototypes);

const char* toString(ReferenceKind kind);
const char* toString(CorrespondenceStatus status);
const char* toString(CorrespondenceProof proof);

} // namespace alex::deobfuscator::luraph::vm
