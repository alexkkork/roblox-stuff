#pragma once

#include "scan.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
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

OperandLane normalizeLane(int64_t rawWord, size_t pc, size_t constantCount, size_t prototypeCount);
NormalizedInstruction normalizeInstruction(
    const InstructionMetadata& instruction,
    size_t constantCount,
    size_t prototypeCount);
NormalizedContainer normalizeContainer(const ContainerAnalysis& container);

const char* toString(ReferenceKind kind);

} // namespace alex::deobfuscator::luraph::vm
