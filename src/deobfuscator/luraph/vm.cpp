#include "vm.hpp"

#include <limits>

namespace alex::deobfuscator::luraph::vm
{
namespace
{

SideReference reference(ReferenceKind kind, int64_t wrapperIndex, size_t count)
{
    SideReference result;
    result.kind = kind;
    result.wrapper_index = wrapperIndex;
    if (wrapperIndex >= 1 && static_cast<uint64_t>(wrapperIndex) <= count)
    {
        result.metadata_index = static_cast<size_t>(wrapperIndex - 1);
        result.valid = true;
    }
    return result;
}

} // namespace

OperandLane normalizeLane(int64_t rawWord, size_t pc, size_t constantCount, size_t prototypeCount)
{
    OperandLane lane;
    lane.raw_word = rawWord;

    int64_t residue = rawWord % 8;
    if (residue < 0)
        residue += 8;
    lane.residue = static_cast<unsigned int>(residue);
    lane.quotient = (rawWord - residue) / 8;
    lane.base_value = lane.quotient;

    if (lane.residue == 1)
        lane.side_reference = reference(ReferenceKind::Constant, lane.quotient, constantCount);
    else if (lane.residue == 3)
        lane.side_reference = reference(ReferenceKind::Prototype, lane.quotient, prototypeCount);
    else if (lane.residue == 5)
        lane.base_value = static_cast<int64_t>(pc) - lane.quotient;
    else if (lane.residue == 6)
        lane.base_value = static_cast<int64_t>(pc) + lane.quotient;

    return lane;
}

NormalizedInstruction normalizeInstruction(
    const InstructionMetadata& instruction,
    size_t constantCount,
    size_t prototypeCount)
{
    NormalizedInstruction result;
    result.metadata_index = instruction.index;
    result.pc = instruction.index + 1;
    result.opcode = instruction.words[2].value;
    result.D = normalizeLane(instruction.words[0].value, result.pc, constantCount, prototypeCount);
    result.G = normalizeLane(instruction.words[1].value, result.pc, constantCount, prototypeCount);
    result.p = normalizeLane(instruction.words[3].value, result.pc, constantCount, prototypeCount);
    return result;
}

NormalizedContainer normalizeContainer(const ContainerAnalysis& container)
{
    NormalizedContainer result;
    result.constant_pool_mode = container.constant_pool_mode;
    result.root_wrapper_index = container.root_selector;
    if (container.root_selector >= 1 && container.root_selector <= container.prototypes.size())
    {
        result.root_metadata_index = static_cast<size_t>(container.root_selector - 1);
        result.root_valid = true;
    }

    result.prototypes.reserve(container.prototypes.size());
    for (const PrototypeMetadata& prototype : container.prototypes)
    {
        NormalizedPrototype normalized;
        normalized.metadata_index = prototype.index;
        normalized.wrapper_index = prototype.index + 1;
        normalized.register_capacity = prototype.final_value;
        normalized.instructions.reserve(prototype.instructions.size());
        for (const InstructionMetadata& instruction : prototype.instructions)
            normalized.instructions.push_back(
                normalizeInstruction(instruction, container.constants.size(), container.prototypes.size()));
        result.prototypes.push_back(std::move(normalized));
    }
    return result;
}

const char* toString(ReferenceKind kind)
{
    switch (kind)
    {
    case ReferenceKind::None: return "none";
    case ReferenceKind::Constant: return "constant";
    case ReferenceKind::Prototype: return "prototype";
    }
    return "unknown";
}

} // namespace alex::deobfuscator::luraph::vm
