#include "vm.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <utility>

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

void hashByte(uint64_t& hash, unsigned char value)
{
    hash ^= value;
    hash *= 1099511628211ull;
}

void hashWord(uint64_t& hash, uint64_t value)
{
    for (unsigned int shift = 0; shift < 64; shift += 8)
        hashByte(hash, static_cast<unsigned char>((value >> shift) & 0xff));
}

bool captureShapesEqual(
    const std::vector<CaptureDescriptorShape>& left,
    const std::vector<CaptureDescriptorShape>& right)
{
    return left == right;
}

std::vector<CaptureDescriptorShape> captureShape(const PrototypeMetadata& prototype, bool& valid)
{
    std::vector<CaptureDescriptorShape> result;
    result.reserve(prototype.descriptors.size());
    for (size_t index = 0; index < prototype.descriptors.size(); ++index)
    {
        const DescriptorMetadata& descriptor = prototype.descriptors[index];
        if (descriptor.index != index || !descriptor.capture_semantics_verified ||
            !descriptor.source_index_validated || !descriptor.source_index_in_bounds)
        {
            valid = false;
            return {};
        }
        result.push_back({descriptor.capture_kind_code, descriptor.capture_source_index});
    }
    return result;
}

bool containsCandidate(const std::vector<size_t>& candidates, size_t value)
{
    return std::binary_search(candidates.begin(), candidates.end(), value);
}

const StaticPrototypeShape::ClosureEdge* findStaticClosure(
    const StaticPrototypeShape& prototype,
    size_t sourcePc)
{
    auto row = std::lower_bound(
        prototype.closure_edges.begin(), prototype.closure_edges.end(), sourcePc,
        [](const StaticPrototypeShape::ClosureEdge& edge, size_t pc) { return edge.source_pc < pc; });
    return row != prototype.closure_edges.end() && row->source_pc == sourcePc ? &*row : nullptr;
}

const ClosureTargetShape* findClosureShape(
    const PrototypeStructuralFingerprint& fingerprint,
    size_t sourcePc)
{
    auto row = std::lower_bound(
        fingerprint.closure_targets.begin(), fingerprint.closure_targets.end(), sourcePc,
        [](const ClosureTargetShape& edge, size_t pc) { return edge.source_pc < pc; });
    return row != fingerprint.closure_targets.end() && row->source_pc == sourcePc ? &*row : nullptr;
}

void addProof(std::vector<CorrespondenceProof>& proofs, CorrespondenceProof proof)
{
    if (std::find(proofs.begin(), proofs.end(), proof) == proofs.end())
        proofs.push_back(proof);
}

bool validInstructionShapes(const std::vector<InstructionShape>& instructions, size_t instructionCount)
{
    if (instructions.size() != instructionCount)
        return false;
    for (size_t index = 0; index < instructions.size(); ++index)
        if (instructions[index].pc != index + 1)
            return false;
    return true;
}

InstructionShape instructionShape(const NormalizedInstruction& instruction)
{
    return {
        instruction.pc,
        instruction.opcode,
        {instruction.D.base_value, instruction.G.base_value, instruction.p.base_value},
    };
}

const OperandLane& operandLane(const NormalizedInstruction& instruction, NormalizedOperandLane lane)
{
    switch (lane)
    {
    case NormalizedOperandLane::D: return instruction.D;
    case NormalizedOperandLane::G: return instruction.G;
    case NormalizedOperandLane::p: return instruction.p;
    }
    return instruction.D;
}

bool checkedAdd(int64_t left, int64_t right, int64_t& result)
{
    if ((right > 0 && left > std::numeric_limits<int64_t>::max() - right) ||
        (right < 0 && left < std::numeric_limits<int64_t>::min() - right))
        return false;
    result = left + right;
    return true;
}

bool checkedSubtract(int64_t left, int64_t right, int64_t& result)
{
    if ((right > 0 && left < std::numeric_limits<int64_t>::min() + right) ||
        (right < 0 && left > std::numeric_limits<int64_t>::max() + right))
        return false;
    result = left - right;
    return true;
}

void recordResidue(
    OperandResidueDiagnostics& diagnostics,
    const OperandLane& lane,
    size_t prototypeMetadataIndex,
    size_t pc,
    NormalizedOperandLane laneName)
{
    ++diagnostics.operand_lane_count;
    if (lane.residue < diagnostics.counts.size())
        ++diagnostics.counts[lane.residue];
    if (lane.status == OperandLaneStatus::Valid)
    {
        ++diagnostics.valid_operand_lane_count;
        return;
    }

    ++diagnostics.invalid_operand_lane_count;
    if (!diagnostics.first_invalid_prototype_metadata_index)
    {
        diagnostics.first_invalid_prototype_metadata_index = prototypeMetadataIndex;
        diagnostics.first_invalid_pc = pc;
        diagnostics.first_invalid_lane = laneName;
        diagnostics.first_invalid_residue = lane.residue;
    }
}

} // namespace

InstructionSchemaSelection selectInstructionSchema(const ContainerAnalysis& container)
{
    InstructionSchemaSelection result;
    result.lph_dollar_marker = container.marker == '$';
    result.transport_validated = container.decode_status == ContainerDecodeStatus::Decoded;
    result.structural_metadata_validated =
        container.parse_status == ContainerParseStatus::StructuralMetadataRecovered;
    result.static_graph_validated = container.prototype_graph_complete &&
        container.root_selector_graph_validated && container.root_selector_in_bounds &&
        container.root_metadata_index.has_value() &&
        *container.root_metadata_index < container.prototypes.size() &&
        container.prototype_count == container.prototypes.size() &&
        container.root_selector == *container.root_metadata_index + 1;

    if (!result.lph_dollar_marker)
    {
        result.schema = InstructionSchema::LegacyV147;
        result.status = InstructionSchemaSelectionStatus::Selected;
        result.diagnostic = "legacy v14.7 schema selected because the carrier is not LPH$";
        return result;
    }

    result.schema = InstructionSchema::LuaAuthLphDollar;
    if (!result.transport_validated || !result.structural_metadata_validated ||
        !result.static_graph_validated)
    {
        result.status = InstructionSchemaSelectionStatus::InvalidEvidence;
        result.diagnostic =
            "LPH$ schema withheld because decoded transport, structural metadata, and a complete rooted static graph were not all validated";
        return result;
    }

    result.status = InstructionSchemaSelectionStatus::Selected;
    result.diagnostic =
        "LuaAuth LPH$ schema selected from validated framing, structural metadata, and rooted static graph evidence";
    return result;
}

OperandLane normalizeLane(
    int64_t rawWord,
    size_t pc,
    size_t constantCount,
    size_t prototypeCount,
    InstructionSchema schema)
{
    OperandLane lane;
    lane.raw_word = rawWord;

    int64_t residue = rawWord % 8;
    if (residue < 0)
        residue += 8;
    lane.residue = static_cast<unsigned int>(residue);
    lane.quotient = (rawWord - residue) / 8;
    lane.base_value = lane.quotient;

    if (schema == InstructionSchema::LegacyV147)
    {
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

    if (lane.residue == 5 || lane.residue == 6)
    {
        lane.status = OperandLaneStatus::InvalidResidue;
        return lane;
    }
    if (lane.residue != 3 && lane.residue != 4)
        return lane;
    if (pc > static_cast<size_t>(std::numeric_limits<int64_t>::max()))
    {
        lane.status = OperandLaneStatus::PcOutOfRange;
        return lane;
    }

    const int64_t signedPc = static_cast<int64_t>(pc);
    const bool valid = lane.residue == 3
        ? checkedSubtract(signedPc, lane.quotient, lane.base_value)
        : checkedAdd(signedPc, lane.quotient, lane.base_value);
    if (!valid)
        lane.status = OperandLaneStatus::ArithmeticOverflow;

    return lane;
}

OperandLane normalizeLane(int64_t rawWord, size_t pc, size_t constantCount, size_t prototypeCount)
{
    return normalizeLane(rawWord, pc, constantCount, prototypeCount, InstructionSchema::LegacyV147);
}

NormalizedInstruction normalizeInstruction(
    const InstructionMetadata& instruction,
    size_t constantCount,
    size_t prototypeCount,
    InstructionSchema schema)
{
    NormalizedInstruction result;
    result.metadata_index = instruction.index;
    result.pc = instruction.index + 1;
    if (schema == InstructionSchema::LuaAuthLphDollar)
    {
        result.opcode = instruction.words[0].value;
        result.D = normalizeLane(instruction.words[2].value, result.pc, constantCount, prototypeCount, schema);
        result.G = normalizeLane(instruction.words[1].value, result.pc, constantCount, prototypeCount, schema);
        result.p = normalizeLane(instruction.words[3].value, result.pc, constantCount, prototypeCount, schema);
    }
    else
    {
        result.opcode = instruction.words[2].value;
        result.D = normalizeLane(instruction.words[0].value, result.pc, constantCount, prototypeCount, schema);
        result.G = normalizeLane(instruction.words[1].value, result.pc, constantCount, prototypeCount, schema);
        result.p = normalizeLane(instruction.words[3].value, result.pc, constantCount, prototypeCount, schema);
    }
    result.valid = result.D.status == OperandLaneStatus::Valid &&
        result.G.status == OperandLaneStatus::Valid && result.p.status == OperandLaneStatus::Valid;
    return result;
}

NormalizedInstruction normalizeInstruction(
    const InstructionMetadata& instruction,
    size_t constantCount,
    size_t prototypeCount)
{
    return normalizeInstruction(
        instruction, constantCount, prototypeCount, InstructionSchema::LegacyV147);
}

NormalizedContainer normalizeContainer(const ContainerAnalysis& container)
{
    NormalizedContainer result;
    result.schema_selection = selectInstructionSchema(container);
    result.constant_pool_mode = container.constant_pool_mode;
    result.root_wrapper_index = container.root_selector;
    if (result.schema_selection.status != InstructionSchemaSelectionStatus::Selected)
    {
        result.residue_diagnostics.diagnostic =
            "operand residues were not decoded because instruction schema evidence is invalid";
        return result;
    }
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
        {
            NormalizedInstruction row = normalizeInstruction(instruction, container.constants.size(),
                container.prototypes.size(), result.schema_selection.schema);
            recordResidue(result.residue_diagnostics, row.D, prototype.index, row.pc, NormalizedOperandLane::D);
            recordResidue(result.residue_diagnostics, row.G, prototype.index, row.pc, NormalizedOperandLane::G);
            recordResidue(result.residue_diagnostics, row.p, prototype.index, row.pc, NormalizedOperandLane::p);
            normalized.instructions.push_back(std::move(row));
        }
        result.prototypes.push_back(std::move(normalized));
    }
    result.valid = result.residue_diagnostics.invalid_operand_lane_count == 0;
    result.residue_diagnostics.diagnostic = result.valid
        ? "all operand residues are valid for the selected instruction schema"
        : "one or more operand residues are invalid for the selected instruction schema";
    return result;
}

OperandLaneProjectionResult inferOperandLaneProjection(
    const NormalizedContainer& staticContainer,
    const std::vector<RuntimeOperandLaneAnchor>& runtimeAnchors)
{
    OperandLaneProjectionResult result;
    const auto invalid = [&](std::string diagnostic) {
        result.status = OperandLaneProjectionStatus::InvalidEvidence;
        result.uniquely_matched_anchor_count = 0;
        result.anchor_metadata_indices.clear();
        result.candidates.clear();
        result.diagnostic = std::move(diagnostic);
        return result;
    };

    if (staticContainer.prototypes.empty())
        return invalid("normalized static container has no prototypes");

    std::set<size_t> staticMetadataIndices;
    std::map<size_t, std::vector<const NormalizedPrototype*>> staticByInstructionCount;
    for (const NormalizedPrototype& prototype : staticContainer.prototypes)
    {
        if (!staticMetadataIndices.insert(prototype.metadata_index).second)
            return invalid("normalized static prototype metadata indices are not unique");
        for (size_t index = 0; index < prototype.instructions.size(); ++index)
        {
            const NormalizedInstruction& instruction = prototype.instructions[index];
            if (instruction.metadata_index != index || instruction.pc != index + 1)
                return invalid("normalized static prototype instruction order is inconsistent");
        }
        staticByInstructionCount[prototype.instructions.size()].push_back(&prototype);
    }

    if (runtimeAnchors.empty())
    {
        result.status = OperandLaneProjectionStatus::InsufficientEvidence;
        result.diagnostic = "no runtime operand-lane anchors were supplied";
        return result;
    }

    struct MatchedAnchor
    {
        const NormalizedPrototype* prototype = nullptr;
        std::map<std::string, const std::vector<int64_t>*> sequences;
    };

    std::vector<std::string> expectedNames;
    std::vector<MatchedAnchor> matchedAnchors;
    std::set<size_t> distinctAnchorMetadataIndices;
    for (size_t anchorIndex = 0; anchorIndex < runtimeAnchors.size(); ++anchorIndex)
    {
        const RuntimeOperandLaneAnchor& anchor = runtimeAnchors[anchorIndex];
        std::map<std::string, const std::vector<int64_t>*> sequences;
        for (const NamedRuntimeOperandLaneSequence& lane : anchor.lanes)
        {
            if (lane.name.empty() || !sequences.emplace(lane.name, &lane.values).second)
                return invalid("runtime operand-lane names must be nonempty and unique within each anchor");
            if (lane.values.size() != anchor.instruction_count)
                return invalid("runtime operand-lane sequence length does not equal its anchor instruction count");
        }

        std::vector<std::string> names;
        names.reserve(sequences.size());
        for (const auto& [name, values] : sequences)
        {
            (void)values;
            names.push_back(name);
        }
        if (anchorIndex == 0)
        {
            if (names.size() < 3)
                return invalid("runtime anchors must expose at least three named operand lanes");
            expectedNames = names;
        }
        else if (names != expectedNames)
        {
            return invalid("runtime anchors do not expose the same operand-lane names");
        }

        auto staticRows = staticByInstructionCount.find(anchor.instruction_count);
        if (staticRows == staticByInstructionCount.end() || staticRows->second.size() != 1)
            continue;

        const NormalizedPrototype* prototype = staticRows->second.front();
        matchedAnchors.push_back({prototype, std::move(sequences)});
        result.anchor_metadata_indices.push_back(prototype->metadata_index);
        distinctAnchorMetadataIndices.insert(prototype->metadata_index);
    }

    result.uniquely_matched_anchor_count = matchedAnchors.size();
    if (distinctAnchorMetadataIndices.size() < 2)
    {
        result.status = OperandLaneProjectionStatus::InsufficientEvidence;
        result.diagnostic = "fewer than two distinct runtime anchors uniquely match static instruction counts";
        return result;
    }

    constexpr std::array<NormalizedOperandLane, 3> normalizedLanes{
        NormalizedOperandLane::D,
        NormalizedOperandLane::G,
        NormalizedOperandLane::p,
    };
    std::array<std::vector<std::string>, 3> matchingNames;
    for (size_t laneIndex = 0; laneIndex < normalizedLanes.size(); ++laneIndex)
    {
        const NormalizedOperandLane normalizedLane = normalizedLanes[laneIndex];
        for (const std::string& name : expectedNames)
        {
            bool matchesEveryAnchor = true;
            for (const MatchedAnchor& anchor : matchedAnchors)
            {
                const std::vector<int64_t>& runtimeSequence = *anchor.sequences.at(name);
                const std::vector<NormalizedInstruction>& staticInstructions = anchor.prototype->instructions;
                if (!std::equal(runtimeSequence.begin(), runtimeSequence.end(), staticInstructions.begin(),
                        staticInstructions.end(), [&](int64_t runtimeValue, const NormalizedInstruction& instruction) {
                            return runtimeValue == operandLane(instruction, normalizedLane).base_value;
                        }))
                {
                    matchesEveryAnchor = false;
                    break;
                }
            }
            if (matchesEveryAnchor)
                matchingNames[laneIndex].push_back(name);
        }
    }

    for (const std::string& dName : matchingNames[0])
    {
        for (const std::string& gName : matchingNames[1])
        {
            if (gName == dName)
                continue;
            for (const std::string& pName : matchingNames[2])
            {
                if (pName == dName || pName == gName)
                    continue;
                OperandLaneProjection projection;
                projection.bindings = {{
                    {dName, NormalizedOperandLane::D},
                    {gName, NormalizedOperandLane::G},
                    {pName, NormalizedOperandLane::p},
                }};
                result.candidates.push_back(std::move(projection));
            }
        }
    }

    if (result.candidates.empty())
    {
        result.status = OperandLaneProjectionStatus::Contradictory;
        result.diagnostic = "no injective operand-lane projection matches every uniquely count-matched anchor";
    }
    else if (result.candidates.size() == 1)
    {
        result.status = OperandLaneProjectionStatus::Unique;
        result.diagnostic = "one operand-lane projection exactly matches every uniquely count-matched anchor";
    }
    else
    {
        result.status = OperandLaneProjectionStatus::Ambiguous;
        result.diagnostic = std::to_string(result.candidates.size()) +
            " operand-lane projections exactly match every uniquely count-matched anchor";
    }
    return result;
}

uint64_t fingerprintDigest(const PrototypeStructuralFingerprint& fingerprint)
{
    uint64_t hash = 1469598103934665603ull;
    hashByte(hash, 2);
    hashByte(hash, fingerprint.is_root ? 1 : 0);
    hashWord(hash, fingerprint.instruction_count);
    hashWord(hash, fingerprint.opcode_lane_digest);
    hashByte(hash, fingerprint.captures_complete ? 1 : 0);
    hashWord(hash, fingerprint.captures.size());
    for (const CaptureDescriptorShape& capture : fingerprint.captures)
    {
        hashWord(hash, capture.kind_code);
        hashWord(hash, capture.source_index);
    }
    hashByte(hash, fingerprint.closure_targets_complete ? 1 : 0);
    hashWord(hash, fingerprint.closure_targets.size());
    for (const ClosureTargetShape& closure : fingerprint.closure_targets)
    {
        hashWord(hash, closure.source_pc);
        hashWord(hash, closure.target_instruction_count);
        hashByte(hash, closure.target_captures_complete ? 1 : 0);
        hashWord(hash, closure.target_captures.size());
        for (const CaptureDescriptorShape& capture : closure.target_captures)
        {
            hashWord(hash, capture.kind_code);
            hashWord(hash, capture.source_index);
        }
    }
    return hash;
}

uint64_t opcodeLaneFingerprintDigest(const std::vector<InstructionShape>& instructions)
{
    uint64_t hash = 1469598103934665603ull;
    hashByte(hash, 1);
    hashWord(hash, instructions.size());
    for (const InstructionShape& instruction : instructions)
    {
        hashWord(hash, instruction.pc);
        hashWord(hash, static_cast<uint64_t>(instruction.opcode));
        for (int64_t lane : instruction.lanes)
            hashWord(hash, static_cast<uint64_t>(lane));
    }
    return hash;
}

StaticPrototypeIndex buildStaticPrototypeIndex(const ContainerAnalysis& container)
{
    StaticPrototypeIndex result;
    result.schema_selection = selectInstructionSchema(container);
    const auto fail = [&](std::string diagnostic) {
        result.valid = false;
        result.prototypes.clear();
        result.root_metadata_index.reset();
        result.diagnostic = std::move(diagnostic);
        return result;
    };

    if (result.schema_selection.status != InstructionSchemaSelectionStatus::Selected)
        return fail(result.schema_selection.diagnostic);

    if (container.prototype_count != container.prototypes.size() || container.prototypes.empty())
        return fail("static prototype count is inconsistent");
    if (!container.root_metadata_index || !container.root_selector_in_bounds)
        return fail("static root selector is not in bounds");
    if (*container.root_metadata_index >= container.prototypes.size() || container.root_selector == 0 ||
        container.root_selector - 1 != *container.root_metadata_index)
        return fail("static root selector is inconsistent");

    const size_t prototypeCount = container.prototypes.size();
    const bool completeStaticGraph = container.prototype_graph_complete &&
        container.root_selector_graph_validated;
    result.graph_complete = completeStaticGraph;
    result.root_graph_validated = container.root_selector_graph_validated;

    if (!completeStaticGraph)
        return fail("static prototype graph is not completely proven");

    if (container.invalid_prototype_reference_count != 0 || container.invalid_capture_descriptor_count != 0)
        return fail("static graph contains an invalid reference or capture descriptor");

    const NormalizedContainer normalizedContainer = normalizeContainer(container);
    result.residue_diagnostics = normalizedContainer.residue_diagnostics;
    if (!normalizedContainer.valid || normalizedContainer.prototypes.size() != container.prototypes.size())
        return fail(normalizedContainer.residue_diagnostics.diagnostic.empty()
                ? "static instructions are invalid for the selected instruction schema"
                : normalizedContainer.residue_diagnostics.diagnostic);

    std::vector<std::vector<StaticPrototypeShape::ClosureEdge>> closureEdges(prototypeCount);
    std::vector<std::optional<size_t>> parentClosurePc(prototypeCount);
    std::vector<size_t> actualIncoming(prototypeCount, 0);
    size_t actualReferenceCount = 0;
    size_t actualClosureCount = 0;
    size_t actualCaptureCount = 0;

    for (size_t index = 0; index < prototypeCount; ++index)
    {
        const PrototypeMetadata& prototype = container.prototypes[index];
        if (prototype.index != index || prototype.instruction_count != prototype.instructions.size())
            return fail("static prototype metadata or instruction count is inconsistent");
        for (size_t instructionIndex = 0; instructionIndex < prototype.instructions.size(); ++instructionIndex)
            if (prototype.instructions[instructionIndex].index != instructionIndex)
                return fail("static prototype instruction order is inconsistent");
        if (index == *container.root_metadata_index)
        {
            if (prototype.parent_prototype_index || prototype.incoming_prototype_reference_count != 0)
                return fail("static root has an incoming prototype edge");
        }
        else
        {
            if (!prototype.parent_prototype_index || *prototype.parent_prototype_index >= prototypeCount ||
                prototype.incoming_prototype_reference_count != 1)
                return fail("static non-root prototype does not have one proven parent");
        }

        bool capturesValid = true;
        (void)captureShape(prototype, capturesValid);
        if (!capturesValid)
            return fail("static prototype has an unverified capture descriptor");
        actualCaptureCount += prototype.descriptors.size();

        std::set<size_t> closurePcs;
        for (const PrototypeReferenceMetadata& reference : prototype.prototype_references)
        {
            if (!reference.in_bounds || !reference.metadata_index || *reference.metadata_index >= prototypeCount)
                return fail("static prototype reference is not in bounds");
            if (reference.instruction_index >= prototype.instruction_count || reference.operand_word_index >= 4)
                return fail("static prototype reference has an invalid instruction location");
            const size_t target = *reference.metadata_index;
            if (container.prototypes[target].parent_prototype_index != std::optional<size_t>(index))
                return fail("static prototype reference disagrees with the proven parent graph");
            ++actualIncoming[target];
            ++actualReferenceCount;
            if (!reference.closure_target)
                continue;
            if (reference.opcode != 112)
                return fail("static closure target does not use the proven opcode-112 layout");
            const size_t sourcePc = reference.instruction_index + 1;
            if (sourcePc == 0 || sourcePc > prototype.instruction_count || !closurePcs.insert(sourcePc).second)
                return fail("static closure target has an invalid or duplicate source PC");
            if (reference.capture_descriptor_count != container.prototypes[target].descriptors.size())
                return fail("static closure target disagrees with the proven prototype graph");
            closureEdges[index].push_back({sourcePc, target});
            ++actualClosureCount;
            if (parentClosurePc[target] && *parentClosurePc[target] != sourcePc)
                return fail("static child has multiple closure-construction sites");
            parentClosurePc[target] = sourcePc;
        }
    }

    for (size_t index = 0; index < prototypeCount; ++index)
    {
        const size_t expectedIncoming = index == *container.root_metadata_index ? 0 : 1;
        if (actualIncoming[index] != expectedIncoming ||
            actualIncoming[index] != container.prototypes[index].incoming_prototype_reference_count)
            return fail("static incoming prototype edges are inconsistent");
    }
    if (actualReferenceCount != container.prototype_reference_count ||
        actualReferenceCount != container.valid_prototype_reference_count ||
        actualClosureCount != container.closure_target_count ||
        actualCaptureCount != container.validated_capture_descriptor_count)
        return fail("static graph aggregate counts are inconsistent");

    std::vector<std::vector<size_t>> children(prototypeCount);
    for (size_t child = 0; child < prototypeCount; ++child)
        if (container.prototypes[child].parent_prototype_index)
            children[*container.prototypes[child].parent_prototype_index].push_back(child);
    std::vector<bool> reached(prototypeCount, false);
    std::vector<size_t> pending{*container.root_metadata_index};
    while (!pending.empty())
    {
        const size_t current = pending.back();
        pending.pop_back();
        if (reached[current])
            return fail("static prototype graph contains a cycle");
        reached[current] = true;
        pending.insert(pending.end(), children[current].begin(), children[current].end());
    }
    if (std::find(reached.begin(), reached.end(), false) != reached.end())
        return fail("static prototype graph is not fully reachable from its root");

    result.prototypes.reserve(prototypeCount);
    for (size_t index = 0; index < prototypeCount; ++index)
    {
        const PrototypeMetadata& prototype = container.prototypes[index];
        const NormalizedPrototype& normalizedPrototype = normalizedContainer.prototypes[index];
        StaticPrototypeShape row;
        row.metadata_index = index;
        row.wrapper_index = index + 1;
        row.parent_metadata_index = prototype.parent_prototype_index;
        row.parent_closure_pc = parentClosurePc[index];
        row.closure_edges = std::move(closureEdges[index]);
        std::sort(row.closure_edges.begin(), row.closure_edges.end(), [](const auto& left, const auto& right) {
            return left.source_pc < right.source_pc;
        });

        row.fingerprint.is_root = index == *container.root_metadata_index;
        row.fingerprint.instruction_count = prototype.instruction_count;
        row.fingerprint.opcode_lanes.reserve(normalizedPrototype.instructions.size());
        for (const NormalizedInstruction& instruction : normalizedPrototype.instructions)
            row.fingerprint.opcode_lanes.push_back(instructionShape(instruction));
        row.fingerprint.opcode_lane_digest = opcodeLaneFingerprintDigest(row.fingerprint.opcode_lanes);
        bool capturesValid = true;
        row.fingerprint.captures = captureShape(prototype, capturesValid);
        row.fingerprint.captures_complete = true;
        for (const StaticPrototypeShape::ClosureEdge& edge : row.closure_edges)
        {
            const PrototypeMetadata& target = container.prototypes[edge.target_metadata_index];
            bool targetCapturesValid = true;
            row.fingerprint.closure_targets.push_back({
                edge.source_pc,
                target.instruction_count,
                captureShape(target, targetCapturesValid),
                true,
            });
            if (!targetCapturesValid)
                return fail("static closure target has an unverified capture descriptor");
        }
        row.fingerprint.closure_targets_complete = true;
        row.fingerprint.digest = fingerprintDigest(row.fingerprint);
        result.prototypes.push_back(std::move(row));
    }

    result.valid = true;
    result.graph_complete = true;
    result.root_graph_validated = true;
    result.root_metadata_index = container.root_metadata_index;
    result.diagnostic = "static prototype graph indexed without inferred edges";
    return result;
}

std::optional<PrototypeStructuralFingerprint> buildRuntimePrototypeFingerprint(
    const RuntimePrototypeRecord& prototype,
    const std::vector<RuntimePrototypeRecord>& runtimePrototypes)
{
    if (prototype.runtime_id == 0 || !prototype.is_root || !prototype.opcode_lanes_complete ||
        !validInstructionShapes(prototype.opcode_lanes, prototype.instruction_count) ||
        !prototype.captures_complete ||
        !prototype.closure_targets_complete)
        return std::nullopt;

    std::map<uint64_t, const RuntimePrototypeRecord*> records;
    for (const RuntimePrototypeRecord& row : runtimePrototypes)
        if (row.runtime_id == 0 || !records.emplace(row.runtime_id, &row).second)
            return std::nullopt;

    PrototypeStructuralFingerprint result;
    result.is_root = *prototype.is_root;
    result.instruction_count = prototype.instruction_count;
    result.opcode_lanes = prototype.opcode_lanes;
    result.opcode_lane_digest = opcodeLaneFingerprintDigest(result.opcode_lanes);
    result.captures = prototype.captures;
    result.captures_complete = true;
    std::set<size_t> sourcePcs;
    for (const RuntimeClosureEvidence& closure : prototype.closure_targets)
    {
        auto target = records.find(closure.target_runtime_id);
        if (closure.source_pc == 0 || closure.source_pc > prototype.instruction_count ||
            !sourcePcs.insert(closure.source_pc).second || target == records.end() ||
            !target->second->captures_complete)
            return std::nullopt;
        if (closure.captures_complete && !captureShapesEqual(closure.captures, target->second->captures))
            return std::nullopt;
        result.closure_targets.push_back({
            closure.source_pc,
            target->second->instruction_count,
            target->second->captures,
            true,
        });
    }
    std::sort(result.closure_targets.begin(), result.closure_targets.end(), [](const auto& left, const auto& right) {
        return left.source_pc < right.source_pc;
    });
    result.closure_targets_complete = true;
    result.digest = fingerprintDigest(result);
    return result;
}

PrototypeCorrespondenceResult correlateRuntimePrototypes(
    const StaticPrototypeIndex& staticIndex,
    const std::vector<RuntimePrototypeRecord>& runtimePrototypes)
{
    PrototypeCorrespondenceResult result;
    const auto appendInvalidRecords = [&]() {
        std::vector<uint64_t> ids;
        ids.reserve(runtimePrototypes.size());
        for (const RuntimePrototypeRecord& row : runtimePrototypes)
            ids.push_back(row.runtime_id);
        std::sort(ids.begin(), ids.end());
        for (uint64_t id : ids)
        {
            PrototypeCorrespondence invalid;
            invalid.runtime_id = id;
            invalid.status = CorrespondenceStatus::InvalidEvidence;
            result.records.push_back(std::move(invalid));
        }
    };
    result.static_evidence_valid = staticIndex.valid;
    if (!staticIndex.valid || !staticIndex.root_metadata_index || staticIndex.prototypes.empty())
    {
        result.diagnostic = staticIndex.diagnostic.empty()
            ? "static prototype evidence is not valid" : staticIndex.diagnostic;
        appendInvalidRecords();
        return result;
    }

    size_t indexedRoots = 0;
    for (size_t index = 0; index < staticIndex.prototypes.size(); ++index)
    {
        const StaticPrototypeShape& row = staticIndex.prototypes[index];
        indexedRoots += row.fingerprint.is_root ? 1 : 0;
        if (row.metadata_index != index || row.wrapper_index != index + 1 ||
            !validInstructionShapes(row.fingerprint.opcode_lanes, row.fingerprint.instruction_count) ||
            row.fingerprint.opcode_lane_digest !=
                opcodeLaneFingerprintDigest(row.fingerprint.opcode_lanes) ||
            row.fingerprint.digest != fingerprintDigest(row.fingerprint) ||
            row.fingerprint.is_root != (index == *staticIndex.root_metadata_index) ||
            (row.parent_metadata_index && *row.parent_metadata_index >= staticIndex.prototypes.size()) ||
            row.closure_edges.size() != row.fingerprint.closure_targets.size())
        {
            result.static_evidence_valid = false;
            result.diagnostic = "static prototype index is internally inconsistent";
            appendInvalidRecords();
            return result;
        }
        for (size_t edgeIndex = 0; edgeIndex < row.closure_edges.size(); ++edgeIndex)
        {
            const StaticPrototypeShape::ClosureEdge& edge = row.closure_edges[edgeIndex];
            const ClosureTargetShape& shape = row.fingerprint.closure_targets[edgeIndex];
            if (edge.source_pc == 0 || edge.source_pc > row.fingerprint.instruction_count ||
                edge.target_metadata_index >= staticIndex.prototypes.size() ||
                shape.source_pc != edge.source_pc ||
                shape.target_instruction_count !=
                    staticIndex.prototypes[edge.target_metadata_index].fingerprint.instruction_count ||
                shape.target_captures_complete !=
                    staticIndex.prototypes[edge.target_metadata_index].fingerprint.captures_complete ||
                shape.target_captures !=
                    staticIndex.prototypes[edge.target_metadata_index].fingerprint.captures ||
                (edgeIndex > 0 && row.closure_edges[edgeIndex - 1].source_pc >= edge.source_pc))
            {
                result.static_evidence_valid = false;
                result.diagnostic = "static closure index is internally inconsistent";
                appendInvalidRecords();
                return result;
            }
        }
    }
    if (indexedRoots != 1)
    {
        result.static_evidence_valid = false;
        result.diagnostic = "static prototype index does not contain exactly one root";
        appendInvalidRecords();
        return result;
    }

    const auto invalidRuntime = [&](std::string diagnostic) {
        result.runtime_evidence_valid = false;
        result.records.clear();
        result.diagnostic = std::move(diagnostic);
        appendInvalidRecords();
        return result;
    };

    std::map<uint64_t, const RuntimePrototypeRecord*> runtime;
    size_t explicitRoots = 0;
    for (const RuntimePrototypeRecord& row : runtimePrototypes)
    {
        if (row.runtime_id == 0 || !runtime.emplace(row.runtime_id, &row).second ||
            (row.parent_closure_pc && !row.parent_runtime_id))
            return invalidRuntime("runtime prototype identifiers or parent evidence are invalid");
        if (row.opcode_lanes_complete &&
            !validInstructionShapes(row.opcode_lanes, row.instruction_count))
            return invalidRuntime("complete runtime opcode/lane fingerprint is malformed");
        explicitRoots += row.is_root == std::optional<bool>(true) ? 1 : 0;
    }
    if (explicitRoots > 1)
        return invalidRuntime("runtime evidence identifies more than one root");

    std::map<uint64_t, std::pair<uint64_t, size_t>> observedParents;
    for (const RuntimePrototypeRecord& row : runtimePrototypes)
    {
        if (row.parent_runtime_id && !runtime.contains(*row.parent_runtime_id))
            return invalidRuntime("runtime parent identifier is absent");
        if (row.parent_runtime_id && row.parent_closure_pc &&
            *row.parent_closure_pc > runtime.at(*row.parent_runtime_id)->instruction_count)
            return invalidRuntime("runtime parent closure PC is outside the parent prototype");
        std::set<size_t> sourcePcs;
        for (const RuntimeClosureEvidence& closure : row.closure_targets)
        {
            if (closure.source_pc == 0 || closure.source_pc > row.instruction_count ||
                closure.target_runtime_id == 0 || !runtime.contains(closure.target_runtime_id) ||
                !sourcePcs.insert(closure.source_pc).second || closure.target_runtime_id == row.runtime_id)
                return invalidRuntime("runtime closure evidence is malformed");
            auto [parent, inserted] = observedParents.emplace(
                closure.target_runtime_id, std::pair<uint64_t, size_t>{row.runtime_id, closure.source_pc});
            if (!inserted && parent->second != std::pair<uint64_t, size_t>{row.runtime_id, closure.source_pc})
                return invalidRuntime("runtime prototype has multiple observed parents");
            const RuntimePrototypeRecord& target = *runtime.at(closure.target_runtime_id);
            if (closure.captures_complete && target.captures_complete &&
                !captureShapesEqual(closure.captures, target.captures))
                return invalidRuntime("runtime closure captures disagree with the target prototype");
        }
    }
    for (const auto& [id, row] : runtime)
    {
        auto observed = observedParents.find(id);
        if (row->is_root == std::optional<bool>(true) &&
            (row->parent_runtime_id || observed != observedParents.end()))
            return invalidRuntime("runtime root has parent evidence");
        if (row->parent_runtime_id && observed != observedParents.end() &&
            (*row->parent_runtime_id != observed->second.first ||
                (row->parent_closure_pc && *row->parent_closure_pc != observed->second.second)))
            return invalidRuntime("runtime parent fields contradict closure evidence");
        if (row->parent_runtime_id)
        {
            const RuntimePrototypeRecord& parent = *runtime.at(*row->parent_runtime_id);
            if (parent.closure_targets_complete && observed == observedParents.end())
                return invalidRuntime("complete runtime parent omits the declared child closure");
        }
    }
    result.runtime_evidence_valid = true;

    std::map<uint64_t, std::vector<size_t>> candidates;
    for (const auto& [id, runtimeRow] : runtime)
    {
        std::optional<PrototypeStructuralFingerprint> completeFingerprint =
            buildRuntimePrototypeFingerprint(*runtimeRow, runtimePrototypes);
        for (const StaticPrototypeShape& staticRow : staticIndex.prototypes)
        {
            if (staticRow.fingerprint.instruction_count != runtimeRow->instruction_count)
                continue;
            if (runtimeRow->opcode_lanes_complete &&
                staticRow.fingerprint.opcode_lanes != runtimeRow->opcode_lanes)
                continue;
            if (runtimeRow->is_root && staticRow.fingerprint.is_root != *runtimeRow->is_root)
                continue;
            if (runtimeRow->captures_complete && staticRow.fingerprint.captures_complete &&
                !captureShapesEqual(staticRow.fingerprint.captures, runtimeRow->captures))
                continue;
            if (runtimeRow->parent_closure_pc &&
                staticRow.parent_closure_pc != runtimeRow->parent_closure_pc)
                continue;
            if (completeFingerprint && staticRow.fingerprint.captures_complete &&
                staticRow.fingerprint.closure_targets_complete &&
                staticRow.fingerprint != *completeFingerprint)
                continue;

            bool closuresMatch = true;
            for (const RuntimeClosureEvidence& closure : runtimeRow->closure_targets)
            {
                const ClosureTargetShape* staticClosure = findClosureShape(staticRow.fingerprint, closure.source_pc);
                const RuntimePrototypeRecord& target = *runtime.at(closure.target_runtime_id);
                if (!staticClosure || staticClosure->target_instruction_count != target.instruction_count ||
                    (closure.captures_complete && staticClosure->target_captures_complete &&
                        !captureShapesEqual(staticClosure->target_captures, closure.captures)))
                {
                    closuresMatch = false;
                    break;
                }
            }
            if (!closuresMatch || (runtimeRow->closure_targets_complete &&
                    staticRow.fingerprint.closure_targets_complete &&
                    runtimeRow->closure_targets.size() != staticRow.closure_edges.size()))
                continue;
            candidates[id].push_back(staticRow.metadata_index);
        }
    }

    bool changed = true;
    while (changed)
    {
        changed = false;
        for (const auto& [id, runtimeRow] : runtime)
        {
            std::vector<size_t>& rows = candidates[id];
            const size_t before = rows.size();
            rows.erase(std::remove_if(rows.begin(), rows.end(), [&](size_t staticIndexValue) {
                const StaticPrototypeShape& staticRow = staticIndex.prototypes[staticIndexValue];
                if (runtimeRow->parent_runtime_id)
                {
                    const std::vector<size_t>& parentCandidates = candidates[*runtimeRow->parent_runtime_id];
                    if (runtimeRow->parent_closure_pc)
                    {
                        const bool compatibleParent = std::any_of(
                            parentCandidates.begin(), parentCandidates.end(), [&](size_t parentIndex) {
                                const StaticPrototypeShape::ClosureEdge* edge = findStaticClosure(
                                    staticIndex.prototypes[parentIndex], *runtimeRow->parent_closure_pc);
                                return edge && edge->target_metadata_index == staticIndexValue;
                            });
                        if (!compatibleParent)
                            return true;
                    }
                    else if (staticRow.parent_metadata_index &&
                        !containsCandidate(parentCandidates, *staticRow.parent_metadata_index))
                        return true;
                }
                for (const RuntimeClosureEvidence& closure : runtimeRow->closure_targets)
                {
                    const StaticPrototypeShape::ClosureEdge* edge = findStaticClosure(staticRow, closure.source_pc);
                    if (!edge || !containsCandidate(candidates[closure.target_runtime_id], edge->target_metadata_index))
                        return true;
                }
                return false;
            }), rows.end());
            changed = changed || rows.size() != before;
        }

        std::map<size_t, std::vector<uint64_t>> singletonOwners;
        for (const auto& [id, rows] : candidates)
            if (rows.size() == 1)
                singletonOwners[rows.front()].push_back(id);
        for (const auto& [staticPrototype, owners] : singletonOwners)
        {
            if (owners.size() != 1)
                continue;
            for (auto& [id, rows] : candidates)
            {
                if (id == owners.front() || rows.size() <= 1)
                    continue;
                const size_t before = rows.size();
                rows.erase(std::remove(rows.begin(), rows.end(), staticPrototype), rows.end());
                changed = changed || rows.size() != before;
            }
        }
    }

    std::map<size_t, size_t> singletonUseCount;
    for (const auto& [id, rows] : candidates)
        if (rows.size() == 1)
            ++singletonUseCount[rows.front()];

    for (const auto& [id, runtimeRow] : runtime)
    {
        PrototypeCorrespondence row;
        row.runtime_id = id;
        row.candidate_metadata_indices = candidates[id];
        if (row.candidate_metadata_indices.empty())
        {
            row.status = CorrespondenceStatus::Unmatched;
            ++result.unmatched_count;
        }
        else if (row.candidate_metadata_indices.size() == 1 &&
            singletonUseCount[row.candidate_metadata_indices.front()] == 1)
        {
            row.status = CorrespondenceStatus::Matched;
            row.static_metadata_index = row.candidate_metadata_indices.front();
            const StaticPrototypeShape& matched = staticIndex.prototypes[*row.static_metadata_index];
            if (runtimeRow->is_root == std::optional<bool>(true))
                addProof(row.proof, CorrespondenceProof::GraphRoot);

            const size_t sameInstructionCount = std::count_if(
                staticIndex.prototypes.begin(), staticIndex.prototypes.end(), [&](const StaticPrototypeShape& candidate) {
                    return candidate.fingerprint.instruction_count == runtimeRow->instruction_count &&
                        (!runtimeRow->is_root || candidate.fingerprint.is_root == *runtimeRow->is_root);
                });
            if (sameInstructionCount == 1)
                addProof(row.proof, CorrespondenceProof::UniqueInstructionCount);
            if (runtimeRow->opcode_lanes_complete &&
                matched.fingerprint.opcode_lanes == runtimeRow->opcode_lanes)
                addProof(row.proof, CorrespondenceProof::ExactOpcodeLaneFingerprint);
            if (runtimeRow->captures_complete && matched.fingerprint.captures_complete &&
                matched.fingerprint.captures == runtimeRow->captures)
                addProof(row.proof, CorrespondenceProof::ExactCaptureShape);
            if (auto fingerprint = buildRuntimePrototypeFingerprint(*runtimeRow, runtimePrototypes);
                fingerprint && matched.fingerprint == *fingerprint)
                addProof(row.proof, CorrespondenceProof::CompleteStructuralFingerprint);
            if (runtimeRow->parent_runtime_id && candidates[*runtimeRow->parent_runtime_id].size() == 1)
                addProof(row.proof, CorrespondenceProof::ParentClosureEdge);
            if (std::any_of(runtimeRow->closure_targets.begin(), runtimeRow->closure_targets.end(),
                    [&](const RuntimeClosureEvidence& closure) {
                        return candidates[closure.target_runtime_id].size() == 1;
                    }))
                addProof(row.proof, CorrespondenceProof::ChildClosureEdge);
            ++result.matched_count;
        }
        else
        {
            row.status = CorrespondenceStatus::Ambiguous;
            ++result.ambiguous_count;
        }
        result.records.push_back(std::move(row));
    }

    result.diagnostic = result.unmatched_count == 0
        ? "runtime prototypes correlated only where static structure was unique"
        : "some runtime prototypes contradict or exceed the available static evidence";
    return result;
}

PrototypeCorrespondenceResult correlateRuntimePrototypes(
    const ContainerAnalysis& container,
    const std::vector<RuntimePrototypeRecord>& runtimePrototypes)
{
    return correlateRuntimePrototypes(buildStaticPrototypeIndex(container), runtimePrototypes);
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

const char* toString(InstructionSchema schema)
{
    switch (schema)
    {
    case InstructionSchema::LegacyV147: return "legacy_v14_7";
    case InstructionSchema::LuaAuthLphDollar: return "luaauth_lph_dollar";
    }
    return "unknown";
}

const char* toString(InstructionSchemaSelectionStatus status)
{
    switch (status)
    {
    case InstructionSchemaSelectionStatus::Selected: return "selected";
    case InstructionSchemaSelectionStatus::InvalidEvidence: return "invalid_evidence";
    }
    return "unknown";
}

const char* toString(OperandLaneStatus status)
{
    switch (status)
    {
    case OperandLaneStatus::Valid: return "valid";
    case OperandLaneStatus::InvalidResidue: return "invalid_residue";
    case OperandLaneStatus::PcOutOfRange: return "pc_out_of_range";
    case OperandLaneStatus::ArithmeticOverflow: return "arithmetic_overflow";
    }
    return "unknown";
}

const char* toString(NormalizedOperandLane lane)
{
    switch (lane)
    {
    case NormalizedOperandLane::D: return "D";
    case NormalizedOperandLane::G: return "G";
    case NormalizedOperandLane::p: return "p";
    }
    return "unknown";
}

const char* toString(OperandLaneProjectionStatus status)
{
    switch (status)
    {
    case OperandLaneProjectionStatus::Unique: return "unique";
    case OperandLaneProjectionStatus::Ambiguous: return "ambiguous";
    case OperandLaneProjectionStatus::Contradictory: return "contradictory";
    case OperandLaneProjectionStatus::InsufficientEvidence: return "insufficient_evidence";
    case OperandLaneProjectionStatus::InvalidEvidence: return "invalid_evidence";
    }
    return "unknown";
}

const char* toString(CorrespondenceStatus status)
{
    switch (status)
    {
    case CorrespondenceStatus::Matched: return "matched";
    case CorrespondenceStatus::Ambiguous: return "ambiguous";
    case CorrespondenceStatus::Unmatched: return "unmatched";
    case CorrespondenceStatus::InvalidEvidence: return "invalid_evidence";
    }
    return "unknown";
}

const char* toString(CorrespondenceProof proof)
{
    switch (proof)
    {
    case CorrespondenceProof::GraphRoot: return "graph_root";
    case CorrespondenceProof::UniqueInstructionCount: return "unique_instruction_count";
    case CorrespondenceProof::ExactOpcodeLaneFingerprint: return "exact_opcode_lane_fingerprint";
    case CorrespondenceProof::ExactCaptureShape: return "exact_capture_shape";
    case CorrespondenceProof::CompleteStructuralFingerprint: return "complete_structural_fingerprint";
    case CorrespondenceProof::ParentClosureEdge: return "parent_closure_edge";
    case CorrespondenceProof::ChildClosureEdge: return "child_closure_edge";
    }
    return "unknown";
}

} // namespace alex::deobfuscator::luraph::vm
