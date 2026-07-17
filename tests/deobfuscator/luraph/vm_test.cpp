#include "luraph/vm.hpp"

#include <algorithm>
#include <array>
#include <iostream>
#include <optional>
#include <vector>
#include <string_view>

namespace luraph = alex::deobfuscator::luraph;
namespace vm = alex::deobfuscator::luraph::vm;

namespace
{

bool require(bool condition, std::string_view message)
{
    if (!condition)
        std::cerr << "luraph_vm_test: " << message << '\n';
    return condition;
}

luraph::InstructionMetadata instruction(size_t index, std::array<int64_t, 4> words)
{
    luraph::InstructionMetadata result;
    result.index = index;
    for (size_t word = 0; word < words.size(); ++word)
        result.words[word].value = words[word];
    return result;
}

void addInstructions(luraph::PrototypeMetadata& prototype, size_t count)
{
    prototype.instruction_count = count;
    prototype.instructions.reserve(count);
    for (size_t index = 0; index < count; ++index)
        prototype.instructions.push_back(instruction(index, {0, 0, 0, 0}));
}

vm::NormalizedPrototype normalizedPrototype(
    size_t metadataIndex,
    const std::vector<std::array<int64_t, 3>>& lanes)
{
    vm::NormalizedPrototype prototype;
    prototype.metadata_index = metadataIndex;
    prototype.wrapper_index = metadataIndex + 1;
    prototype.instructions.reserve(lanes.size());
    for (size_t index = 0; index < lanes.size(); ++index)
    {
        vm::NormalizedInstruction instruction;
        instruction.metadata_index = index;
        instruction.pc = index + 1;
        instruction.D.base_value = lanes[index][0];
        instruction.G.base_value = lanes[index][1];
        instruction.p.base_value = lanes[index][2];
        prototype.instructions.push_back(instruction);
    }
    return prototype;
}

luraph::DescriptorMetadata captureDescriptor(
    size_t index,
    size_t parent,
    unsigned int kind,
    uint64_t sourceIndex)
{
    luraph::DescriptorMetadata descriptor;
    descriptor.index = index;
    descriptor.capture_semantics_verified = true;
    descriptor.capture_kind_code = kind;
    descriptor.capture_source_index = sourceIndex;
    descriptor.parent_prototype_index = parent;
    descriptor.source_index_validated = true;
    descriptor.source_index_in_bounds = true;
    return descriptor;
}

luraph::ContainerAnalysis starContainer(size_t prototypeCount, size_t rootIndex, bool uniqueInstructionCounts)
{
    luraph::ContainerAnalysis container;
    container.prototype_count = prototypeCount;
    container.root_selector = rootIndex + 1;
    container.root_metadata_index = rootIndex;
    container.root_selector_in_bounds = true;
    container.root_selector_graph_validated = true;
    container.prototype_graph_complete = true;
    container.prototypes.resize(prototypeCount);

    for (size_t index = 0; index < prototypeCount; ++index)
    {
        luraph::PrototypeMetadata& prototype = container.prototypes[index];
        prototype.index = index;
        const size_t instructionCount = index == rootIndex
            ? prototypeCount + 1
            : (uniqueInstructionCounts ? index + 1 : 1);
        addInstructions(prototype, instructionCount);
        prototype.register_capacity = prototypeCount + 8;
        prototype.register_capacity_verified = true;
        prototype.secondary_meta = prototype.register_capacity;
        if (index == rootIndex)
            continue;
        prototype.parent_prototype_index = rootIndex;
        prototype.incoming_prototype_reference_count = 1;
        prototype.descriptors.push_back(captureDescriptor(0, rootIndex, 0, index));
        prototype.descriptor_count = 1;
        ++container.prototypes_with_capture_descriptors;
        ++container.validated_capture_descriptor_count;
    }

    size_t sourcePc = 1;
    luraph::PrototypeMetadata& root = container.prototypes[rootIndex];
    for (size_t child = 0; child < prototypeCount; ++child)
    {
        if (child == rootIndex)
            continue;
        luraph::PrototypeReferenceMetadata reference;
        reference.instruction_index = sourcePc - 1;
        reference.operand_word_index = 2;
        reference.wrapper_index = static_cast<int64_t>(child + 1);
        reference.metadata_index = child;
        reference.in_bounds = true;
        reference.opcode = 112;
        reference.closure_target = true;
        reference.capture_descriptor_count = 1;
        root.prototype_references.push_back(reference);
        ++sourcePc;
    }
    container.prototype_reference_count = root.prototype_references.size();
    container.valid_prototype_reference_count = root.prototype_references.size();
    container.closure_target_count = root.prototype_references.size();
    for (const luraph::PrototypeMetadata& prototype : container.prototypes)
        container.instruction_count += prototype.instruction_count;
    return container;
}

std::vector<vm::RuntimePrototypeRecord> runtimeRecords(const vm::StaticPrototypeIndex& index)
{
    std::vector<vm::RuntimePrototypeRecord> records;
    records.reserve(index.prototypes.size());
    const auto runtimeId = [](size_t staticIndex) { return uint64_t(100000 + staticIndex * 17); };
    for (const vm::StaticPrototypeShape& prototype : index.prototypes)
    {
        vm::RuntimePrototypeRecord row;
        row.runtime_id = runtimeId(prototype.metadata_index);
        row.instruction_count = prototype.fingerprint.instruction_count;
        row.opcode_lanes = prototype.fingerprint.opcode_lanes;
        row.opcode_lanes_complete = true;
        row.is_root = prototype.fingerprint.is_root;
        row.captures = prototype.fingerprint.captures;
        row.captures_complete = true;
        row.closure_targets_complete = true;
        if (prototype.parent_metadata_index)
        {
            row.parent_runtime_id = runtimeId(*prototype.parent_metadata_index);
            row.parent_closure_pc = prototype.parent_closure_pc;
        }
        for (const vm::StaticPrototypeShape::ClosureEdge& edge : prototype.closure_edges)
        {
            vm::RuntimeClosureEvidence closure;
            closure.source_pc = edge.source_pc;
            closure.target_runtime_id = runtimeId(edge.target_metadata_index);
            closure.captures = index.prototypes[edge.target_metadata_index].fingerprint.captures;
            closure.captures_complete = true;
            row.closure_targets.push_back(std::move(closure));
        }
        records.push_back(std::move(row));
    }
    std::reverse(records.begin(), records.end());
    return records;
}

const vm::PrototypeCorrespondence* correspondence(
    const vm::PrototypeCorrespondenceResult& result,
    uint64_t runtimeId)
{
    auto row = std::find_if(result.records.begin(), result.records.end(),
        [&](const vm::PrototypeCorrespondence& item) { return item.runtime_id == runtimeId; });
    return row == result.records.end() ? nullptr : &*row;
}

} // namespace

int main()
{
    bool ok = true;

    const vm::NormalizedInstruction rootFirst = vm::normalizeInstruction(instruction(0, {2, 718, 90, 2}), 1145, 37);
    ok &= require(rootFirst.pc == 1 && rootFirst.opcode == 90, "root first opcode or PC is incorrect");
    ok &= require(rootFirst.D.base_value == 0 && rootFirst.G.base_value == 90 && rootFirst.p.base_value == 0,
        "ordinary operand lanes are incorrect");

    const vm::NormalizedInstruction constants = vm::normalizeInstruction(instruction(4, {2409, 7281, 39, 354}), 1145, 37);
    ok &= require(constants.D.residue == 1 && constants.D.quotient == 301 && constants.D.base_value == 301,
        "D constant lane split is incorrect");
    ok &= require(constants.D.side_reference.kind == vm::ReferenceKind::Constant && constants.D.side_reference.valid &&
                      constants.D.side_reference.wrapper_index == 301 && constants.D.side_reference.metadata_index == 300,
        "D constant reference is incorrect");
    ok &= require(constants.G.side_reference.kind == vm::ReferenceKind::Constant && constants.G.side_reference.valid &&
                      constants.G.side_reference.wrapper_index == 910 && constants.G.side_reference.metadata_index == 909,
        "G constant reference is incorrect");
    ok &= require(constants.p.base_value == 44 && constants.p.residue == 2 && constants.opcode == 39,
        "plain p lane or opcode is incorrect");

    const vm::NormalizedInstruction closure = vm::normalizeInstruction(instruction(168, {91, 122, 22, 2}), 1145, 37);
    ok &= require(closure.pc == 169 && closure.opcode == 22 && closure.D.base_value == 11,
        "closure instruction base fields are incorrect");
    ok &= require(closure.D.side_reference.kind == vm::ReferenceKind::Prototype && closure.D.side_reference.valid &&
                      closure.D.side_reference.wrapper_index == 11 && closure.D.side_reference.metadata_index == 10,
        "closure prototype reference is incorrect");
    ok &= require(closure.G.base_value == 15 && closure.G.side_reference.kind == vm::ReferenceKind::None,
        "closure G lane is incorrect");

    const vm::OperandLane backward = vm::normalizeLane(8 * 4 + 5, 20, 10, 10);
    const vm::OperandLane forward = vm::normalizeLane(8 * 4 + 6, 20, 10, 10);
    ok &= require(backward.base_value == 16 && forward.base_value == 24, "relative lanes are incorrect");
    const vm::OperandLane negative = vm::normalizeLane(-3, 20, 10, 10);
    ok &= require(negative.residue == 5 && negative.quotient == -1 && negative.base_value == 21,
        "negative word Euclidean split is incorrect");

    const vm::OperandLane invalidConstant = vm::normalizeLane(8 * 99 + 1, 1, 10, 10);
    ok &= require(invalidConstant.side_reference.kind == vm::ReferenceKind::Constant && !invalidConstant.side_reference.valid &&
                      !invalidConstant.side_reference.metadata_index.has_value(),
        "out-of-range constant reference was accepted");

    luraph::ContainerAnalysis container;
    container.constant_pool_mode = 0;
    container.root_selector = 2;
    container.constants.resize(4);
    container.prototypes.resize(2);
    container.prototypes[0].index = 0;
    container.prototypes[0].final_value = 12;
    container.prototypes[0].instructions.push_back(instruction(0, {2, 718, 90, 2}));
    container.prototypes[1].index = 1;
    container.prototypes[1].final_value = 35;
    const vm::NormalizedContainer normalized = vm::normalizeContainer(container);
    ok &= require(normalized.root_valid && normalized.root_wrapper_index == 2 && normalized.root_metadata_index == 1,
        "root selector was not resolved from one-based wrapper indexing");
    ok &= require(normalized.prototypes.size() == 2 && normalized.prototypes[0].wrapper_index == 1 &&
                      normalized.prototypes[0].register_capacity == 12 && normalized.prototypes[0].instructions.size() == 1,
        "prototype normalization is incorrect");

    container.root_selector = 0;
    const vm::NormalizedContainer invalidRoot = vm::normalizeContainer(container);
    ok &= require(!invalidRoot.root_valid && !invalidRoot.root_metadata_index.has_value(), "invalid root selector was accepted");

    vm::NormalizedContainer projectionStatic;
    projectionStatic.prototypes.push_back(normalizedPrototype(0, {
        {11, 21, 31},
        {12, 22, 32},
    }));
    projectionStatic.prototypes.push_back(normalizedPrototype(1, {
        {13, 23, 33},
        {14, 24, 34},
        {15, 25, 35},
    }));
    const std::vector<vm::RuntimeOperandLaneAnchor> uniqueLaneAnchors{
        {2, {
            {"S", {11, 12}},
            {"V", {21, 22}},
            {"Z", {31, 32}},
            {"g", {41, 42}},
            {"r", {51, 52}},
            {"v", {61, 62}},
        }},
        {3, {
            {"S", {13, 14, 15}},
            {"V", {23, 24, 25}},
            {"Z", {33, 34, 35}},
            {"g", {43, 44, 45}},
            {"r", {53, 54, 55}},
            {"v", {63, 64, 65}},
        }},
    };
    vm::OperandLaneProjection expectedProjection;
    expectedProjection.bindings = {{
        {"S", vm::NormalizedOperandLane::D},
        {"V", vm::NormalizedOperandLane::G},
        {"Z", vm::NormalizedOperandLane::p},
    }};
    const vm::OperandLaneProjectionResult uniqueProjection =
        vm::inferOperandLaneProjection(projectionStatic, uniqueLaneAnchors);
    ok &= require(uniqueProjection.status == vm::OperandLaneProjectionStatus::Unique &&
                      uniqueProjection.uniquely_matched_anchor_count == 2 &&
                      uniqueProjection.anchor_metadata_indices == std::vector<size_t>({0, 1}) &&
                      uniqueProjection.candidates == std::vector<vm::OperandLaneProjection>({expectedProjection}),
        "exact multi-anchor operand lanes did not produce the unique S/V/Z to D/G/p projection");

    std::vector<vm::RuntimeOperandLaneAnchor> ambiguousLaneAnchors = uniqueLaneAnchors;
    ambiguousLaneAnchors[0].lanes[5].values = ambiguousLaneAnchors[0].lanes[0].values;
    ambiguousLaneAnchors[1].lanes[5].values = ambiguousLaneAnchors[1].lanes[0].values;
    const vm::OperandLaneProjectionResult ambiguousProjection =
        vm::inferOperandLaneProjection(projectionStatic, ambiguousLaneAnchors);
    ok &= require(ambiguousProjection.status == vm::OperandLaneProjectionStatus::Ambiguous &&
                      ambiguousProjection.candidates.size() == 2 &&
                      ambiguousProjection.candidates[0].bindings[0].runtime_name == "S" &&
                      ambiguousProjection.candidates[1].bindings[0].runtime_name == "v" &&
                      ambiguousProjection.candidates[0].bindings[1].runtime_name == "V" &&
                      ambiguousProjection.candidates[1].bindings[2].runtime_name == "Z",
        "multiple exact operand-lane projections were not preserved as explicit ambiguity");

    std::vector<vm::RuntimeOperandLaneAnchor> contradictoryLaneAnchors = uniqueLaneAnchors;
    contradictoryLaneAnchors[1].lanes[0].values.back() = 999;
    const vm::OperandLaneProjectionResult contradictoryProjection =
        vm::inferOperandLaneProjection(projectionStatic, contradictoryLaneAnchors);
    ok &= require(contradictoryProjection.status == vm::OperandLaneProjectionStatus::Contradictory &&
                      contradictoryProjection.uniquely_matched_anchor_count == 2 &&
                      contradictoryProjection.candidates.empty(),
        "a one-value contradiction in a later anchor was accepted as a lane projection");

    const luraph::ContainerAnalysis exactShape = starContainer(399, 265, true);
    const vm::StaticPrototypeIndex staticIndex = vm::buildStaticPrototypeIndex(exactShape);
    ok &= require(staticIndex.valid && staticIndex.prototypes.size() == 399 &&
                      staticIndex.root_metadata_index == std::optional<size_t>(265) &&
                      staticIndex.prototypes[265].wrapper_index == 266,
        "399-prototype static graph or root selector 266 was not indexed exactly");
    ok &= require(staticIndex.prototypes[265].closure_edges.size() == 398 &&
                      staticIndex.prototypes[0].parent_metadata_index == std::optional<size_t>(265) &&
                      staticIndex.prototypes[0].parent_closure_pc == std::optional<size_t>(1) &&
                      staticIndex.prototypes[0].fingerprint.captures ==
                          std::vector<vm::CaptureDescriptorShape>{{0, 0}},
        "closure targets, parents, or capture descriptors were not retained in the static index");
    const uint64_t firstDigest = staticIndex.prototypes[265].fingerprint.digest;
    const uint64_t firstOpcodeLaneDigest =
        staticIndex.prototypes[265].fingerprint.opcode_lane_digest;
    const vm::StaticPrototypeIndex repeatedIndex = vm::buildStaticPrototypeIndex(exactShape);
    ok &= require(firstDigest != 0 && firstOpcodeLaneDigest != 0 && repeatedIndex.valid &&
                      repeatedIndex.prototypes[265].fingerprint.digest == firstDigest &&
                      repeatedIndex.prototypes[265].fingerprint.opcode_lane_digest ==
                          firstOpcodeLaneDigest,
        "structural fingerprint is not deterministic");

    const std::vector<vm::RuntimePrototypeRecord> exactRuntime = runtimeRecords(staticIndex);
    const vm::PrototypeCorrespondenceResult exactMapping =
        vm::correlateRuntimePrototypes(staticIndex, exactRuntime);
    ok &= require(exactMapping.static_evidence_valid && exactMapping.runtime_evidence_valid &&
                      exactMapping.matched_count == 399 && exactMapping.ambiguous_count == 0 &&
                      exactMapping.unmatched_count == 0,
        "complete runtime graph did not map all 399 prototypes deterministically");
    const vm::PrototypeCorrespondence* mappedRoot = correspondence(exactMapping, 100000 + 265 * 17);
    ok &= require(mappedRoot && mappedRoot->status == vm::CorrespondenceStatus::Matched &&
                      mappedRoot->static_metadata_index == std::optional<size_t>(265) &&
                      std::find(mappedRoot->proof.begin(), mappedRoot->proof.end(),
                          vm::CorrespondenceProof::GraphRoot) != mappedRoot->proof.end() &&
                      std::find(mappedRoot->proof.begin(), mappedRoot->proof.end(),
                          vm::CorrespondenceProof::ExactOpcodeLaneFingerprint) != mappedRoot->proof.end() &&
                      std::find(mappedRoot->proof.begin(), mappedRoot->proof.end(),
                          vm::CorrespondenceProof::CompleteStructuralFingerprint) != mappedRoot->proof.end(),
        "runtime root was not mapped to static wrapper selector 266 with explicit proof");
    ok &= require(std::is_sorted(exactMapping.records.begin(), exactMapping.records.end(),
                      [](const vm::PrototypeCorrespondence& left, const vm::PrototypeCorrespondence& right) {
                          return left.runtime_id < right.runtime_id;
                      }),
        "runtime input order leaked into correspondence report order");

    const luraph::ContainerAnalysis duplicateShape = starContainer(3, 0, false);
    const vm::StaticPrototypeIndex duplicateIndex = vm::buildStaticPrototypeIndex(duplicateShape);
    std::vector<vm::RuntimePrototypeRecord> ambiguousRuntime(2);
    for (size_t index = 0; index < ambiguousRuntime.size(); ++index)
    {
        ambiguousRuntime[index].runtime_id = 700 + index;
        ambiguousRuntime[index].instruction_count = 1;
        ambiguousRuntime[index].is_root = false;
        ambiguousRuntime[index].captures = {{0, 1 + index}};
        ambiguousRuntime[index].captures_complete = false;
    }
    const vm::PrototypeCorrespondenceResult ambiguousMapping =
        vm::correlateRuntimePrototypes(duplicateIndex, ambiguousRuntime);
    ok &= require(ambiguousMapping.runtime_evidence_valid && ambiguousMapping.matched_count == 0 &&
                      ambiguousMapping.ambiguous_count == 2 &&
                      ambiguousMapping.records[0].candidate_metadata_indices.size() == 2,
        "duplicate runtime shapes were guessed instead of remaining ambiguous");

    std::vector<vm::RuntimePrototypeRecord> edgeRuntime = runtimeRecords(duplicateIndex);
    const vm::PrototypeCorrespondenceResult edgeMapping =
        vm::correlateRuntimePrototypes(duplicateIndex, edgeRuntime);
    ok &= require(edgeMapping.matched_count == 3 && edgeMapping.ambiguous_count == 0,
        "proven parent closure PCs did not disambiguate duplicate child shapes");

    luraph::ContainerAnalysis opcodeShape = starContainer(3, 0, false);
    opcodeShape.prototypes[1].instructions[0] = instruction(0, {10, 18, 7, 26});
    opcodeShape.prototypes[2].instructions[0] = instruction(0, {10, 18, 8, 34});
    const vm::StaticPrototypeIndex opcodeIndex = vm::buildStaticPrototypeIndex(opcodeShape);
    vm::RuntimePrototypeRecord opcodeRuntime;
    opcodeRuntime.runtime_id = 901;
    opcodeRuntime.instruction_count = 1;
    opcodeRuntime.opcode_lanes = opcodeIndex.prototypes[2].fingerprint.opcode_lanes;
    opcodeRuntime.opcode_lanes_complete = true;
    opcodeRuntime.is_root = false;
    const vm::PrototypeCorrespondenceResult opcodeMapping =
        vm::correlateRuntimePrototypes(opcodeIndex, {opcodeRuntime});
    const vm::PrototypeCorrespondence* opcodeMatch = correspondence(opcodeMapping, 901);
    ok &= require(opcodeIndex.valid &&
                      opcodeIndex.prototypes[1].fingerprint.opcode_lane_digest !=
                          opcodeIndex.prototypes[2].fingerprint.opcode_lane_digest &&
                      opcodeMatch && opcodeMatch->status == vm::CorrespondenceStatus::Matched &&
                      opcodeMatch->static_metadata_index == std::optional<size_t>(2) &&
                      std::find(opcodeMatch->proof.begin(), opcodeMatch->proof.end(),
                          vm::CorrespondenceProof::ExactOpcodeLaneFingerprint) != opcodeMatch->proof.end(),
        "exact opcode/lane evidence did not disambiguate equal instruction counts");

    opcodeRuntime.opcode_lanes[0].pc = 2;
    const vm::PrototypeCorrespondenceResult malformedFingerprint =
        vm::correlateRuntimePrototypes(opcodeIndex, {opcodeRuntime});
    ok &= require(!malformedFingerprint.runtime_evidence_valid &&
                      malformedFingerprint.records.size() == 1 &&
                      malformedFingerprint.records[0].status == vm::CorrespondenceStatus::InvalidEvidence,
        "malformed complete opcode/lane evidence was not rejected");

    std::vector<vm::RuntimePrototypeRecord> invalidRuntime = edgeRuntime;
    invalidRuntime.push_back(invalidRuntime.front());
    const vm::PrototypeCorrespondenceResult invalidMapping =
        vm::correlateRuntimePrototypes(duplicateIndex, invalidRuntime);
    ok &= require(!invalidMapping.runtime_evidence_valid && !invalidMapping.records.empty() &&
                      std::all_of(invalidMapping.records.begin(), invalidMapping.records.end(),
                          [](const vm::PrototypeCorrespondence& row) {
                              return row.status == vm::CorrespondenceStatus::InvalidEvidence;
                          }),
        "duplicate runtime identifiers were not rejected as invalid evidence");

    luraph::ContainerAnalysis unproved = exactShape;
    unproved.prototype_graph_complete = false;
    unproved.root_selector_graph_validated = false;
    const vm::StaticPrototypeIndex unprovedIndex = vm::buildStaticPrototypeIndex(unproved);
    ok &= require(!unprovedIndex.valid && unprovedIndex.prototypes.empty(),
        "unproved static graph was accepted for runtime correspondence");
    ok &= require(std::string_view(vm::toString(vm::CorrespondenceStatus::Ambiguous)) == "ambiguous" &&
                      std::string_view(vm::toString(vm::NormalizedOperandLane::p)) == "p" &&
                      std::string_view(vm::toString(vm::OperandLaneProjectionStatus::Contradictory)) ==
                          "contradictory" &&
                      std::string_view(vm::toString(vm::CorrespondenceProof::ExactOpcodeLaneFingerprint)) ==
                          "exact_opcode_lane_fingerprint" &&
                      std::string_view(vm::toString(vm::CorrespondenceProof::ParentClosureEdge)) ==
                          "parent_closure_edge",
        "correspondence status or proof labels are unstable");

    if (!ok)
        return 1;
    std::cout << "luraph-vm-unit-ok\n";
    return 0;
}
