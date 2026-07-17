#include "luraph/vm.hpp"

#include <array>
#include <iostream>
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

    if (!ok)
        return 1;
    std::cout << "luraph-vm-unit-ok\n";
    return 0;
}
