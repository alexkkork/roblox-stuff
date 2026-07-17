#include "luraph/index_read_semantics.hpp"

#include <iostream>
#include <string_view>

namespace semantics = alex::deobfuscator::luraph::index_read;

namespace
{

bool require(bool condition, std::string_view message)
{
    if (!condition)
        std::cerr << "luraph_index_read_semantics_test: " << message << '\n';
    return condition;
}

semantics::RuntimeOperands operands(int64_t destination, int64_t tableRegister, uint64_t capacity = 0)
{
    semantics::RuntimeOperands result;
    result.destination_register = destination;
    result.table_register = tableRegister;
    result.index_operand_present = true;
    if (capacity != 0)
        result.register_capacity = capacity;
    return result;
}

semantics::ObservedGuardPathEvidence completeObservation(uint64_t count = 1)
{
    semantics::ObservedGuardPathEvidence observed;
    observed.opcode = semantics::kOpcode28;
    observed.selected_handler_begin = semantics::kExactFixtureLeafBegin;
    observed.selected_handler_end = semantics::kExactFixtureLeafEnd;
    observed.path_complete = true;
    observed.selected_handler_exactly = true;
    observed.executed_statement_path_complete = true;
    observed.full_effect_validation = true;
    observed.lookup_attempt_observed = true;
    observed.observation_count = count;
    observed.decisions.push_back({
        semantics::kExactFixtureGuardBegin,
        semantics::kExactFixtureGuardEnd,
        false,
    });
    return observed;
}

} // namespace

int main()
{
    bool ok = true;

    const semantics::StaticHandlerEvidence shape = semantics::exactFixtureHandlerEvidence();

    const semantics::RecognitionResult shapeOnly =
        semantics::recognizeOpcode28RegisterTableIndexRead(shape, operands(15, 15));
    ok &= require(shapeOnly.status == semantics::RecognitionStatus::MissingGuardPathProof &&
                      !shapeOnly.operation && !shapeOnly.proof,
        "handler shape alone was accepted without complete guard evidence");

    semantics::ObservedGuardPathEvidence observed = completeObservation(534);
    observed.changed_register_writes = {15};
    const semantics::RecognitionResult runtime = semantics::recognizeOpcode28RegisterTableIndexRead(
        shape, operands(15, 15, 64), observed);
    ok &= require(runtime.recognized() && runtime.proof &&
                      runtime.proof->scope == semantics::ProofScope::RuntimeObservedGuardPath &&
                      runtime.proof->path_specific && !runtime.proof->general_semantic &&
                      runtime.proof->observation_count == 534,
        "complete runtime proof was not kept path-specific");
    ok &= require(runtime.operation && runtime.operation->destination_register == 15 &&
                      runtime.operation->table_register == 15 &&
                      runtime.operation->destination_lane == semantics::RuntimeOperandLane::r &&
                      runtime.operation->table_register_lane == semantics::RuntimeOperandLane::S &&
                      runtime.operation->index_lane == semantics::RuntimeOperandLane::V &&
                      runtime.operation->reads_table_before_destination_write &&
                      runtime.operation->preserves_aliasing_when_destination_equals_table,
        "R[r] = R[S][V] lane roles or read-before-write aliasing were not preserved");

    const semantics::LookupEffectPolicy& effects = runtime.operation->effects;
    ok &= require(effects.evaluates_table_once && effects.evaluates_index_once &&
                      effects.performs_lookup_once && effects.writes_destination_only_after_success &&
                      effects.may_invoke_index_metamethod && effects.may_raise && effects.effect_barrier &&
                      !effects.constant_foldable && !effects.common_subexpression_eliminable &&
                      !effects.dead_code_eliminable && !effects.reorderable,
        "lookup metamethod, error, ordering, or non-foldability policy was weakened");
    ok &= require(runtime.operation->evaluation_order ==
                      std::vector<semantics::EvaluationStep>({
                          semantics::EvaluationStep::ReadTableRegister,
                          semantics::EvaluationStep::ReadIndexOperand,
                          semantics::EvaluationStep::PerformIndexRead,
                          semantics::EvaluationStep::WriteDestinationRegister,
                      }),
        "index-read evaluation order was not preserved exactly");

    semantics::ObservedGuardPathEvidence unchanged = completeObservation();
    const semantics::RecognitionResult unchangedResult =
        semantics::recognizeOpcode28RegisterTableIndexRead(shape, operands(4, 9), unchanged);
    ok &= require(unchangedResult.recognized(),
        "empty changed-write evidence was rejected even though unchanged writes are omitted");

    semantics::StaticHandlerEvidence staticGuard = shape;
    staticGuard.guard_selection_statically_proven = true;
    const semantics::RecognitionResult general = semantics::recognizeOpcode28RegisterTableIndexRead(
        staticGuard, operands(3, 8), std::nullopt, semantics::RequiredProof::GeneralSemantic);
    ok &= require(general.recognized() && general.proof &&
                      general.proof->scope == semantics::ProofScope::StaticGuardPath &&
                      general.proof->general_semantic && !general.proof->path_specific,
        "static guard-selection proof did not produce general semantics");

    const semantics::RecognitionResult runtimeAsGeneral = semantics::recognizeOpcode28RegisterTableIndexRead(
        shape, operands(3, 8), completeObservation(10000), semantics::RequiredProof::GeneralSemantic);
    ok &= require(runtimeAsGeneral.status == semantics::RecognitionStatus::GeneralProofUnavailable &&
                      !runtimeAsGeneral.recognized(),
        "repeated runtime observations were promoted into general static semantics");

    semantics::RuntimeOperands missingIndex = operands(1, 2);
    missingIndex.index_operand_present = false;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      staticGuard, missingIndex).status == semantics::RecognitionStatus::InvalidOperandLane,
        "missing V key operand was accepted");

    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      staticGuard, operands(-1, 2)).status == semantics::RecognitionStatus::InvalidOperandLane,
        "negative destination register was accepted");
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      staticGuard, operands(1, -2)).status == semantics::RecognitionStatus::InvalidOperandLane,
        "negative table register was accepted");
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      staticGuard, operands(8, 1, 8)).status == semantics::RecognitionStatus::InvalidOperandLane,
        "destination equal to register capacity was accepted");

    semantics::ObservedGuardPathEvidence incomplete = completeObservation();
    incomplete.path_overflow = true;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      shape, operands(1, 2), incomplete).status ==
                      semantics::RecognitionStatus::IncompleteGuardPathProof,
        "overflowing guard path was accepted");

    semantics::ObservedGuardPathEvidence noLookup = completeObservation();
    noLookup.lookup_attempt_observed = false;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      shape, operands(1, 2), noLookup).status ==
                      semantics::RecognitionStatus::IncompleteGuardPathProof,
        "path without an observed lookup attempt was accepted");

    semantics::ObservedGuardPathEvidence wrongDecision = completeObservation();
    wrongDecision.decisions[0].decision = true;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      shape, operands(1, 2), wrongDecision).status ==
                      semantics::RecognitionStatus::ContradictoryGuardPathProof,
        "guard decision selecting a different leaf was accepted");

    semantics::ObservedGuardPathEvidence duplicateDecision = completeObservation();
    duplicateDecision.decisions.push_back(duplicateDecision.decisions.front());
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      shape, operands(1, 2), duplicateDecision).status ==
                      semantics::RecognitionStatus::IncompleteGuardPathProof,
        "duplicate guard-decision evidence was accepted");

    semantics::ObservedGuardPathEvidence wrongLeaf = completeObservation();
    ++wrongLeaf.selected_handler_end;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      shape, operands(1, 2), wrongLeaf).status ==
                      semantics::RecognitionStatus::ContradictoryGuardPathProof,
        "contradictory selected leaf was accepted");

    semantics::ObservedGuardPathEvidence outsideWrite = completeObservation();
    outsideWrite.changed_register_writes = {7};
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      shape, operands(6, 2), outsideWrite).status ==
                      semantics::RecognitionStatus::ContradictoryGuardPathProof,
        "changed write outside R[r] was accepted");

    semantics::ObservedGuardPathEvidence duplicateWrite = completeObservation();
    duplicateWrite.changed_register_writes = {6, 6};
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      shape, operands(6, 2), duplicateWrite).status ==
                      semantics::RecognitionStatus::ContradictoryGuardPathProof,
        "duplicate changed-write evidence was accepted");

    semantics::StaticHandlerEvidence wrongOpcode = shape;
    wrongOpcode.opcode = 27;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      wrongOpcode, operands(1, 2), completeObservation()).status ==
                      semantics::RecognitionStatus::WrongOpcode,
        "non-28 opcode was accepted");

    semantics::StaticHandlerEvidence swappedLanes = shape;
    swappedLanes.destination_lane = semantics::RuntimeOperandLane::S;
    swappedLanes.table_register_lane = semantics::RuntimeOperandLane::r;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      swappedLanes, operands(1, 2), completeObservation()).status ==
                      semantics::RecognitionStatus::HandlerShapeMismatch,
        "swapped destination/table lanes were accepted");

    semantics::StaticHandlerEvidence wrongKeyLane = shape;
    wrongKeyLane.index_lane = semantics::RuntimeOperandLane::v;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      wrongKeyLane, operands(1, 2), completeObservation()).status ==
                      semantics::RecognitionStatus::HandlerShapeMismatch,
        "non-V key lane was accepted");

    semantics::StaticHandlerEvidence extraStatement = shape;
    extraStatement.continuation_statement_count = 1;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      extraStatement, operands(1, 2), completeObservation()).status ==
                      semantics::RecognitionStatus::HandlerShapeMismatch,
        "leaf with an extra executable statement was accepted");

    semantics::StaticHandlerEvidence foldable = shape;
    foldable.lookup_constant_foldable = true;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      foldable, operands(1, 2), completeObservation()).status ==
                      semantics::RecognitionStatus::HandlerShapeMismatch,
        "constant-foldable lookup evidence was accepted");

    semantics::StaticHandlerEvidence noMetamethod = shape;
    noMetamethod.lookup_may_invoke_index_metamethod = false;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      noMetamethod, operands(1, 2), completeObservation()).status ==
                      semantics::RecognitionStatus::HandlerShapeMismatch,
        "lookup that discards __index behavior was accepted");

    semantics::StaticHandlerEvidence noError = shape;
    noError.lookup_may_raise = false;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      noError, operands(1, 2), completeObservation()).status ==
                      semantics::RecognitionStatus::HandlerShapeMismatch,
        "lookup that discards error behavior was accepted");

    semantics::StaticHandlerEvidence twoLookups = shape;
    twoLookups.index_read_count = 2;
    ok &= require(semantics::recognizeOpcode28RegisterTableIndexRead(
                      twoLookups, operands(1, 2), completeObservation()).status ==
                      semantics::RecognitionStatus::HandlerShapeMismatch,
        "leaf with multiple lookups was accepted");

    ok &= require(std::string_view(semantics::toString(semantics::RuntimeOperandLane::V)) == "V" &&
                      std::string_view(semantics::toString(semantics::EvaluationStep::PerformIndexRead)) ==
                          "perform_index_read" &&
                      std::string_view(semantics::toString(semantics::ProofScope::StaticGuardPath)) ==
                          "static_guard_path" &&
                      std::string_view(semantics::toString(
                          semantics::RecognitionStatus::GeneralProofUnavailable)) ==
                          "general_proof_unavailable",
        "stable lane, step, proof, or status labels are incorrect");

    return ok ? 0 : 1;
}
