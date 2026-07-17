#include "luraph/range_clear_semantics.hpp"

#include <iostream>
#include <limits>
#include <string_view>

namespace semantics = alex::deobfuscator::luraph::range_clear;

namespace
{

bool require(bool condition, std::string_view message)
{
    if (!condition)
        std::cerr << "luraph_range_clear_semantics_test: " << message << '\n';
    return condition;
}

semantics::RuntimeOperandLanes lanes(int64_t first, int64_t last, uint64_t capacity = 0)
{
    semantics::RuntimeOperandLanes result;
    result.r = first;
    result.S = last;
    if (capacity != 0)
        result.register_capacity = capacity;
    return result;
}

semantics::ObservedGuardPathEvidence completeObservation(uint64_t count = 1)
{
    semantics::ObservedGuardPathEvidence observed;
    observed.opcode = semantics::kOpcode89;
    observed.selected_handler_begin = semantics::kExactFixtureHandlerBegin;
    observed.selected_handler_end = semantics::kExactFixtureHandlerEnd;
    observed.path_complete = true;
    observed.selected_handler_exactly = true;
    observed.executed_statement_path_complete = true;
    observed.full_effect_validation = true;
    observed.observation_count = count;
    observed.decisions.push_back({
        semantics::kExactFixtureGuardBegin,
        semantics::kExactFixtureGuardEnd,
        true,
    });
    return observed;
}

} // namespace

int main()
{
    bool ok = true;

    const semantics::StaticHandlerEvidence shapeOnly = semantics::exactFixtureHandlerEvidence();
    const semantics::RecognitionResult shapeResult =
        semantics::recognizeOpcode89RegisterRangeClear(shapeOnly, lanes(84, 91));
    ok &= require(shapeResult.recognized() && shapeResult.proof &&
                      shapeResult.proof->scope == semantics::ProofScope::StaticHandlerShape &&
                      !shapeResult.proof->general_semantic && !shapeResult.proof->path_specific,
        "static handler shape was promoted beyond candidate evidence");
    ok &= require(shapeResult.operation && shapeResult.operation->first_register == 84 &&
                      shapeResult.operation->last_register == 91 &&
                      shapeResult.operation->first_register_lane == semantics::RuntimeOperandLane::r &&
                      shapeResult.operation->last_register_lane == semantics::RuntimeOperandLane::S &&
                      shapeResult.operation->inclusive_last_register && shapeResult.operation->writes_nil &&
                      shapeResult.operation->assignment_count == 8 && !shapeResult.operation->empty,
        "inclusive r-to-S clear range was not modeled exactly");

    semantics::StaticHandlerEvidence staticGuard = shapeOnly;
    staticGuard.guard_selection_statically_proven = true;
    const semantics::RecognitionResult generalResult = semantics::recognizeOpcode89RegisterRangeClear(
        staticGuard, lanes(17, 29), std::nullopt, semantics::RequiredProof::GeneralSemantic);
    ok &= require(generalResult.recognized() && generalResult.proof &&
                      generalResult.proof->scope == semantics::ProofScope::StaticGuardPath &&
                      generalResult.proof->general_semantic && !generalResult.proof->path_specific &&
                      generalResult.operation && generalResult.operation->assignment_count == 13,
        "static guard proof did not produce exact general semantics");

    semantics::ObservedGuardPathEvidence observed = completeObservation(468);
    observed.changed_register_writes = {{85, true}, {89, true}};
    const semantics::RecognitionResult observedResult = semantics::recognizeOpcode89RegisterRangeClear(
        shapeOnly, lanes(84, 91), observed, semantics::RequiredProof::PathSpecificSemantic);
    ok &= require(observedResult.recognized() && observedResult.proof &&
                      observedResult.proof->scope == semantics::ProofScope::RuntimeObservedGuardPath &&
                      !observedResult.proof->general_semantic && observedResult.proof->path_specific &&
                      observedResult.proof->observation_count == 468,
        "observed guard-path proof was promoted to a universal static claim");

    semantics::ObservedGuardPathEvidence sparse = completeObservation();
    const semantics::RecognitionResult sparseResult = semantics::recognizeOpcode89RegisterRangeClear(
        shapeOnly, lanes(30, 37), sparse, semantics::RequiredProof::PathSpecificSemantic);
    ok &= require(sparseResult.recognized(),
        "empty changed-write evidence was rejected even though nil-to-nil assignments are omitted");

    const semantics::RecognitionResult oneRegister = semantics::recognizeOpcode89RegisterRangeClear(
        staticGuard, lanes(7, 7));
    ok &= require(oneRegister.recognized() && oneRegister.operation &&
                      oneRegister.operation->assignment_count == 1 && !oneRegister.operation->empty,
        "equal inclusive endpoints did not clear exactly one register");

    const semantics::RecognitionResult emptyRange = semantics::recognizeOpcode89RegisterRangeClear(
        staticGuard, lanes(9, 4));
    ok &= require(emptyRange.recognized() && emptyRange.operation && emptyRange.operation->empty &&
                      emptyRange.operation->assignment_count == 0,
        "descending unit-step range was not preserved as an exact no-op");

    const semantics::RecognitionResult largeRange = semantics::recognizeOpcode89RegisterRangeClear(
        staticGuard, lanes(0, std::numeric_limits<int64_t>::max()));
    ok &= require(largeRange.recognized() && largeRange.operation &&
                      largeRange.operation->assignment_count == (uint64_t(1) << 63) &&
                      !largeRange.operation->assignment_count_overflow,
        "large inclusive range cardinality overflowed");

    semantics::RuntimeOperandLanes missingStart;
    missingStart.S = 10;
    const semantics::RecognitionResult missingLane =
        semantics::recognizeOpcode89RegisterRangeClear(shapeOnly, missingStart);
    ok &= require(missingLane.status == semantics::RecognitionStatus::InvalidOperandLane &&
                      !missingLane.operation && !missingLane.proof,
        "missing r operand lane was accepted");

    const semantics::RecognitionResult negativeLane =
        semantics::recognizeOpcode89RegisterRangeClear(shapeOnly, lanes(-1, 2));
    ok &= require(negativeLane.status == semantics::RecognitionStatus::InvalidOperandLane,
        "negative register endpoint was accepted");

    const semantics::RecognitionResult capacityViolation =
        semantics::recognizeOpcode89RegisterRangeClear(shapeOnly, lanes(4, 8, 8));
    ok &= require(capacityViolation.status == semantics::RecognitionStatus::InvalidOperandLane,
        "endpoint equal to register capacity was accepted");

    const semantics::RecognitionResult missingPath = semantics::recognizeOpcode89RegisterRangeClear(
        shapeOnly, lanes(1, 2), std::nullopt, semantics::RequiredProof::PathSpecificSemantic);
    ok &= require(missingPath.status == semantics::RecognitionStatus::MissingGuardPathProof &&
                      !missingPath.recognized(),
        "path-specific semantics were accepted without an observed guard path");

    const semantics::RecognitionResult observedAsGeneral = semantics::recognizeOpcode89RegisterRangeClear(
        shapeOnly, lanes(1, 2), completeObservation(1000), semantics::RequiredProof::GeneralSemantic);
    ok &= require(observedAsGeneral.status == semantics::RecognitionStatus::GeneralProofUnavailable &&
                      !observedAsGeneral.recognized(),
        "repeated runtime observations were accepted as general static proof");

    semantics::ObservedGuardPathEvidence incomplete = completeObservation();
    incomplete.path_overflow = true;
    const semantics::RecognitionResult incompleteResult = semantics::recognizeOpcode89RegisterRangeClear(
        shapeOnly, lanes(1, 2), incomplete, semantics::RequiredProof::PathSpecificSemantic);
    ok &= require(incompleteResult.status == semantics::RecognitionStatus::IncompleteGuardPathProof &&
                      !incompleteResult.operation && !incompleteResult.proof,
        "overflowing guard path was accepted");

    semantics::ObservedGuardPathEvidence wrongDecision = completeObservation();
    wrongDecision.decisions[0].decision = false;
    const semantics::RecognitionResult wrongDecisionResult = semantics::recognizeOpcode89RegisterRangeClear(
        shapeOnly, lanes(1, 2), wrongDecision, semantics::RequiredProof::PathSpecificSemantic);
    ok &= require(wrongDecisionResult.status == semantics::RecognitionStatus::IncompleteGuardPathProof,
        "wrong exact-fixture guard decision was accepted");

    semantics::ObservedGuardPathEvidence duplicateDecision = completeObservation();
    duplicateDecision.decisions.push_back(duplicateDecision.decisions.front());
    const semantics::RecognitionResult duplicateDecisionResult = semantics::recognizeOpcode89RegisterRangeClear(
        shapeOnly, lanes(1, 2), duplicateDecision, semantics::RequiredProof::PathSpecificSemantic);
    ok &= require(duplicateDecisionResult.status == semantics::RecognitionStatus::IncompleteGuardPathProof,
        "duplicate exact-fixture guard decision was accepted");

    semantics::ObservedGuardPathEvidence contradiction = completeObservation();
    contradiction.selected_handler_end += 1;
    const semantics::RecognitionResult contradictoryHandler = semantics::recognizeOpcode89RegisterRangeClear(
        shapeOnly, lanes(1, 2), contradiction, semantics::RequiredProof::PathSpecificSemantic);
    ok &= require(contradictoryHandler.status == semantics::RecognitionStatus::ContradictoryGuardPathProof,
        "contradictory selected handler range was accepted");

    const semantics::RecognitionResult staticWithContradiction = semantics::recognizeOpcode89RegisterRangeClear(
        staticGuard, lanes(1, 2), contradiction, semantics::RequiredProof::GeneralSemantic);
    ok &= require(staticWithContradiction.status == semantics::RecognitionStatus::ContradictoryGuardPathProof,
        "contradictory runtime evidence was ignored in the presence of static guard proof");

    semantics::ObservedGuardPathEvidence outsideWrite = completeObservation();
    outsideWrite.changed_register_writes = {{3, true}};
    const semantics::RecognitionResult outsideWriteResult = semantics::recognizeOpcode89RegisterRangeClear(
        shapeOnly, lanes(4, 8), outsideWrite, semantics::RequiredProof::PathSpecificSemantic);
    ok &= require(outsideWriteResult.status == semantics::RecognitionStatus::ContradictoryGuardPathProof,
        "changed register outside the inclusive range was accepted");

    semantics::ObservedGuardPathEvidence nonNilWrite = completeObservation();
    nonNilWrite.changed_register_writes = {{5, false}};
    const semantics::RecognitionResult nonNilWriteResult = semantics::recognizeOpcode89RegisterRangeClear(
        shapeOnly, lanes(4, 8), nonNilWrite, semantics::RequiredProof::PathSpecificSemantic);
    ok &= require(nonNilWriteResult.status == semantics::RecognitionStatus::ContradictoryGuardPathProof,
        "observed non-nil write was accepted as a clear");

    semantics::ObservedGuardPathEvidence duplicateWrite = completeObservation();
    duplicateWrite.changed_register_writes = {{5, true}, {5, true}};
    const semantics::RecognitionResult duplicateWriteResult = semantics::recognizeOpcode89RegisterRangeClear(
        shapeOnly, lanes(4, 8), duplicateWrite, semantics::RequiredProof::PathSpecificSemantic);
    ok &= require(duplicateWriteResult.status == semantics::RecognitionStatus::ContradictoryGuardPathProof,
        "duplicate changed-register evidence was accepted");

    semantics::StaticHandlerEvidence wrongOpcode = shapeOnly;
    wrongOpcode.opcode = 88;
    ok &= require(semantics::recognizeOpcode89RegisterRangeClear(wrongOpcode, lanes(1, 2)).status ==
                      semantics::RecognitionStatus::WrongOpcode,
        "non-89 opcode was accepted");

    semantics::StaticHandlerEvidence reusedOpcodeLocal = shapeOnly;
    reusedOpcodeLocal.opcode_local_reused = true;
    ok &= require(semantics::recognizeOpcode89RegisterRangeClear(reusedOpcodeLocal, lanes(1, 2)).status ==
                      semantics::RecognitionStatus::HandlerShapeMismatch,
        "reused opcode local was accepted");

    semantics::StaticHandlerEvidence extraStatement = shapeOnly;
    extraStatement.continuation_statement_count = 1;
    ok &= require(semantics::recognizeOpcode89RegisterRangeClear(extraStatement, lanes(1, 2)).status ==
                      semantics::RecognitionStatus::HandlerShapeMismatch,
        "handler leaf with an extra executable statement was accepted");

    semantics::StaticHandlerEvidence swappedLanes = shapeOnly;
    swappedLanes.first_register_lane = semantics::RuntimeOperandLane::S;
    swappedLanes.last_register_lane = semantics::RuntimeOperandLane::r;
    ok &= require(semantics::recognizeOpcode89RegisterRangeClear(swappedLanes, lanes(1, 2)).status ==
                      semantics::RecognitionStatus::HandlerShapeMismatch,
        "swapped endpoint lanes were accepted");

    semantics::StaticHandlerEvidence nonNilHandler = shapeOnly;
    nonNilHandler.writes_nil_to_register_file = false;
    ok &= require(semantics::recognizeOpcode89RegisterRangeClear(nonNilHandler, lanes(1, 2)).status ==
                      semantics::RecognitionStatus::HandlerShapeMismatch,
        "non-nil handler was accepted as a range clear");

    ok &= require(std::string_view(semantics::toString(semantics::RuntimeOperandLane::r)) == "r" &&
                      std::string_view(semantics::toString(
                          semantics::ProofScope::RuntimeObservedGuardPath)) == "runtime_observed_guard_path" &&
                      std::string_view(semantics::toString(
                          semantics::RecognitionStatus::GeneralProofUnavailable)) == "general_proof_unavailable",
        "stable lane, provenance, or status labels are incorrect");

    return ok ? 0 : 1;
}
