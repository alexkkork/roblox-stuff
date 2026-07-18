#include "luraph/call_semantics.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>

namespace call = alex::deobfuscator::luraph::call_semantics;

namespace
{

bool require(bool condition, std::string_view message)
{
    if (!condition)
        std::cerr << "luraph_call_semantics_test: " << message << '\n';
    return condition;
}

call::Opcode8CallEvidence verified(int64_t base, int64_t arguments, int64_t results)
{
    call::Opcode8CallEvidence evidence;
    evidence.packed_handler_shape_verified = true;
    evidence.guard_path_proof = call::GuardPathProof::RuntimeObserved;
    evidence.guard_path_complete = true;
    evidence.base_register = base;
    evidence.encoded_argument_count = arguments;
    evidence.encoded_result_count = results;
    return evidence;
}

} // namespace

int main()
{
    bool ok = true;

    // Exact fixture example: prototype 2, PC 435. A=8, b=8, r=6 and
    // child [false, 9, 13] prove seven arguments and five fixed results.
    const call::ChildReturnArityResult child = call::decodeChildReturnArity({true, 3, false, 9, 13});
    ok &= require(child.status == call::ChildReturnDecodeStatus::Decoded && child.source_result_arity == 5,
        "child control tuple was mistaken for three source results");

    call::Opcode8CallEvidence fixedEvidence = verified(8, 8, 6);
    fixedEvidence.actual_result_arity = child.source_result_arity;
    fixedEvidence.observed_changed_registers = {10, 11, 12, 8, 9};
    const call::RecognitionResult fixed = call::recognizeOpcode8Call(fixedEvidence);
    ok &= require(fixed.status == call::RecognitionStatus::Recognized && fixed.semantics.has_value(),
        "observed fixed call was not recognized");
    if (fixed.semantics)
    {
        const call::Opcode8CallSemantics& model = *fixed.semantics;
        ok &= require(model.function_register == 8 && model.result_base_register == 8 && model.runtime_validated,
            "callee/result base or runtime proof is incorrect");
        ok &= require(model.arguments.mode == call::ArgumentMode::Fixed && model.arguments.count == 7 &&
                          model.arguments.registers == call::RegisterRange{9, 16},
            "fixed argument pack is incorrect");
        ok &= require(model.results.mode == call::ResultMode::Fixed && model.results.requested_count == 5 &&
                          model.results.actual_result_arity == 5 && model.results.assignment_count == 5 &&
                          model.results.assignment_registers == call::RegisterRange{8, 13} &&
                          model.results.top_after == 13,
            "fixed result placement is incorrect");
        ok &= require(model.results.nil_pads_missing_values && model.results.truncates_extra_values,
            "fixed result normalization flags are missing");
    }

    // Changed-value rows are lower bounds: nil padding can assign nil without
    // producing a trace row when the destination was already empty.
    call::Opcode8CallEvidence paddedEvidence = verified(13, 10, 4);
    paddedEvidence.actual_result_arity = 2;
    paddedEvidence.observed_changed_registers = {13, 14};
    const call::RecognitionResult padded = call::recognizeOpcode8Call(paddedEvidence);
    ok &= require(padded.status == call::RecognitionStatus::Recognized &&
                      padded.semantics->results.assignment_count == 3 &&
                      padded.semantics->results.assignment_registers == call::RegisterRange{13, 16},
        "fixed nil-padding call required every assignment to appear as a changed write");

    call::Opcode8CallEvidence truncatedEvidence = verified(3, 2, 3);
    truncatedEvidence.actual_result_arity = 8;
    const call::RecognitionResult truncated = call::recognizeOpcode8Call(truncatedEvidence);
    ok &= require(truncated.status == call::RecognitionStatus::Recognized &&
                      truncated.semantics->results.requested_count == 2 &&
                      truncated.semantics->results.actual_result_arity == 8 &&
                      truncated.semantics->results.truncates_extra_values,
        "fixed call did not preserve truncation semantics");

    call::Opcode8CallEvidence openEvidence = verified(4, 0, 0);
    openEvidence.incoming_top = 8;
    openEvidence.actual_result_arity = 81;
    openEvidence.observed_changed_registers = {4, 84};
    const call::RecognitionResult open = call::recognizeOpcode8Call(openEvidence);
    ok &= require(open.status == call::RecognitionStatus::Recognized &&
                      open.semantics->arguments.mode == call::ArgumentMode::Open &&
                      open.semantics->arguments.count == 4 &&
                      open.semantics->arguments.registers == call::RegisterRange{5, 9} &&
                      open.semantics->results.mode == call::ResultMode::Open &&
                      open.semantics->results.assignment_count == 81 &&
                      open.semantics->results.assignment_registers == call::RegisterRange{4, 85} &&
                      open.semantics->results.top_after == 84,
        "open argument/result placement is incorrect");

    const call::RecognitionResult symbolic = call::recognizeOpcode8Call(verified(4, 0, 0));
    ok &= require(symbolic.status == call::RecognitionStatus::Recognized &&
                      !symbolic.semantics->arguments.count &&
                      !symbolic.semantics->arguments.registers.end_exclusive &&
                      !symbolic.semantics->results.assignment_count &&
                      !symbolic.semantics->results.assignment_registers.end_exclusive,
        "open call invented concrete arity without runtime evidence");

    const call::RecognitionResult emptyArguments = call::recognizeOpcode8Call(verified(7, 1, 3));
    ok &= require(emptyArguments.status == call::RecognitionStatus::Recognized &&
                      emptyArguments.semantics->arguments.mode == call::ArgumentMode::Empty &&
                      emptyArguments.semantics->arguments.count == 0 &&
                      emptyArguments.semantics->arguments.registers == call::RegisterRange{8, 8},
        "encoded argument count one did not produce an empty pack");

    call::Opcode8CallEvidence retainedCallee = verified(7, 4, 0);
    retainedCallee.observed_callable_registers = {6};
    retainedCallee.observed_non_callable_registers = {7, 8, 9};
    const call::RecognitionResult retained = call::recognizeOpcode8Call(retainedCallee);
    ok &= require(retained.status == call::RecognitionStatus::Recognized && retained.semantics &&
                      retained.semantics->function_register == 6 &&
                      retained.semantics->result_base_register == 7 &&
                      retained.semantics->arguments.registers == call::RegisterRange{7, 10} &&
                      retained.semantics->function_register_adjusted_from_runtime_frame,
        "guard-retained callee register was not separated from the encoded result base");

    call::Opcode8CallEvidence disprovedCallee = verified(7, 4, 0);
    disprovedCallee.observed_non_callable_registers = {7};
    ok &= require(call::recognizeOpcode8Call(disprovedCallee).status ==
                      call::RecognitionStatus::ContradictoryEvidence,
        "disproved callee was accepted without a callable predecessor");

    call::Opcode8CallEvidence conflictingFrame = verified(7, 4, 0);
    conflictingFrame.observed_callable_registers = {7};
    conflictingFrame.observed_non_callable_registers = {7};
    ok &= require(call::recognizeOpcode8Call(conflictingFrame).status ==
                      call::RecognitionStatus::ContradictoryEvidence,
        "contradictory pre-call register classification was accepted");

    call::Opcode8CallEvidence discardNoWrites = verified(8, 2, 1);
    discardNoWrites.actual_result_arity = 5;
    const call::RecognitionResult discardLowArity = call::recognizeOpcode8Call(discardNoWrites);
    ok &= require(discardLowArity.status == call::RecognitionStatus::Recognized &&
                      discardLowArity.semantics->results.mode == call::ResultMode::Discard &&
                      discardLowArity.semantics->results.requested_count == 0 &&
                      discardLowArity.semantics->results.assignment_count == 0 &&
                      discardLowArity.semantics->results.logical_registers == call::RegisterRange{8, 8} &&
                      discardLowArity.semantics->results.assignment_registers == call::RegisterRange{8, 8} &&
                      discardLowArity.semantics->results.top_after == 7 &&
                      discardLowArity.semantics->results.encoded_one_loop_bound_anomaly,
        "encoded-result-count one anomaly was normalized away");

    call::Opcode8CallEvidence anomalousWrites = verified(2, 2, 1);
    anomalousWrites.actual_result_arity = 5;
    anomalousWrites.observed_changed_registers = {2, 3, 4, 5};
    const call::RecognitionResult anomaly = call::recognizeOpcode8Call(anomalousWrites);
    ok &= require(anomaly.status == call::RecognitionStatus::Recognized &&
                      anomaly.semantics->results.assignment_count == 4 &&
                      anomaly.semantics->results.assignment_registers == call::RegisterRange{2, 6} &&
                      anomaly.semantics->results.logical_registers == call::RegisterRange{2, 2} &&
                      anomaly.semantics->results.top_after == 1,
        "literal encoded-one loop-bound anomaly is not modeled exactly");

    call::Opcode8CallEvidence noShape = verified(8, 8, 6);
    noShape.packed_handler_shape_verified = false;
    ok &= require(call::recognizeOpcode8Call(noShape).status == call::RecognitionStatus::InsufficientEvidence,
        "unverified handler shape was accepted");

    call::Opcode8CallEvidence noPath = verified(8, 8, 6);
    noPath.guard_path_proof = call::GuardPathProof::None;
    ok &= require(call::recognizeOpcode8Call(noPath).status == call::RecognitionStatus::InsufficientEvidence,
        "unproved protector guard path was accepted");

    call::Opcode8CallEvidence partialPath = verified(8, 8, 6);
    partialPath.guard_path_complete = false;
    ok &= require(call::recognizeOpcode8Call(partialPath).status == call::RecognitionStatus::InsufficientEvidence,
        "partial protector guard path was accepted");

    call::Opcode8CallEvidence outsideWrite = verified(8, 8, 6);
    outsideWrite.observed_changed_registers = {7};
    ok &= require(call::recognizeOpcode8Call(outsideWrite).status == call::RecognitionStatus::ContradictoryEvidence,
        "changed write below the result base was accepted");

    call::Opcode8CallEvidence duplicateWrite = verified(8, 8, 6);
    duplicateWrite.observed_changed_registers = {8, 8};
    ok &= require(call::recognizeOpcode8Call(duplicateWrite).status == call::RecognitionStatus::ContradictoryEvidence,
        "duplicate changed-register evidence was accepted");

    call::Opcode8CallEvidence wrongOpcode = verified(8, 8, 6);
    wrongOpcode.opcode = 9;
    ok &= require(call::recognizeOpcode8Call(wrongOpcode).status == call::RecognitionStatus::InvalidEvidence,
        "non-opcode-8 evidence was accepted");

    call::Opcode8CallEvidence overflowing = verified(std::numeric_limits<int64_t>::max(), 2, 3);
    ok &= require(call::recognizeOpcode8Call(overflowing).status == call::RecognitionStatus::InvalidEvidence,
        "overflowing register arithmetic was accepted");

    call::Opcode8CallEvidence overflowingTop = verified(1, 0, 3);
    overflowingTop.incoming_top = std::numeric_limits<int64_t>::max();
    ok &= require(call::recognizeOpcode8Call(overflowingTop).status == call::RecognitionStatus::InvalidEvidence,
        "overflowing open argument top was accepted");

    ok &= require(call::decodeChildReturnArity({true, 3, true, 9, 13}).status ==
                      call::ChildReturnDecodeStatus::NotRangeReturn,
        "continuation tuple was decoded as source returns");
    ok &= require(call::decodeChildReturnArity({true, 2, false, 9, 13}).status ==
                      call::ChildReturnDecodeStatus::InvalidEvidence,
        "wrong raw control-tuple arity was accepted");
    const call::ChildReturnArityResult emptyChild = call::decodeChildReturnArity({true, 3, false, 9, 8});
    ok &= require(emptyChild.status == call::ChildReturnDecodeStatus::Decoded && emptyChild.source_result_arity == 0,
        "empty child result range was not decoded");
    ok &= require(call::decodeChildReturnArity({true, 3, false, 9, 7}).status ==
                      call::ChildReturnDecodeStatus::InvalidEvidence,
        "invalid reversed child result range was accepted");

    // Pinned aggregate invariants from the exact offline v3 fixture artifacts.
    constexpr std::array<uint64_t, 9> staticSitesByOrdinaryResultEncoding{16, 0, 47, 35, 21, 14, 5, 1, 1};
    constexpr uint64_t outlierStaticSites = 5;
    uint64_t staticSites = outlierStaticSites;
    for (const uint64_t count : staticSitesByOrdinaryResultEncoding)
        staticSites += count;
    ok &= require(staticSites == 145, "fixture opcode-8 static site total changed");

    constexpr std::array<uint64_t, 8> observedExecutionsByResultEncoding{11, 240, 175, 289, 502, 3, 1, 1};
    uint64_t observedExecutions = 0;
    for (const uint64_t count : observedExecutionsByResultEncoding)
        observedExecutions += count;
    ok &= require(observedExecutions == 1222, "fixture opcode-8 execution total changed");

    constexpr std::array<uint64_t, 7> matchedFixedCalls{240, 175, 288, 501, 3, 1, 1};
    uint64_t matchedFixed = 0;
    for (const uint64_t count : matchedFixedCalls)
        matchedFixed += count;
    ok &= require(matchedFixed == 1209, "fixture matched child-call total changed");

    return ok ? 0 : 1;
}
