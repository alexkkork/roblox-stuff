#include "range_clear_semantics.hpp"

#include <limits>
#include <unordered_set>
#include <utility>

namespace alex::deobfuscator::luraph::range_clear
{

namespace
{

bool exactHandlerShape(const StaticHandlerEvidence& handler)
{
    return handler.opcode == kOpcode89 &&
        handler.source_begin == kExactFixtureHandlerBegin &&
        handler.source_end == kExactFixtureHandlerEnd &&
        handler.source_begin < handler.source_end &&
        handler.first_register_lane == RuntimeOperandLane::r &&
        handler.last_register_lane == RuntimeOperandLane::S &&
        handler.step == 1 &&
        handler.body_statement_count == 1 &&
        handler.register_write_count == 1 &&
        handler.table_write_count == 1 &&
        handler.call_count == 0 &&
        handler.closure_count == 0 &&
        handler.conditional_count == 0 &&
        handler.pc_write_count == 0 &&
        handler.continuation_statement_count == 0 &&
        handler.normalization_complete &&
        handler.vm_state_independent &&
        !handler.opcode_local_reused &&
        handler.numeric_for_loop &&
        handler.inclusive_last_register &&
        handler.destination_is_loop_index &&
        handler.writes_nil_to_register_file;
}

RecognitionResult reject(RecognitionStatus status, std::string diagnostic)
{
    RecognitionResult result;
    result.status = status;
    result.diagnostic = std::move(diagnostic);
    return result;
}

RegisterRangeClear makeOperation(int64_t firstRegister, int64_t lastRegister)
{
    RegisterRangeClear operation;
    operation.first_register = firstRegister;
    operation.last_register = lastRegister;
    operation.empty = firstRegister > lastRegister;

    if (operation.empty)
    {
        operation.assignment_count = 0;
        return operation;
    }

    const uint64_t distance = static_cast<uint64_t>(lastRegister) - static_cast<uint64_t>(firstRegister);
    if (distance == std::numeric_limits<uint64_t>::max())
    {
        operation.assignment_count_overflow = true;
        return operation;
    }

    operation.assignment_count = distance + 1;
    return operation;
}

bool containsUniqueExactFixtureDecision(const ObservedGuardPathEvidence& observed)
{
    size_t matchCount = 0;
    for (const GuardDecision& decision : observed.decisions)
    {
        if (decision.source_begin == kExactFixtureGuardBegin &&
            decision.source_end == kExactFixtureGuardEnd)
        {
            ++matchCount;
            if (!decision.decision)
                return false;
        }
    }
    return matchCount == 1;
}

bool changedWritesAreConsistent(
    const ObservedGuardPathEvidence& observed,
    int64_t firstRegister,
    int64_t lastRegister)
{
    std::unordered_set<int64_t> uniqueRegisters;
    for (const ObservedRegisterWrite& write : observed.changed_register_writes)
    {
        if (!write.value_is_nil || write.register_index < firstRegister || write.register_index > lastRegister ||
            !uniqueRegisters.insert(write.register_index).second)
            return false;
    }
    return true;
}

} // namespace

std::optional<int64_t> RuntimeOperandLanes::value(RuntimeOperandLane lane) const
{
    switch (lane)
    {
    case RuntimeOperandLane::S: return S;
    case RuntimeOperandLane::V: return V;
    case RuntimeOperandLane::Z: return Z;
    case RuntimeOperandLane::g: return g;
    case RuntimeOperandLane::r: return r;
    case RuntimeOperandLane::v: return v;
    }
    return std::nullopt;
}

StaticHandlerEvidence exactFixtureHandlerEvidence()
{
    StaticHandlerEvidence handler;
    handler.opcode = kOpcode89;
    handler.source_begin = kExactFixtureHandlerBegin;
    handler.source_end = kExactFixtureHandlerEnd;
    handler.first_register_lane = RuntimeOperandLane::r;
    handler.last_register_lane = RuntimeOperandLane::S;
    handler.step = 1;
    handler.body_statement_count = 1;
    handler.register_write_count = 1;
    handler.table_write_count = 1;
    handler.normalization_complete = true;
    handler.vm_state_independent = true;
    handler.opcode_local_reused = false;
    handler.numeric_for_loop = true;
    handler.inclusive_last_register = true;
    handler.destination_is_loop_index = true;
    handler.writes_nil_to_register_file = true;
    return handler;
}

RecognitionResult recognizeOpcode89RegisterRangeClear(
    const StaticHandlerEvidence& handler,
    const RuntimeOperandLanes& lanes,
    const std::optional<ObservedGuardPathEvidence>& observedGuardPath,
    RequiredProof requiredProof)
{
    if (handler.opcode != kOpcode89)
        return reject(RecognitionStatus::WrongOpcode, "the handler opcode is not 89");

    if (!exactHandlerShape(handler))
    {
        return reject(RecognitionStatus::HandlerShapeMismatch,
            "the handler does not exactly match the supplied fixture's inclusive r-to-S nil-clear leaf");
    }

    const std::optional<int64_t> firstRegister = lanes.value(handler.first_register_lane);
    const std::optional<int64_t> lastRegister = lanes.value(handler.last_register_lane);
    if (!firstRegister || !lastRegister || *firstRegister < 0 || *lastRegister < 0)
    {
        return reject(RecognitionStatus::InvalidOperandLane,
            "both runtime operand lanes r and S must be proven nonnegative integers");
    }
    if (lanes.register_capacity &&
        (static_cast<uint64_t>(*firstRegister) >= *lanes.register_capacity ||
            static_cast<uint64_t>(*lastRegister) >= *lanes.register_capacity))
    {
        return reject(RecognitionStatus::InvalidOperandLane,
            "a register endpoint is outside the proven register capacity");
    }

    if (observedGuardPath)
    {
        const ObservedGuardPathEvidence& observed = *observedGuardPath;
        if (observed.opcode != kOpcode89 ||
            observed.selected_handler_begin != handler.source_begin ||
            observed.selected_handler_end != handler.source_end ||
            !changedWritesAreConsistent(observed, *firstRegister, *lastRegister))
        {
            return reject(RecognitionStatus::ContradictoryGuardPathProof,
                "the observed opcode, selected handler, or changed writes contradict the static opcode-89 leaf");
        }
        if (!observed.path_complete || observed.path_overflow || !observed.selected_handler_exactly ||
            !observed.executed_statement_path_complete || !observed.full_effect_validation ||
            observed.observation_count == 0 || !containsUniqueExactFixtureDecision(observed))
        {
            return reject(RecognitionStatus::IncompleteGuardPathProof,
                "the observed guard path is incomplete, overflowing, unvalidated, empty, or missing its exact decision");
        }

    }

    RecognitionProof proof;
    if (handler.guard_selection_statically_proven)
    {
        proof.scope = ProofScope::StaticGuardPath;
        proof.general_semantic = true;
    }
    else if (observedGuardPath)
    {
        proof.scope = ProofScope::RuntimeObservedGuardPath;
        proof.path_specific = true;
        proof.observation_count = observedGuardPath->observation_count;
    }
    else
    {
        proof.scope = ProofScope::StaticHandlerShape;
    }

    if (requiredProof == RequiredProof::GeneralSemantic && !proof.general_semantic)
    {
        return reject(RecognitionStatus::GeneralProofUnavailable,
            "handler-shape or repeated runtime evidence cannot replace a static guard-selection proof");
    }
    if (requiredProof == RequiredProof::PathSpecificSemantic &&
        proof.scope == ProofScope::StaticHandlerShape)
    {
        return reject(RecognitionStatus::MissingGuardPathProof,
            "path-specific semantics require a complete observed guard path");
    }

    RecognitionResult result;
    result.status = RecognitionStatus::Recognized;
    result.operation = makeOperation(*firstRegister, *lastRegister);
    result.proof = proof;
    switch (proof.scope)
    {
    case ProofScope::StaticHandlerShape:
        result.diagnostic = "recognized as static handler-shape evidence only";
        break;
    case ProofScope::RuntimeObservedGuardPath:
        result.diagnostic = "recognized only for the complete observed guard path";
        break;
    case ProofScope::StaticGuardPath:
        result.diagnostic = "recognized as general semantics from static handler and guard proofs";
        break;
    }
    return result;
}

const char* toString(RuntimeOperandLane lane)
{
    switch (lane)
    {
    case RuntimeOperandLane::S: return "S";
    case RuntimeOperandLane::V: return "V";
    case RuntimeOperandLane::Z: return "Z";
    case RuntimeOperandLane::g: return "g";
    case RuntimeOperandLane::r: return "r";
    case RuntimeOperandLane::v: return "v";
    }
    return "unknown";
}

const char* toString(ProofScope scope)
{
    switch (scope)
    {
    case ProofScope::StaticHandlerShape: return "static_handler_shape";
    case ProofScope::RuntimeObservedGuardPath: return "runtime_observed_guard_path";
    case ProofScope::StaticGuardPath: return "static_guard_path";
    }
    return "unknown";
}

const char* toString(RecognitionStatus status)
{
    switch (status)
    {
    case RecognitionStatus::Recognized: return "recognized";
    case RecognitionStatus::WrongOpcode: return "wrong_opcode";
    case RecognitionStatus::HandlerShapeMismatch: return "handler_shape_mismatch";
    case RecognitionStatus::InvalidOperandLane: return "invalid_operand_lane";
    case RecognitionStatus::MissingGuardPathProof: return "missing_guard_path_proof";
    case RecognitionStatus::IncompleteGuardPathProof: return "incomplete_guard_path_proof";
    case RecognitionStatus::ContradictoryGuardPathProof: return "contradictory_guard_path_proof";
    case RecognitionStatus::GeneralProofUnavailable: return "general_proof_unavailable";
    }
    return "unknown";
}

} // namespace alex::deobfuscator::luraph::range_clear
