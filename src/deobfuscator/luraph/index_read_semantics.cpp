#include "index_read_semantics.hpp"

#include <set>
#include <utility>

namespace alex::deobfuscator::luraph::index_read
{

namespace
{

bool exactHandlerShape(const StaticHandlerEvidence& handler)
{
    return handler.opcode == kOpcode28 &&
        handler.source_begin == kExactFixtureLeafBegin &&
        handler.source_end == kExactFixtureLeafEnd &&
        handler.source_begin < handler.source_end &&
        handler.destination_lane == RuntimeOperandLane::r &&
        handler.table_register_lane == RuntimeOperandLane::S &&
        handler.index_lane == RuntimeOperandLane::V &&
        handler.body_statement_count == 1 &&
        handler.register_read_count == 1 &&
        handler.register_write_count == 1 &&
        handler.index_read_count == 1 &&
        handler.direct_call_count == 0 &&
        handler.closure_count == 0 &&
        handler.conditional_count == 0 &&
        handler.pc_write_count == 0 &&
        handler.continuation_statement_count == 0 &&
        handler.normalization_complete &&
        !handler.opcode_local_reused &&
        handler.destination_is_register_slot &&
        handler.table_operand_is_register_read &&
        handler.index_operand_is_runtime_lane &&
        handler.lookup_evaluated_once &&
        handler.result_written_only_after_lookup &&
        handler.lookup_may_invoke_index_metamethod &&
        handler.lookup_may_raise &&
        handler.lookup_is_effectful &&
        !handler.lookup_constant_foldable &&
        !handler.lookup_common_subexpression_eliminable;
}

RecognitionResult reject(RecognitionStatus status, std::string diagnostic)
{
    RecognitionResult result;
    result.status = status;
    result.diagnostic = std::move(diagnostic);
    return result;
}

bool validRegister(int64_t value, const std::optional<uint64_t>& capacity)
{
    return value >= 0 && (!capacity || static_cast<uint64_t>(value) < *capacity);
}

enum class ExactDecisionStatus
{
    Valid,
    MissingOrDuplicate,
    Contradictory,
};

ExactDecisionStatus validateGuardDecisions(const std::vector<GuardDecision>& decisions)
{
    std::set<std::pair<size_t, size_t>> ranges;
    size_t exactFixtureMatches = 0;

    for (const GuardDecision& decision : decisions)
    {
        if (decision.source_begin >= decision.source_end ||
            !ranges.emplace(decision.source_begin, decision.source_end).second)
            return ExactDecisionStatus::MissingOrDuplicate;

        if (decision.source_begin == kExactFixtureGuardBegin &&
            decision.source_end == kExactFixtureGuardEnd)
        {
            ++exactFixtureMatches;
            if (decision.decision)
                return ExactDecisionStatus::Contradictory;
        }
    }

    return exactFixtureMatches == 1 ? ExactDecisionStatus::Valid : ExactDecisionStatus::MissingOrDuplicate;
}

bool changedWritesAreConsistent(
    const ObservedGuardPathEvidence& observed,
    int64_t destinationRegister)
{
    std::set<int64_t> uniqueRegisters;
    for (const int64_t changedRegister : observed.changed_register_writes)
    {
        if (changedRegister != destinationRegister || !uniqueRegisters.insert(changedRegister).second)
            return false;
    }
    return true;
}

RegisterTableIndexRead makeOperation(int64_t destinationRegister, int64_t tableRegister)
{
    RegisterTableIndexRead operation;
    operation.destination_register = destinationRegister;
    operation.table_register = tableRegister;
    operation.evaluation_order = {
        EvaluationStep::ReadTableRegister,
        EvaluationStep::ReadIndexOperand,
        EvaluationStep::PerformIndexRead,
        EvaluationStep::WriteDestinationRegister,
    };
    return operation;
}

} // namespace

StaticHandlerEvidence exactFixtureHandlerEvidence()
{
    StaticHandlerEvidence handler;
    handler.opcode = kOpcode28;
    handler.source_begin = kExactFixtureLeafBegin;
    handler.source_end = kExactFixtureLeafEnd;
    handler.destination_lane = RuntimeOperandLane::r;
    handler.table_register_lane = RuntimeOperandLane::S;
    handler.index_lane = RuntimeOperandLane::V;
    handler.body_statement_count = 1;
    handler.register_read_count = 1;
    handler.register_write_count = 1;
    handler.index_read_count = 1;
    handler.normalization_complete = true;
    handler.opcode_local_reused = false;
    handler.destination_is_register_slot = true;
    handler.table_operand_is_register_read = true;
    handler.index_operand_is_runtime_lane = true;
    handler.lookup_evaluated_once = true;
    handler.result_written_only_after_lookup = true;
    handler.lookup_may_invoke_index_metamethod = true;
    handler.lookup_may_raise = true;
    handler.lookup_is_effectful = true;
    handler.lookup_constant_foldable = false;
    handler.lookup_common_subexpression_eliminable = false;
    return handler;
}

RecognitionResult recognizeOpcode28RegisterTableIndexRead(
    const StaticHandlerEvidence& handler,
    const RuntimeOperands& operands,
    const std::optional<ObservedGuardPathEvidence>& observedGuardPath,
    RequiredProof requiredProof)
{
    if (handler.opcode != kOpcode28)
        return reject(RecognitionStatus::WrongOpcode, "the handler opcode is not 28");

    if (!exactHandlerShape(handler))
    {
        return reject(RecognitionStatus::HandlerShapeMismatch,
            "the handler does not exactly match the supplied fixture's effectful R[r] = R[S][V] leaf");
    }

    if (!operands.destination_register || !operands.table_register || !operands.index_operand_present ||
        !validRegister(*operands.destination_register, operands.register_capacity) ||
        !validRegister(*operands.table_register, operands.register_capacity))
    {
        return reject(RecognitionStatus::InvalidOperandLane,
            "r and S must be in-range register indices and the V index operand must be present");
    }

    if (observedGuardPath)
    {
        const ObservedGuardPathEvidence& observed = *observedGuardPath;
        if (observed.opcode != kOpcode28 ||
            observed.selected_handler_begin != handler.source_begin ||
            observed.selected_handler_end != handler.source_end ||
            !changedWritesAreConsistent(observed, *operands.destination_register))
        {
            return reject(RecognitionStatus::ContradictoryGuardPathProof,
                "the observed opcode, selected leaf, or changed writes contradict the opcode-28 index read");
        }

        const ExactDecisionStatus decisionStatus = validateGuardDecisions(observed.decisions);
        if (decisionStatus == ExactDecisionStatus::Contradictory)
        {
            return reject(RecognitionStatus::ContradictoryGuardPathProof,
                "the exact fixture guard selected a branch other than the index-read leaf");
        }
        if (!observed.path_complete || observed.path_overflow || !observed.selected_handler_exactly ||
            !observed.executed_statement_path_complete || !observed.full_effect_validation ||
            !observed.lookup_attempt_observed || observed.observation_count == 0 ||
            decisionStatus != ExactDecisionStatus::Valid)
        {
            return reject(RecognitionStatus::IncompleteGuardPathProof,
                "the observed guard path is incomplete, unvalidated, empty, or missing its unique exact decision");
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
        return reject(RecognitionStatus::MissingGuardPathProof,
            "the exact handler shape is insufficient without a complete runtime or static guard-selection proof");
    }

    if (requiredProof == RequiredProof::GeneralSemantic && !proof.general_semantic)
    {
        return reject(RecognitionStatus::GeneralProofUnavailable,
            "runtime observations cannot replace a static guard-selection proof for general semantics");
    }

    RecognitionResult result;
    result.status = RecognitionStatus::Recognized;
    result.operation = makeOperation(*operands.destination_register, *operands.table_register);
    result.proof = proof;
    result.diagnostic = proof.general_semantic
        ? "recognized as general effectful index-read semantics from a static guard proof"
        : "recognized only for the complete observed effectful index-read path";
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

const char* toString(EvaluationStep step)
{
    switch (step)
    {
    case EvaluationStep::ReadTableRegister: return "read_table_register";
    case EvaluationStep::ReadIndexOperand: return "read_index_operand";
    case EvaluationStep::PerformIndexRead: return "perform_index_read";
    case EvaluationStep::WriteDestinationRegister: return "write_destination_register";
    }
    return "unknown";
}

const char* toString(ProofScope scope)
{
    switch (scope)
    {
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

} // namespace alex::deobfuscator::luraph::index_read
