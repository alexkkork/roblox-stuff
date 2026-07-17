#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace alex::deobfuscator::luraph::index_read
{

inline constexpr int64_t kOpcode28 = 28;
inline constexpr size_t kExactFixtureGuardBegin = 341070;
inline constexpr size_t kExactFixtureGuardEnd = 341098;
inline constexpr size_t kExactFixtureLeafBegin = 341212;
inline constexpr size_t kExactFixtureLeafEnd = 341238;

enum class RuntimeOperandLane
{
    S,
    V,
    Z,
    g,
    r,
    v,
};

enum class EvaluationStep
{
    ReadTableRegister,
    ReadIndexOperand,
    PerformIndexRead,
    WriteDestinationRegister,
};

// This describes the exact normalized leaf R[r] = R[S][V]. It is deliberately
// stricter than a generic register-write shape: the lookup remains an ordered,
// effectful operation because it can invoke __index or raise an error.
struct StaticHandlerEvidence
{
    int64_t opcode = 0;
    size_t source_begin = 0;
    size_t source_end = 0;
    RuntimeOperandLane destination_lane = RuntimeOperandLane::r;
    RuntimeOperandLane table_register_lane = RuntimeOperandLane::S;
    RuntimeOperandLane index_lane = RuntimeOperandLane::V;
    size_t body_statement_count = 0;
    size_t register_read_count = 0;
    size_t register_write_count = 0;
    size_t index_read_count = 0;
    size_t direct_call_count = 0;
    size_t closure_count = 0;
    size_t conditional_count = 0;
    size_t pc_write_count = 0;
    size_t continuation_statement_count = 0;
    bool normalization_complete = false;
    bool opcode_local_reused = true;
    bool destination_is_register_slot = false;
    bool table_operand_is_register_read = false;
    bool index_operand_is_runtime_lane = false;
    bool lookup_evaluated_once = false;
    bool result_written_only_after_lookup = false;
    bool lookup_may_invoke_index_metamethod = false;
    bool lookup_may_raise = false;
    bool lookup_is_effectful = false;
    bool lookup_constant_foldable = true;
    bool lookup_common_subexpression_eliminable = true;
    bool guard_selection_statically_proven = false;
};

// V is intentionally not materialized here. Its value may be any Luau key,
// including a value that makes the lookup fail. Keeping only the lane identity
// prevents the recognizer from replacing the lookup with an observed result.
struct RuntimeOperands
{
    std::optional<int64_t> destination_register;
    std::optional<int64_t> table_register;
    bool index_operand_present = false;
    std::optional<uint64_t> register_capacity;
};

struct GuardDecision
{
    size_t source_begin = 0;
    size_t source_end = 0;
    bool decision = false;
};

// Changed-register rows are lower-bound evidence. The trace omits a write when
// the assigned value is rawequal to the previous register value.
struct ObservedGuardPathEvidence
{
    int64_t opcode = 0;
    size_t selected_handler_begin = 0;
    size_t selected_handler_end = 0;
    bool path_complete = false;
    bool path_overflow = false;
    bool selected_handler_exactly = false;
    bool executed_statement_path_complete = false;
    bool full_effect_validation = false;
    bool lookup_attempt_observed = false;
    uint64_t observation_count = 0;
    std::vector<GuardDecision> decisions;
    std::vector<int64_t> changed_register_writes;
};

enum class ProofScope
{
    RuntimeObservedGuardPath,
    StaticGuardPath,
};

enum class RequiredProof
{
    AnySemantic,
    GeneralSemantic,
};

struct LookupEffectPolicy
{
    bool evaluates_table_once = true;
    bool evaluates_index_once = true;
    bool performs_lookup_once = true;
    bool writes_destination_only_after_success = true;
    bool may_invoke_index_metamethod = true;
    bool may_raise = true;
    bool effect_barrier = true;
    bool constant_foldable = false;
    bool common_subexpression_eliminable = false;
    bool dead_code_eliminable = false;
    bool reorderable = false;
};

struct RegisterTableIndexRead
{
    RuntimeOperandLane destination_lane = RuntimeOperandLane::r;
    RuntimeOperandLane table_register_lane = RuntimeOperandLane::S;
    RuntimeOperandLane index_lane = RuntimeOperandLane::V;
    int64_t destination_register = 0;
    int64_t table_register = 0;
    bool reads_table_before_destination_write = true;
    bool preserves_aliasing_when_destination_equals_table = true;
    LookupEffectPolicy effects;
    std::vector<EvaluationStep> evaluation_order;
};

struct RecognitionProof
{
    ProofScope scope = ProofScope::RuntimeObservedGuardPath;
    bool general_semantic = false;
    bool path_specific = false;
    uint64_t observation_count = 0;
};

enum class RecognitionStatus
{
    Recognized,
    WrongOpcode,
    HandlerShapeMismatch,
    InvalidOperandLane,
    MissingGuardPathProof,
    IncompleteGuardPathProof,
    ContradictoryGuardPathProof,
    GeneralProofUnavailable,
};

struct RecognitionResult
{
    RecognitionStatus status = RecognitionStatus::HandlerShapeMismatch;
    std::optional<RegisterTableIndexRead> operation;
    std::optional<RecognitionProof> proof;
    std::string diagnostic;

    bool recognized() const
    {
        return status == RecognitionStatus::Recognized && operation.has_value() && proof.has_value();
    }
};

StaticHandlerEvidence exactFixtureHandlerEvidence();

RecognitionResult recognizeOpcode28RegisterTableIndexRead(
    const StaticHandlerEvidence& handler,
    const RuntimeOperands& operands,
    const std::optional<ObservedGuardPathEvidence>& observedGuardPath = std::nullopt,
    RequiredProof requiredProof = RequiredProof::AnySemantic);

const char* toString(RuntimeOperandLane lane);
const char* toString(EvaluationStep step);
const char* toString(ProofScope scope);
const char* toString(RecognitionStatus status);

} // namespace alex::deobfuscator::luraph::index_read
