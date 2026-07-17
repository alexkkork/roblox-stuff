#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace alex::deobfuscator::luraph::range_clear
{

inline constexpr int64_t kOpcode89 = 89;
inline constexpr size_t kExactFixtureHandlerBegin = 346586;
inline constexpr size_t kExactFixtureHandlerEnd = 346621;
inline constexpr size_t kExactFixtureGuardBegin = 346327;
inline constexpr size_t kExactFixtureGuardEnd = 346347;

enum class RuntimeOperandLane
{
    S,
    V,
    Z,
    g,
    r,
    v,
};

// Values are populated only after the trace reader proves that a lane is a
// primitive integral number. Missing, nonnumeric, and fractional values remain
// nullopt and are rejected by the recognizer.
struct RuntimeOperandLanes
{
    std::optional<int64_t> S;
    std::optional<int64_t> V;
    std::optional<int64_t> Z;
    std::optional<int64_t> g;
    std::optional<int64_t> r;
    std::optional<int64_t> v;
    std::optional<uint64_t> register_capacity;

    std::optional<int64_t> value(RuntimeOperandLane lane) const;
};

// This describes the exact normalized handler leaf. It is not, by itself,
// proof that a surrounding protector guard selects the leaf for every state.
struct StaticHandlerEvidence
{
    int64_t opcode = 0;
    size_t source_begin = 0;
    size_t source_end = 0;
    RuntimeOperandLane first_register_lane = RuntimeOperandLane::r;
    RuntimeOperandLane last_register_lane = RuntimeOperandLane::S;
    int64_t step = 0;
    size_t body_statement_count = 0;
    size_t register_write_count = 0;
    size_t table_write_count = 0;
    size_t call_count = 0;
    size_t closure_count = 0;
    size_t conditional_count = 0;
    size_t pc_write_count = 0;
    size_t continuation_statement_count = 0;
    bool normalization_complete = false;
    bool vm_state_independent = false;
    bool opcode_local_reused = true;
    bool numeric_for_loop = false;
    bool inclusive_last_register = false;
    bool destination_is_loop_index = false;
    bool writes_nil_to_register_file = false;
    bool guard_selection_statically_proven = false;
};

struct GuardDecision
{
    size_t source_begin = 0;
    size_t source_end = 0;
    bool decision = false;
};

struct ObservedRegisterWrite
{
    int64_t register_index = 0;
    bool value_is_nil = false;
};

// Runtime proof remains activation/path specific. Changed-register traces may
// omit nil-to-nil assignments, so sparse or empty write lists are valid.
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
    uint64_t observation_count = 0;
    std::vector<GuardDecision> decisions;
    std::vector<ObservedRegisterWrite> changed_register_writes;
};

enum class ProofScope
{
    StaticHandlerShape,
    RuntimeObservedGuardPath,
    StaticGuardPath,
};

enum class RequiredProof
{
    HandlerShape,
    PathSpecificSemantic,
    GeneralSemantic,
};

struct RegisterRangeClear
{
    RuntimeOperandLane first_register_lane = RuntimeOperandLane::r;
    RuntimeOperandLane last_register_lane = RuntimeOperandLane::S;
    int64_t first_register = 0;
    int64_t last_register = 0;
    int64_t step = 1;
    bool inclusive_last_register = true;
    bool writes_nil = true;
    bool empty = false;
    std::optional<uint64_t> assignment_count;
    bool assignment_count_overflow = false;
};

struct RecognitionProof
{
    ProofScope scope = ProofScope::StaticHandlerShape;
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
    std::optional<RegisterRangeClear> operation;
    std::optional<RecognitionProof> proof;
    std::string diagnostic;

    bool recognized() const
    {
        return status == RecognitionStatus::Recognized && operation.has_value() && proof.has_value();
    }
};

StaticHandlerEvidence exactFixtureHandlerEvidence();

RecognitionResult recognizeOpcode89RegisterRangeClear(
    const StaticHandlerEvidence& handler,
    const RuntimeOperandLanes& lanes,
    const std::optional<ObservedGuardPathEvidence>& observedGuardPath = std::nullopt,
    RequiredProof requiredProof = RequiredProof::HandlerShape);

const char* toString(RuntimeOperandLane lane);
const char* toString(ProofScope scope);
const char* toString(RecognitionStatus status);

} // namespace alex::deobfuscator::luraph::range_clear
