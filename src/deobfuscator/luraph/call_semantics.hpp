#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace alex::deobfuscator::luraph::call_semantics
{

enum class GuardPathProof
{
    None,
    RuntimeObserved,
    StaticallyProven,
};

enum class RecognitionStatus
{
    Recognized,
    InsufficientEvidence,
    ContradictoryEvidence,
    InvalidEvidence,
};

enum class ArgumentMode
{
    Open,
    Empty,
    Fixed,
};

enum class ResultMode
{
    Open,
    Discard,
    Fixed,
};

struct RegisterRange
{
    int64_t begin = 0;
    // nullopt means the upper bound depends on the incoming top or actual arity.
    std::optional<int64_t> end_exclusive;

    bool operator==(const RegisterRange&) const = default;
};

// Inputs describe one execution or one statically proven path through the
// captured packed-register-call handler. Changed-register rows are lower-bound
// evidence because the trace suppresses assignments whose value did not change.
struct Opcode8CallEvidence
{
    int64_t opcode = 8;
    bool packed_handler_shape_verified = false;
    GuardPathProof guard_path_proof = GuardPathProof::None;
    bool guard_path_complete = false;

    int64_t base_register = -1;
    int64_t encoded_argument_count = -1;
    int64_t encoded_result_count = -1;
    std::optional<int64_t> incoming_top;
    std::optional<uint64_t> actual_result_arity;
    std::vector<int64_t> observed_changed_registers;
    // Some guarded handlers retain the callee scratch register instead of
    // assigning it from the encoded result base on every path. A pre-call
    // frame can prove that split without guessing from post-call writes.
    std::vector<int64_t> observed_callable_registers;
    std::vector<int64_t> observed_non_callable_registers;
};

struct ArgumentPack
{
    ArgumentMode mode = ArgumentMode::Open;
    RegisterRange registers;
    std::optional<uint64_t> count;
};

struct ResultPlacement
{
    ResultMode mode = ResultMode::Open;
    std::optional<uint64_t> actual_result_arity;
    // Source-level requested result count. Open results remain nullopt.
    std::optional<uint64_t> requested_count;
    RegisterRange logical_registers;
    // Literal assignments made by the captured VM handler. This differs from
    // logical_registers only for the encoded-result-count == 1 anomaly.
    RegisterRange assignment_registers;
    std::optional<uint64_t> assignment_count;
    std::optional<int64_t> top_after;
    bool nil_pads_missing_values = false;
    bool truncates_extra_values = false;
    bool encoded_one_loop_bound_anomaly = false;
};

struct Opcode8CallSemantics
{
    int64_t function_register = 0;
    int64_t result_base_register = 0;
    int64_t encoded_argument_count = 0;
    int64_t encoded_result_count = 0;
    ArgumentPack arguments;
    ResultPlacement results;
    bool runtime_validated = false;
    bool function_register_adjusted_from_runtime_frame = false;
};

struct RecognitionResult
{
    RecognitionStatus status = RecognitionStatus::InvalidEvidence;
    std::optional<Opcode8CallSemantics> semantics;
    std::string diagnostic;
};

// The child VM reports source returns as the internal control tuple
// [false, first_register, last_register]. Its raw tuple arity is not the source
// result arity.
struct ChildReturnRangeEvidence
{
    bool complete = false;
    size_t raw_tuple_arity = 0;
    bool continuation = true;
    int64_t first_register = 0;
    int64_t last_register = -1;
};

enum class ChildReturnDecodeStatus
{
    Decoded,
    NotRangeReturn,
    InvalidEvidence,
};

struct ChildReturnArityResult
{
    ChildReturnDecodeStatus status = ChildReturnDecodeStatus::InvalidEvidence;
    std::optional<uint64_t> source_result_arity;
    std::string diagnostic;
};

RecognitionResult recognizeOpcode8Call(const Opcode8CallEvidence& evidence);
ChildReturnArityResult decodeChildReturnArity(const ChildReturnRangeEvidence& evidence);

const char* toString(GuardPathProof proof);
const char* toString(RecognitionStatus status);
const char* toString(ArgumentMode mode);
const char* toString(ResultMode mode);
const char* toString(ChildReturnDecodeStatus status);

} // namespace alex::deobfuscator::luraph::call_semantics
