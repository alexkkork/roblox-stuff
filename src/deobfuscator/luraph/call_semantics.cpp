#include "call_semantics.hpp"

#include <algorithm>
#include <limits>
#include <unordered_set>

namespace alex::deobfuscator::luraph::call_semantics
{
namespace
{

bool checkedAdd(int64_t left, uint64_t right, int64_t& result)
{
    if (right > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
        left > std::numeric_limits<int64_t>::max() - static_cast<int64_t>(right))
        return false;
    result = left + static_cast<int64_t>(right);
    return true;
}

RecognitionResult fail(RecognitionStatus status, const char* diagnostic)
{
    RecognitionResult result;
    result.status = status;
    result.diagnostic = diagnostic;
    return result;
}

bool validateChangedRegisters(
    const std::vector<int64_t>& changed,
    const RegisterRange& assignments,
    std::string& diagnostic)
{
    std::unordered_set<int64_t> seen;
    for (const int64_t reg : changed)
    {
        if (reg < 0)
        {
            diagnostic = "changed-register evidence contains a negative register";
            return false;
        }
        if (!seen.insert(reg).second)
        {
            diagnostic = "changed-register evidence contains a duplicate register";
            return false;
        }
        if (reg < assignments.begin || (assignments.end_exclusive && reg >= *assignments.end_exclusive))
        {
            diagnostic = "changed-register evidence falls outside the handler assignment range";
            return false;
        }
    }
    return true;
}

} // namespace

RecognitionResult recognizeOpcode8Call(const Opcode8CallEvidence& evidence)
{
    if (evidence.opcode != 8)
        return fail(RecognitionStatus::InvalidEvidence, "evidence is not for opcode 8");
    if (!evidence.packed_handler_shape_verified)
        return fail(RecognitionStatus::InsufficientEvidence, "packed call handler shape is not verified");
    if (evidence.guard_path_proof == GuardPathProof::None || !evidence.guard_path_complete)
        return fail(RecognitionStatus::InsufficientEvidence, "the call leaf is not selected by a complete guard-path proof");
    if (evidence.base_register < 0 || evidence.encoded_argument_count < 0 || evidence.encoded_result_count < 0)
        return fail(RecognitionStatus::InvalidEvidence, "opcode operands must be non-negative integers");
    if (evidence.incoming_top && *evidence.incoming_top < -1)
        return fail(RecognitionStatus::InvalidEvidence, "incoming top is outside the VM register domain");

    Opcode8CallSemantics semantics;
    semantics.function_register = evidence.base_register;
    semantics.result_base_register = evidence.base_register;
    semantics.encoded_argument_count = evidence.encoded_argument_count;
    semantics.encoded_result_count = evidence.encoded_result_count;
    semantics.runtime_validated = evidence.guard_path_proof == GuardPathProof::RuntimeObserved;

    int64_t firstArgument = 0;
    if (!checkedAdd(evidence.base_register, 1, firstArgument))
        return fail(RecognitionStatus::InvalidEvidence, "argument register arithmetic overflows");
    semantics.arguments.registers.begin = firstArgument;

    if (evidence.encoded_argument_count == 0)
    {
        semantics.arguments.mode = ArgumentMode::Open;
        if (evidence.incoming_top)
        {
            int64_t openEnd = 0;
            if (!checkedAdd(*evidence.incoming_top, 1, openEnd))
                return fail(RecognitionStatus::InvalidEvidence, "open argument range overflows");
            const int64_t end = std::max(firstArgument, openEnd);
            semantics.arguments.registers.end_exclusive = end;
            semantics.arguments.count = static_cast<uint64_t>(end - firstArgument);
        }
    }
    else if (evidence.encoded_argument_count == 1)
    {
        semantics.arguments.mode = ArgumentMode::Empty;
        semantics.arguments.registers.end_exclusive = firstArgument;
        semantics.arguments.count = 0;
    }
    else
    {
        semantics.arguments.mode = ArgumentMode::Fixed;
        const uint64_t count = static_cast<uint64_t>(evidence.encoded_argument_count - 1);
        int64_t end = 0;
        if (!checkedAdd(firstArgument, count, end))
            return fail(RecognitionStatus::InvalidEvidence, "fixed argument range overflows");
        semantics.arguments.registers.end_exclusive = end;
        semantics.arguments.count = count;
    }

    ResultPlacement& results = semantics.results;
    results.actual_result_arity = evidence.actual_result_arity;
    results.logical_registers.begin = evidence.base_register;
    results.assignment_registers.begin = evidence.base_register;

    if (evidence.encoded_result_count == 0)
    {
        results.mode = ResultMode::Open;
        if (evidence.actual_result_arity)
        {
            int64_t end = 0;
            if (!checkedAdd(evidence.base_register, *evidence.actual_result_arity, end))
                return fail(RecognitionStatus::InvalidEvidence, "open result range overflows");
            results.logical_registers.end_exclusive = end;
            results.assignment_registers.end_exclusive = end;
            results.assignment_count = *evidence.actual_result_arity;
            results.top_after = end - 1;
        }
    }
    else if (evidence.encoded_result_count == 1)
    {
        results.mode = ResultMode::Discard;
        results.requested_count = 0;
        results.logical_registers.end_exclusive = evidence.base_register;
        results.top_after = evidence.base_register - 1;
        results.encoded_one_loop_bound_anomaly = true;

        if (evidence.actual_result_arity)
        {
            const uint64_t base = static_cast<uint64_t>(evidence.base_register);
            uint64_t assignmentCount = 0;
            if (*evidence.actual_result_arity >= base)
            {
                const uint64_t difference = *evidence.actual_result_arity - base;
                if (difference == std::numeric_limits<uint64_t>::max())
                    return fail(RecognitionStatus::InvalidEvidence, "encoded-one assignment count overflows");
                assignmentCount = difference + 1;
            }
            int64_t end = 0;
            if (!checkedAdd(evidence.base_register, assignmentCount, end))
                return fail(RecognitionStatus::InvalidEvidence, "encoded-one assignment range overflows");
            results.assignment_registers.end_exclusive = end;
            results.assignment_count = assignmentCount;
        }
    }
    else
    {
        results.mode = ResultMode::Fixed;
        const uint64_t count = static_cast<uint64_t>(evidence.encoded_result_count - 1);
        int64_t end = 0;
        if (!checkedAdd(evidence.base_register, count, end))
            return fail(RecognitionStatus::InvalidEvidence, "fixed result range overflows");
        results.requested_count = count;
        results.logical_registers.end_exclusive = end;
        results.assignment_registers.end_exclusive = end;
        results.assignment_count = count;
        results.top_after = end;
        results.nil_pads_missing_values = true;
        results.truncates_extra_values = true;
    }

    std::string changedDiagnostic;
    if (!validateChangedRegisters(evidence.observed_changed_registers, results.assignment_registers, changedDiagnostic))
        return fail(RecognitionStatus::ContradictoryEvidence, changedDiagnostic.c_str());

    RecognitionResult result;
    result.status = RecognitionStatus::Recognized;
    result.semantics = std::move(semantics);
    result.diagnostic = "packed opcode-8 call semantics recognized";
    return result;
}

ChildReturnArityResult decodeChildReturnArity(const ChildReturnRangeEvidence& evidence)
{
    ChildReturnArityResult result;
    if (!evidence.complete || evidence.raw_tuple_arity != 3)
    {
        result.status = ChildReturnDecodeStatus::InvalidEvidence;
        result.diagnostic = "child return control tuple is incomplete or has the wrong raw arity";
        return result;
    }
    if (evidence.continuation)
    {
        result.status = ChildReturnDecodeStatus::NotRangeReturn;
        result.diagnostic = "child return is a continuation, not a source result range";
        return result;
    }
    if (evidence.first_register < 0 || evidence.last_register < -1)
    {
        result.status = ChildReturnDecodeStatus::InvalidEvidence;
        result.diagnostic = "child return register range is outside the VM register domain";
        return result;
    }
    if (evidence.last_register < evidence.first_register)
    {
        if (evidence.last_register != evidence.first_register - 1)
        {
            result.status = ChildReturnDecodeStatus::InvalidEvidence;
            result.diagnostic = "child return range is reversed by more than the empty-range sentinel";
            return result;
        }
        result.status = ChildReturnDecodeStatus::Decoded;
        result.source_result_arity = 0;
        result.diagnostic = "empty child source result range decoded";
        return result;
    }

    const uint64_t first = static_cast<uint64_t>(evidence.first_register);
    const uint64_t last = static_cast<uint64_t>(evidence.last_register);
    result.status = ChildReturnDecodeStatus::Decoded;
    result.source_result_arity = last - first + 1;
    result.diagnostic = "child source result range decoded";
    return result;
}

const char* toString(GuardPathProof proof)
{
    switch (proof)
    {
    case GuardPathProof::None: return "none";
    case GuardPathProof::RuntimeObserved: return "runtime_observed";
    case GuardPathProof::StaticallyProven: return "statically_proven";
    }
    return "unknown";
}

const char* toString(RecognitionStatus status)
{
    switch (status)
    {
    case RecognitionStatus::Recognized: return "recognized";
    case RecognitionStatus::InsufficientEvidence: return "insufficient_evidence";
    case RecognitionStatus::ContradictoryEvidence: return "contradictory_evidence";
    case RecognitionStatus::InvalidEvidence: return "invalid_evidence";
    }
    return "unknown";
}

const char* toString(ArgumentMode mode)
{
    switch (mode)
    {
    case ArgumentMode::Open: return "open";
    case ArgumentMode::Empty: return "empty";
    case ArgumentMode::Fixed: return "fixed";
    }
    return "unknown";
}

const char* toString(ResultMode mode)
{
    switch (mode)
    {
    case ResultMode::Open: return "open";
    case ResultMode::Discard: return "discard";
    case ResultMode::Fixed: return "fixed";
    }
    return "unknown";
}

const char* toString(ChildReturnDecodeStatus status)
{
    switch (status)
    {
    case ChildReturnDecodeStatus::Decoded: return "decoded";
    case ChildReturnDecodeStatus::NotRangeReturn: return "not_range_return";
    case ChildReturnDecodeStatus::InvalidEvidence: return "invalid_evidence";
    }
    return "unknown";
}

} // namespace alex::deobfuscator::luraph::call_semantics
