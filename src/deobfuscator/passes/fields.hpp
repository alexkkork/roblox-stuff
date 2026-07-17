#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace alex::deobfuscator::state_fields
{

struct RefinementResult
{
    std::string source;
    bool parse_succeeded = false;
    bool compile_attempted = false;
    bool candidate_compiled = false;
    bool committed = false;
    size_t generated_callback_fields_found = 0;
    size_t fields_proposed = 0;
    size_t fields_renamed = 0;
    size_t references_proposed = 0;
    size_t references_renamed = 0;
    size_t ambiguous_fields = 0;
    size_t unproven_fields = 0;
    size_t unsafe_state_tables = 0;
    size_t unsafe_fields = 0;
    size_t name_collisions_detected = 0;
    size_t name_collisions_avoided = 0;
    std::vector<std::string> diagnostics;
};

// Refines private callback fields introduced by register spilling. Changes are
// returned only when the complete rewritten source parses and compiles.
RefinementResult refineGeneratedCallbackFields(std::string_view source);

} // namespace alex::deobfuscator::state_fields
