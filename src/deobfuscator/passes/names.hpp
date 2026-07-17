#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace alex::deobfuscator
{

struct ResidualBindingRoleCounts
{
    size_t registers = 0;
    size_t mutable_cells = 0;
    size_t callbacks = 0;
    size_t semantic_values = 0;
    size_t vm_values = 0;
    size_t vm_temporaries = 0;
};

struct ResidualBindingDiagnostic
{
    std::string code;
    std::string message;
    size_t line = 0;
    size_t column = 0;
};

struct ResidualBindingRenameResult
{
    std::string source;
    size_t renamed = 0;
    size_t unused_declarations_removed = 0;
    size_t lexical_alias_versions_eliminated = 0;
    size_t generated_bindings_renamed = 0;
    size_t temporary_bindings_renamed = 0;
    size_t semantic_role_names = 0;
    size_t generic_fallback_names = 0;
    size_t generated_merge_names = 0;
    ResidualBindingRoleCounts role_counts;
    std::vector<ResidualBindingDiagnostic> diagnostics;
    bool changed = false;
    bool committed = false;
};

// All diagnostic locations are one-based. A failed transaction returns the input source and zero committed counts.
ResidualBindingRenameResult renameResidualBindings(std::string_view final_source);

// Revisit only residual vm_value/vm_temporary bindings after lifetime splitting.
// Ambiguous bindings retain their existing names.
ResidualBindingRenameResult refineResidualBindingNames(std::string_view final_source);

// Give the final, still-ambiguous cross-branch values honest generated names.
// This never claims that original identifiers were recovered.
ResidualBindingRenameResult stabilizeResidualBindingNames(std::string_view final_source);

// Rename generated callbacks only when their signal, task, protected-call, or hook destination proves a purpose.
ResidualBindingRenameResult renameGeneratedCallbackPurposes(std::string_view final_source);

// Split a bounded number of straight-line residual versions into semantic locals.
ResidualBindingRenameResult splitStraightLineResidualRoles(std::string_view final_source);

} // namespace alex::deobfuscator
