#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace alex::deobfuscator::readable
{

struct RewriteResult
{
    std::string source;
    nlohmann::json mapping = nlohmann::json::array();
    size_t regions_found = 0;
    size_t regions_structured = 0;
    size_t blocks_structured = 0;
    size_t reentry_nodes_split = 0;
    size_t residual_state_machines = 0;
    size_t dead_assignments_removed = 0;
    size_t constants_propagated = 0;
    size_t aliases_propagated = 0;
    size_t properties_recovered = 0;
    size_t methods_recovered = 0;
    size_t prototypes_nested = 0;
    size_t capture_references_recovered = 0;
    size_t globals_recovered = 0;
    size_t numeric_loops_recovered = 0;
    size_t generic_loops_recovered = 0;
    size_t unused_command_results_removed = 0;
    size_t locals_promoted = 0;
    size_t declarations_pruned = 0;
    size_t function_parameters_recovered = 0;
    size_t unused_captures_removed = 0;
    size_t capture_factories_collapsed = 0;
    size_t dead_capture_factories_removed = 0;
    size_t discarded_anonymous_functions_removed = 0;
    size_t captured_cells_unboxed = 0;
    size_t stable_capture_cells_scalarized = 0;
    size_t stable_capture_accesses_scalarized = 0;
    size_t returned_closures_recovered = 0;
    size_t function_locals_promoted = 0;
    size_t leading_semicolons_removed = 0;
    size_t redundant_index_groupings_removed = 0;
    size_t redundant_parentheses_removed = 0;
    size_t captured_locals_named = 0;
    size_t semantic_locals_promoted = 0;
    size_t semantic_initializers_coalesced = 0;
    size_t single_assignment_aliases_folded = 0;
    size_t blank_lines_removed = 0;
    size_t property_temporaries_inlined = 0;
    size_t unused_call_results_removed = 0;
    size_t default_assignments_recovered = 0;
    size_t unused_cell_allocations_removed = 0;
    size_t result_returns_collapsed = 0;
    size_t result_packs_collapsed = 0;
    size_t fixed_top_call_packs_expanded = 0;
    size_t write_only_result_packs_removed = 0;
    size_t empty_branches_removed = 0;
    size_t state_registers_renamed = 0;
    size_t alias_reloads_eliminated = 0;
    size_t producer_aliases_coalesced = 0;
    size_t numeric_literals_normalized = 0;
    size_t register_tables_scalarized = 0;
    size_t register_tables_fully_scalarized = 0;
    size_t register_tables_partially_scalarized = 0;
    size_t register_table_slots_scalarized = 0;
    size_t register_table_accesses_scalarized = 0;
    size_t state_tables_scalarized = 0;
    size_t state_fields_scalarized = 0;
    size_t state_accesses_scalarized = 0;
    size_t replay_sequences_compressed = 0;
    size_t replay_sequence_entries_collapsed = 0;
    size_t replay_bytes_removed = 0;
    size_t replay_targets_inlined = 0;
    size_t high_register_replay_patches_removed = 0;
    size_t cleared_replay_metadata_patches_removed = 0;
    size_t low_register_replay_patches_removed = 0;
    size_t replay_branches_collapsed = 0;
    size_t linear_replay_metadata_patches_removed = 0;
    size_t single_use_temporaries_inlined = 0;
    size_t single_use_expressions_inlined = 0;
    size_t callback_aliases_promoted = 0;
    size_t direct_closure_calls_recovered = 0;
    size_t trace_instrumentation_removed = 0;
    size_t unreachable_prototypes_removed = 0;
    size_t semantic_lifetimes_split = 0;
    size_t temporary_conditions_inlined = 0;
    size_t guard_clauses_flattened = 0;
    size_t refinement_passes = 0;
    size_t residual_bindings_renamed = 0;
    size_t residual_generated_bindings_renamed = 0;
    size_t residual_temporary_bindings_renamed = 0;
    size_t residual_semantic_role_names = 0;
    size_t residual_generic_fallback_names = 0;
    size_t residual_generated_merge_names = 0;
    size_t residual_register_bindings_named = 0;
    size_t residual_mutable_cells_named = 0;
    size_t residual_callbacks_named = 0;
    size_t residual_vm_values_named = 0;
    size_t residual_vm_temporaries_named = 0;
    size_t unused_local_declarations_removed = 0;
    nlohmann::json residual_binding_diagnostics = nlohmann::json::array();
    nlohmann::json residual_reasons = nlohmann::json::object();
    bool changed = false;
};

using ProgressCallback = std::function<void(
    std::string_view stage, std::string_view status, std::string_view message, const nlohmann::json& metrics)>;

struct RewriteOptions
{
    bool allow_register_overflow = false;
    bool stabilize_residual_names = false;
};

RewriteResult rewriteStateMachines(
    std::string_view source, const nlohmann::json& mapping, const ProgressCallback& progress = {},
    const RewriteOptions& options = {});

// Exposes one deterministic refinement round for diagnostics and focused pass tests.
RewriteResult rewriteStateMachinesSinglePass(
    std::string_view source, const nlohmann::json& mapping, const ProgressCallback& progress = {});

} // namespace alex::deobfuscator::readable
