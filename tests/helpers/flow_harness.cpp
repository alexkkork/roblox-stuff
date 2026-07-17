#include "passes/flow.hpp"
#include "passes/names.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>

using nlohmann::json;

int main(int argc, char** argv)
{
    if (argc != 2 && argc != 3)
    {
        std::cerr << "usage: readable_rewriter_harness INPUT [--rename-only|--refine-only|--split-only|--stabilize-only|--callback-only|--single-pass]\n";
        return 2;
    }

    std::ifstream input(argv[1], std::ios::binary);
    if (!input)
    {
        std::cerr << "failed to open input\n";
        return 2;
    }
    const std::string source((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    if (argc == 3 && (std::string_view(argv[2]) == "--rename-only" ||
                         std::string_view(argv[2]) == "--refine-only" ||
                         std::string_view(argv[2]) == "--split-only" ||
                         std::string_view(argv[2]) == "--stabilize-only" ||
                         std::string_view(argv[2]) == "--callback-only"))
    {
        const bool refine = std::string_view(argv[2]) == "--refine-only";
        const bool split = std::string_view(argv[2]) == "--split-only";
        const bool stabilize = std::string_view(argv[2]) == "--stabilize-only";
        const bool callbacks = std::string_view(argv[2]) == "--callback-only";
        const alex::deobfuscator::ResidualBindingRenameResult result =
            callbacks ? alex::deobfuscator::renameGeneratedCallbackPurposes(source)
                  : split ? alex::deobfuscator::splitStraightLineResidualRoles(source)
                  : stabilize ? alex::deobfuscator::stabilizeResidualBindingNames(source)
                              : refine ? alex::deobfuscator::refineResidualBindingNames(source)
                                       : alex::deobfuscator::renameResidualBindings(source);
        json output = {
            {"changed", result.changed},
            {"committed", result.committed},
            {"source", result.source},
            {"renamed", result.renamed},
            {"unused_declarations_removed", result.unused_declarations_removed},
            {"lexical_alias_versions_eliminated", result.lexical_alias_versions_eliminated},
            {"semantic_role_names", result.semantic_role_names},
            {"generic_fallback_names", result.generic_fallback_names},
            {"generated_merge_names", result.generated_merge_names},
            {"roles", {
                {"registers", result.role_counts.registers},
                {"mutable_cells", result.role_counts.mutable_cells},
                {"callbacks", result.role_counts.callbacks},
                {"semantic_values", result.role_counts.semantic_values},
                {"vm_values", result.role_counts.vm_values},
                {"vm_temporaries", result.role_counts.vm_temporaries},
            }},
        };
        std::cout << output.dump() << '\n';
        return result.committed ? 0 : 1;
    }
    const bool singlePass = argc == 3 && std::string_view(argv[2]) == "--single-pass";
    const alex::deobfuscator::readable::RewriteResult result = singlePass
        ? alex::deobfuscator::readable::rewriteStateMachinesSinglePass(source, json::array())
        : alex::deobfuscator::readable::rewriteStateMachines(source, json::array());

    json output = {
        {"changed", result.changed},
        {"source", result.source},
        {"mapping", result.mapping},
        {"metrics",
            {
                {"regions_found", result.regions_found},
                {"regions_structured", result.regions_structured},
                {"blocks_structured", result.blocks_structured},
                {"reentry_nodes_split", result.reentry_nodes_split},
                {"residual_state_machines", result.residual_state_machines},
                {"dead_assignments_removed", result.dead_assignments_removed},
                {"prototypes_nested", result.prototypes_nested},
                {"capture_references_recovered", result.capture_references_recovered},
                {"captured_cells_unboxed", result.captured_cells_unboxed},
                {"dead_capture_factories_removed", result.dead_capture_factories_removed},
                {"unused_cell_allocations_removed", result.unused_cell_allocations_removed},
                {"stable_capture_cells_scalarized", result.stable_capture_cells_scalarized},
                {"stable_capture_accesses_scalarized", result.stable_capture_accesses_scalarized},
                {"function_locals_promoted", result.function_locals_promoted},
                {"semantic_locals_promoted", result.semantic_locals_promoted},
                {"numeric_loops_recovered", result.numeric_loops_recovered},
                {"semantic_lifetimes_split", result.semantic_lifetimes_split},
                {"temporary_conditions_inlined", result.temporary_conditions_inlined},
                {"redundant_index_groupings_removed", result.redundant_index_groupings_removed},
                {"result_packs_collapsed", result.result_packs_collapsed},
                {"fixed_top_call_packs_expanded", result.fixed_top_call_packs_expanded},
                {"write_only_result_packs_removed", result.write_only_result_packs_removed},
                {"unused_call_results_removed", result.unused_call_results_removed},
                {"locals_promoted", result.locals_promoted},
                {"declarations_pruned", result.declarations_pruned},
                {"register_tables_scalarized", result.register_tables_scalarized},
                {"register_tables_fully_scalarized", result.register_tables_fully_scalarized},
                {"register_tables_partially_scalarized", result.register_tables_partially_scalarized},
                {"register_table_slots_scalarized", result.register_table_slots_scalarized},
                {"register_table_accesses_scalarized", result.register_table_accesses_scalarized},
                {"state_tables_scalarized", result.state_tables_scalarized},
                {"state_fields_scalarized", result.state_fields_scalarized},
                {"state_accesses_scalarized", result.state_accesses_scalarized},
                {"direct_closure_calls_recovered", result.direct_closure_calls_recovered},
                {"trace_instrumentation_removed", result.trace_instrumentation_removed},
                {"unreachable_prototypes_removed", result.unreachable_prototypes_removed},
                {"replay_sequences_compressed", result.replay_sequences_compressed},
                {"replay_sequence_entries_collapsed", result.replay_sequence_entries_collapsed},
                {"replay_bytes_removed", result.replay_bytes_removed},
                {"replay_targets_inlined", result.replay_targets_inlined},
                {"high_register_replay_patches_removed", result.high_register_replay_patches_removed},
                {"cleared_replay_metadata_patches_removed", result.cleared_replay_metadata_patches_removed},
                {"low_register_replay_patches_removed", result.low_register_replay_patches_removed},
                {"replay_branches_collapsed", result.replay_branches_collapsed},
                {"linear_replay_metadata_patches_removed", result.linear_replay_metadata_patches_removed},
                {"discarded_anonymous_functions_removed", result.discarded_anonymous_functions_removed},
                {"single_use_temporaries_inlined", result.single_use_temporaries_inlined},
                {"single_use_expressions_inlined", result.single_use_expressions_inlined},
                {"guard_clauses_flattened", result.guard_clauses_flattened},
                {"refinement_passes", result.refinement_passes},
                {"residual_bindings_renamed", result.residual_bindings_renamed},
                {"residual_semantic_role_names", result.residual_semantic_role_names},
                {"residual_generic_fallback_names", result.residual_generic_fallback_names},
                {"residual_generated_merge_names", result.residual_generated_merge_names},
                {"unused_local_declarations_removed", result.unused_local_declarations_removed},
                {"redundant_parentheses_removed", result.redundant_parentheses_removed},
                {"callback_aliases_promoted", result.callback_aliases_promoted},
                {"alias_reloads_eliminated", result.alias_reloads_eliminated},
                {"producer_aliases_coalesced", result.producer_aliases_coalesced},
                {"residual_reasons", result.residual_reasons},
            }},
    };
    std::cout << output.dump() << '\n';
    return 0;
}
