#pragma once

#include <cstddef>
#include <string>

#include <nlohmann/json.hpp>

namespace alex::deobfuscator::luraph
{

struct SemanticCandidate
{
    std::string source;
    nlohmann::json mapping = nlohmann::json::array();
    size_t prototypes = 0;
    size_t blocks = 0;
    size_t operations = 0;
    size_t unsupported_expressions = 0;
    size_t unsupported_operations = 0;
    size_t symbolic_transitions = 0;
    size_t dynamic_edge_sites = 0;
    size_t replayed_dynamic_edge_sites = 0;
    size_t activation_scoped_transition_sites = 0;
    size_t stable_mutation_epoch_sites = 0;
    size_t steady_state_transition_sites = 0;
    size_t periodic_transition_sites = 0;
    size_t unobserved_branch_arms = 0;
    size_t runtime_specializations = 0;
    size_t direct_prototype_calls = 0;
    size_t fixed_register_calls = 0;
    size_t open_register_calls = 0;
    size_t observed_global_call_arguments = 0;
    size_t inferred_root_slots = 0;
    size_t root_argument_shared_prototypes = 0;
    size_t root_argument_references_specialized = 0;
    size_t absent_root_argument_references_specialized = 0;
    bool root_argument_table_complete = false;
    bool root_call_frame_specialized = false;
    size_t closure_constructors = 0;
    size_t unresolved_closure_descriptors = 0;
    size_t capture_key_remaps = 0;
    nlohmann::json capture_key_resolutions = nlohmann::json::array();
    size_t unresolved_capture_keys = 0;
    size_t observed_return_events = 0;
    size_t verified_return_sites = 0;
    size_t return_arity_mismatches = 0;
    size_t dynamic_lane_replay_sites = 0;
    size_t replayed_dynamic_lane_values = 0;
    size_t specialized_stable_lanes = 0;
    size_t specialized_stable_lane_values = 0;
    size_t path_specific_operations = 0;
    size_t path_specific_register_writes = 0;
    size_t path_specific_table_writes = 0;
    size_t path_specific_control_flow = 0;
    size_t path_specific_calls = 0;
    size_t path_specific_returns = 0;
    size_t path_specific_closures = 0;
    size_t path_specific_argument_loads = 0;
    size_t fixed_argument_loads = 0;
    size_t variadic_argument_captures = 0;
    size_t unsupported_path_specific_operations = 0;
    nlohmann::json path_specific_operation_provenance = nlohmann::json::array();
    nlohmann::json unknown_operations = nlohmann::json::array();

    bool fully_rendered() const
    {
        return unsupported_expressions == 0 && unsupported_operations == 0 && symbolic_transitions == 0 &&
            unresolved_closure_descriptors == 0 && unresolved_capture_keys == 0 && return_arity_mismatches == 0 &&
            unobserved_branch_arms == 0;
    }
};

SemanticCandidate emitSemanticCandidate(const nlohmann::json& reachableIr, const nlohmann::json& cfg);

} // namespace alex::deobfuscator::luraph
