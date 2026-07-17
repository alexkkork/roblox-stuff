#include "luraph/emit.hpp"

#include <iostream>
#include <string>

using alex::deobfuscator::luraph::SemanticCandidate;
using alex::deobfuscator::luraph::emitSemanticCandidate;
using json = nlohmann::json;

namespace
{

json number(int value)
{
    return {{"primitive", true}, {"read_provenance", "raw_table"}, {"type", "number"},
        {"value", std::to_string(value)}};
}

json immediate(const std::string& lane, int value)
{
    return {{"kind", "immediate"}, {"lane", lane}, {"value", number(value)}};
}

json descriptor(int target, int destination, int captureCount)
{
    json captures = json::array();
    for (int index = 0; index < captureCount; ++index)
        captures.push_back({{"capture_index", index}, {"capture_kind", 0}, {"slot", 10 + index}});
    return {{"complete", true}, {"target_prototype", target}, {"destination_register", destination},
        {"captures", std::move(captures)}};
}

json closureInstruction(int pc, const json& closureDescriptor)
{
    return {{"pc", pc}, {"opcode", 22}, {"closure_descriptor", closureDescriptor},
        {"semantic_operation", {{"kind", "protector_internal_sequence"}, {"operations", json::array()}}}};
}

json closureInstructionWithSemanticDestination(int pc, const json& closureDescriptor, int destination)
{
    json instruction = closureInstruction(pc, closureDescriptor);
    instruction["semantic_operation"] = {
        {"kind", "protector_internal_sequence"},
        {"operations", json::array({
            {
                {"kind", "register_write"},
                {"register", immediate("G", destination)},
                {"value", {{"kind", "vm_state"}, {"name", "closure_result"}}},
            },
        })},
    };
    return instruction;
}

json upvalueInstruction(int pc, int encodedKey, const json& runtimeOverride = json(nullptr),
    int emittedKey = -1)
{
    if (emittedKey < 0)
        emittedKey = encodedKey;
    json instruction = {
        {"pc", pc},
        {"opcode", 119},
        {"static_lanes", {{"G", number(encodedKey)}}},
        {"lanes", {{"G", number(emittedKey)}}},
        {"runtime_lane_overrides", json::object()},
        {"semantic_operation", {
            {"kind", "register_write"},
            {"register", immediate("D", 1)},
            {"value", {
                {"kind", "index_read"},
                {"table", {{"kind", "upvalue_file"}}},
                {"index", immediate("G", emittedKey)},
            }},
        }},
    };
    if (!runtimeOverride.is_null())
        instruction["runtime_lane_overrides"]["G"] = runtimeOverride;
    return instruction;
}

json callableUpvalueInstruction(int pc, int encodedKey)
{
    json instruction = upvalueInstruction(pc, encodedKey);
    instruction["semantic_operation"]["runtime_resolution"] = {
        {"kind", "observed_register_value"},
        {"non_speculative", true},
        {"value", {{"type", "function"}, {"callable", true}}},
    };
    return instruction;
}

json observedFunction(const std::string& name)
{
    return {
        {"type", "function"},
        {"value", nullptr},
        {"primitive", false},
        {"callable", true},
        {"name", name},
        {"read_provenance", "raw_table"},
    };
}

json observedGlobalFunction(const std::string& name)
{
    return {
        {"type", "global_reference"},
        {"value", nullptr},
        {"primitive", false},
        {"path", "_G." + name},
        {"read_provenance", "raw_table"},
    };
}

json observedUpvalueInstruction(int pc, int destination, int encodedKey, int observations)
{
    json instruction = upvalueInstruction(pc, encodedKey);
    instruction["semantic_operation"]["register"] = immediate("D", destination);
    instruction["semantic_operation"]["runtime_resolution"] = {
        {"kind", "observed_register_value"},
        {"register", destination},
        {"value", observedFunction("xpcall")},
        {"observation_count", observations},
        {"scope", "executed-payload-site"},
        {"static_value", false},
        {"non_speculative", true},
    };
    return instruction;
}

json captureCellValue(int encodedKey, const std::string& lane)
{
    const json capture = {
        {"kind", "index_read"},
        {"table", {{"kind", "upvalue_file"}}},
        {"index", immediate(lane, encodedKey)},
    };
    return {
        {"kind", "index_read"},
        {"table", {
            {"kind", "index_read"},
            {"table", capture},
            {"index", {{"kind", "constant"}, {"value", 3.0}}},
        }},
        {"index", {
            {"kind", "index_read"},
            {"table", capture},
            {"index", {{"kind", "constant"}, {"value", 2.0}}},
        }},
    };
}

json captureCellInstruction(int pc, int destination, int encodedKey)
{
    return {
        {"pc", pc},
        {"opcode", 119},
        {"static_opcode", 119},
        {"lanes", {{"D", number(destination)}, {"G", number(encodedKey)}}},
        {"static_lanes", {{"D", number(destination)}, {"G", number(encodedKey)}}},
        {"runtime_lane_overrides", json::object()},
        {"semantic_operation", {
            {"kind", "register_write"},
            {"register", immediate("D", destination)},
            {"value", captureCellValue(encodedKey, "G")},
        }},
    };
}

json indexedCaptureCellInstruction(int pc, int destination, int encodedKey)
{
    return {
        {"pc", pc},
        {"opcode", 115},
        {"static_opcode", 115},
        {"lanes", {{"D", number(0)}, {"G", number(destination)}, {"p", number(encodedKey)}}},
        {"static_lanes", {{"D", number(0)}, {"G", number(destination)}, {"p", number(encodedKey)}}},
        {"runtime_lane_overrides", json::object()},
        {"semantic_operation", {
            {"kind", "register_write"},
            {"register", immediate("G", destination)},
            {"value", {
                {"kind", "index_read"},
                {"table", captureCellValue(encodedKey, "p")},
                {"index", {{"kind", "register_read"}, {"index", immediate("D", 0)}}},
            }},
        }},
    };
}

json mutatedProtectorInstruction(int pc, int baseRegister)
{
    return {
        {"pc", pc},
        {"opcode", 204},
        {"static_opcode", 204},
        {"runtime_opcode_observed", false},
        {"lanes", {{"G", number(baseRegister)}}},
        {"static_lanes", {{"G", number(baseRegister)}}},
        {"runtime_lane_overrides", json::object()},
        {"semantic_operation", {
            {"kind", "protector_internal_sequence"},
            {"operations", json::array({{
                {"kind", "assign"},
                {"targets", json::array({{{"kind", "vm_state"}, {"name", "M"}}})},
                {"values", json::array({immediate("D", 0)})},
            }})},
            {"protector_state", true},
            {"source_semantic", false},
        }},
    };
}

json normalizedCallHandler(int opcode, const std::string& baseLane,
    const std::string& secondArgumentLane = "")
{
    const std::string secondLane = secondArgumentLane.empty() ? baseLane : secondArgumentLane;
    const auto registerAt = [](const std::string& lane, int offset) {
        return json{
            {"kind", "register_read"},
            {"index", {
                {"kind", "binary"},
                {"left", {{"kind", "operand"}, {"lane", lane}}},
                {"operator", "+"},
                {"right", {{"kind", "constant"}, {"value", static_cast<double>(offset)}}},
            }},
        };
    };
    return {
        {"opcode", opcode},
        {"normalization_complete", true},
        {"vm_state_independent", true},
        {"effects", {
            {"calls", 1},
            {"register_calls", 1},
            {"operation_candidates", json::array({"call"})},
        }},
        {"semantic_operation", {
            {"kind", "operation_sequence"},
            {"operations", json::array({{
                {"kind", "expression"},
                {"value", {
                    {"kind", "call"},
                    {"method", false},
                    {"function", {
                        {"kind", "register_read"},
                        {"index", {{"kind", "operand"}, {"lane", baseLane}}},
                    }},
                    {"arguments", json::array({registerAt(baseLane, 1), registerAt(secondLane, 2)})},
                }},
            }})},
        }},
    };
}

json registerAliasInstruction(int pc, int destination, int source)
{
    return {
        {"pc", pc},
        {"opcode", 1},
        {"semantic_operation", {
            {"kind", "register_write"},
            {"register", immediate("D", destination)},
            {"value", {{"kind", "register_read"}, {"index", immediate("B", source)}}},
        }},
    };
}

json callInstruction(int pc, int functionRegister)
{
    return {
        {"pc", pc},
        {"opcode", 142},
        {"semantic_operation", {
            {"kind", "expression"},
            {"value", {
                {"kind", "call"},
                {"function", {{"kind", "register_read"}, {"index", immediate("D", functionRegister)}}},
                {"arguments", json::array()},
            }},
        }},
    };
}

json callArgumentInstruction(int pc, int functionRegister, int firstArgument, int secondArgument)
{
    json instruction = callInstruction(pc, functionRegister);
    instruction["semantic_operation"]["value"]["arguments"] = json::array({
        {{"kind", "register_read"}, {"index", immediate("D", firstArgument)}},
        {{"kind", "register_read"}, {"index", immediate("D", secondArgument)}},
    });
    return instruction;
}

json prototype(int id, json instructions)
{
    return {{"runtime_id", id}, {"entry_pc", 1}, {"instructions", std::move(instructions)}};
}

json cfgPrototype(int id, int lastPc)
{
    json blocks = json::array();
    for (int pc = 1; pc <= lastPc; ++pc)
        blocks.push_back({{"id", "p" + std::to_string(id) + "_b" + std::to_string(pc)},
            {"start_pc", pc}, {"end_pc", pc}, {"reachable", true},
            {"successors", pc < lastPc ? json::array({"p" + std::to_string(id) + "_b" + std::to_string(pc + 1)}) : json::array()},
            {"terminator", pc < lastPc ? "observed_fallthrough" : "return"}});
    return {{"runtime_id", id}, {"entry_pc", 1}, {"blocks", std::move(blocks)}};
}

json sparseCfgPrototype(int id, int entryPc, json blocks)
{
    return {{"runtime_id", id}, {"entry_pc", entryPc}, {"blocks", std::move(blocks)}};
}

json observedCaptureDomain(int prototypeId, bool complete, int captureCount, int xpcallIndex,
    int duplicateXpcallIndex = -1, bool omitXpcall = false)
{
    json indices = json::array();
    json values = json::object();
    for (int index = 0; index < captureCount; ++index)
    {
        indices.push_back(index);
        if (omitXpcall && index == xpcallIndex)
            continue;
        const json resolved = index == xpcallIndex || index == duplicateXpcallIndex
            ? observedGlobalFunction("xpcall") : number(100 + index);
        values[std::to_string(index)] = {
            {"capture_index", index},
            {"resolved_value", resolved},
        };
    }
    return {
        {"prototype", prototypeId},
        {"complete", complete},
        {"indices", std::move(indices)},
        {"values", std::move(values)},
    };
}

json rootDescriptor()
{
    return {{"complete", true}, {"target_prototype", 1}, {"destination_register", 1},
        {"captures", json::array()}};
}

SemanticCandidate emitWithTarget(json targetInstructions, int targetCaptureCount, int targetLastPc = 1,
    json extraPrototypes = json::array(), json extraCfg = json::array(),
    json observedLaneSequences = json::array(), json targetCfg = json(nullptr),
    json observedCaptureDomains = json::array(), json closureDescriptors = json::array(),
    json payloadActivationArguments = json(nullptr), int payloadRoot = 1)
{
    json prototypes = json::array({
        prototype(1, json::array({closureInstruction(1, descriptor(2, 1, targetCaptureCount))})),
        prototype(2, std::move(targetInstructions)),
    });
    for (json& item : extraPrototypes)
        prototypes.push_back(std::move(item));

    json cfgPrototypes = json::array({cfgPrototype(1, 1),
        targetCfg.is_null() ? cfgPrototype(2, targetLastPc) : std::move(targetCfg)});
    for (json& item : extraCfg)
        cfgPrototypes.push_back(std::move(item));

    json ir = {
        {"payload_root", {{"payload_prototype", payloadRoot}, {"closure_descriptor", rootDescriptor()}}},
        {"payload_activation_arguments", std::move(payloadActivationArguments)},
        {"prototype_call_edges", json::array()},
        {"observed_transition_sequences", json::array()},
        {"observed_lane_sequences", std::move(observedLaneSequences)},
        {"observed_capture_domains", std::move(observedCaptureDomains)},
        {"closure_descriptors", std::move(closureDescriptors)},
        {"prototypes", std::move(prototypes)},
    };
    return emitSemanticCandidate(ir, {{"prototypes", std::move(cfgPrototypes)}});
}

struct CallArgumentFixture
{
    json ir;
    json cfg;
};

CallArgumentFixture callArgumentFixture(bool complete, int duplicateXpcallIndex = -1,
    bool includeUnexecutedPrototype = false, int observations = 40)
{
    json prototypes = json::array({
        prototype(1, json::array({registerAliasInstruction(1, 1, 1)})),
        prototype(17, json::array({
            observedUpvalueInstruction(51, 4, 118, observations),
            callArgumentInstruction(63, 9, 8, 4),
        })),
        prototype(6, json::array({registerAliasInstruction(1, 1, 1)})),
    });
    json cfgPrototypes = json::array({
        cfgPrototype(1, 1),
        sparseCfgPrototype(17, 51, json::array({
            {{"id", "p17_b51"}, {"start_pc", 51}, {"end_pc", 51}, {"reachable", true},
                {"successors", json::array({"p17_b63"})}, {"terminator", "observed_fallthrough"}},
            {{"id", "p17_b63"}, {"start_pc", 63}, {"end_pc", 63}, {"reachable", true},
                {"successors", json::array()}, {"terminator", "return"}},
        })),
        cfgPrototype(6, 1),
    });
    json captureDomains = json::array({
        observedCaptureDomain(17, complete, 5, 4, duplicateXpcallIndex),
    });

    if (includeUnexecutedPrototype)
    {
        prototypes.push_back(prototype(19, json::array({upvalueInstruction(65, 6)})));
        cfgPrototypes.push_back(sparseCfgPrototype(19, 65, json::array({
            {{"id", "p19_b65"}, {"start_pc", 65}, {"end_pc", 65}, {"reachable", true},
                {"successors", json::array()}, {"terminator", "return"}},
        })));
        captureDomains.push_back(observedCaptureDomain(19, true, 5, 4));
    }

    return {
        {
            {"payload_root", {{"payload_prototype", 1}, {"closure_descriptor", rootDescriptor()}}},
            {"prototype_call_edges", json::array({{
                {"caller_prototype", 17},
                {"caller_pc", 63},
                {"callee_prototype", 6},
                {"observed_activations", observations},
                {"observed_argument_count_complete", true},
                {"observed_argument_count", 2},
                {"observed_argument_identities", json::array({
                    {{"argument_index", 1}, {"identity", observedFunction("xpcall")},
                        {"observed_activations", observations}},
                    {{"argument_index", 2}, {"identity", observedFunction("xpcall")},
                        {"observed_activations", observations}},
                })},
            }})},
            {"observed_transition_sequences", json::array()},
            {"observed_lane_sequences", json::array()},
            {"observed_capture_domains", std::move(captureDomains)},
            {"closure_descriptors", json::array()},
            {"prototypes", std::move(prototypes)},
        },
        {{"prototypes", std::move(cfgPrototypes)}},
    };
}

CallArgumentFixture mutatedOpcodeCallArgumentFixture()
{
    json edge = {
        {"caller_prototype", 17},
        {"caller_pc", 63},
        {"caller_opcode", 21},
        {"callee_prototype", 6},
        {"observed_activations", 40},
        {"observed_argument_count_complete", true},
        {"observed_argument_count", 2},
        {"observed_argument_identities", json::array({
            {{"argument_index", 1}, {"identity", observedFunction("xpcall")},
                {"observed_activations", 40}},
            {{"argument_index", 2}, {"identity", observedFunction("xpcall")},
                {"observed_activations", 40}},
        })},
        {"observed_caller_handler", normalizedCallHandler(21, "G")},
    };
    json prototypes = json::array({
        prototype(1, json::array({registerAliasInstruction(1, 1, 1)})),
        prototype(17, json::array({
            captureCellInstruction(51, 4, 118),
            mutatedProtectorInstruction(63, 2),
        })),
        prototype(6, json::array({registerAliasInstruction(1, 1, 1)})),
        prototype(19, json::array({indexedCaptureCellInstruction(65, 96, 6)})),
    });
    json cfgPrototypes = json::array({
        cfgPrototype(1, 1),
        sparseCfgPrototype(17, 51, json::array({
            {{"id", "p17_b51"}, {"start_pc", 51}, {"end_pc", 51}, {"reachable", true},
                {"successors", json::array({"p17_b63"})}, {"terminator", "observed_fallthrough"}},
            {{"id", "p17_b63"}, {"start_pc", 63}, {"end_pc", 63}, {"reachable", true},
                {"successors", json::array()}, {"terminator", "return"}},
        })),
        cfgPrototype(6, 1),
        sparseCfgPrototype(19, 65, json::array({
            {{"id", "p19_b65"}, {"start_pc", 65}, {"end_pc", 65}, {"reachable", true},
                {"successors", json::array()}, {"terminator", "return"}},
        })),
    });
    return {
        {
            {"payload_root", {{"payload_prototype", 1}, {"closure_descriptor", rootDescriptor()}}},
            {"prototype_call_edges", json::array({std::move(edge)})},
            {"observed_transition_sequences", json::array()},
            {"observed_lane_sequences", json::array()},
            {"observed_capture_domains", json::array({
                observedCaptureDomain(17, true, 6, 4),
                observedCaptureDomain(19, true, 6, 4),
            })},
            {"closure_descriptors", json::array()},
            {"prototypes", std::move(prototypes)},
        },
        {{"prototypes", std::move(cfgPrototypes)}},
    };
}

const json* captureResolution(const SemanticCandidate& candidate, uint64_t prototypeId, int encodedKey)
{
    for (const json& resolution : candidate.capture_key_resolutions)
        if (resolution.value("prototype", uint64_t(0)) == prototypeId &&
            resolution.value("encoded", int64_t(-1)) == encodedKey)
            return &resolution;
    return nullptr;
}

bool require(bool condition, const std::string& message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << '\n';
    return condition;
}

bool testRuntimeLaneRemap()
{
    const SemanticCandidate candidate = emitWithTarget(
        json::array({upvalueInstruction(1, 188, number(0))}), 2);
    bool ok = true;
    ok &= require(candidate.source.find("captured_values[0]") != std::string::npos,
        "runtime lane evidence did not produce the dense capture key");
    ok &= require(candidate.source.find("captured_values[188]") == std::string::npos,
        "encoded capture key leaked into emitted source");
    ok &= require(candidate.capture_key_remaps == 1, "runtime lane remap was not counted once");
    ok &= require(candidate.capture_key_resolutions.size() == 1 &&
            candidate.capture_key_resolutions[0].value("prototype", 0) == 2 &&
            candidate.capture_key_resolutions[0].value("pc", 0) == 1 &&
            candidate.capture_key_resolutions[0].value("encoded", 0) == 188 &&
            candidate.capture_key_resolutions[0].value("resolved", -1) == 0 &&
            candidate.capture_key_resolutions[0].value("complete", false),
        "runtime lane remap evidence was not exported");
    ok &= require(candidate.unresolved_capture_keys == 0, "proven runtime lane remap was marked unresolved");
    return ok;
}

bool testAlreadySpecializedRuntimeLaneRemap()
{
    const SemanticCandidate candidate = emitWithTarget(
        json::array({upvalueInstruction(1, 188, number(0), 0)}), 2);
    return require(candidate.source.find("captured_values[0]") != std::string::npos,
               "already-specialized semantic IR lost its runtime lane provenance") &&
        require(candidate.capture_key_remaps == 1, "static-to-runtime provenance was not counted after specialization") &&
        require(candidate.unresolved_capture_keys == 0, "already-specialized runtime key was marked unresolved");
}

bool testInheritedCaptureReusesProvenance()
{
    json childDescriptor = descriptor(3, 2, 1);
    childDescriptor["captures"][0] = {
        {"capture_index", 0}, {"capture_kind", 2}, {"slot", 188},
    };
    json targetInstructions = json::array({
        upvalueInstruction(1, 188, number(0)),
        closureInstruction(2, childDescriptor),
    });
    const SemanticCandidate candidate = emitWithTarget(std::move(targetInstructions), 2, 2,
        json::array({prototype(3, json::array({upvalueInstruction(1, 0)}))}),
        json::array({cfgPrototype(3, 1)}));
    bool ok = true;
    ok &= require(candidate.source.find("[0] = captured_values[0],") != std::string::npos,
        "inherited capture did not reuse the proven key mapping");
    ok &= require(candidate.source.find("captured_values[188]") == std::string::npos,
        "inherited capture retained the encoded key");
    ok &= require(candidate.capture_key_remaps == 2, "read and inherited-capture remaps were not tracked separately");
    return ok;
}

bool testSingleCaptureInference()
{
    const SemanticCandidate candidate = emitWithTarget(json::array({upvalueInstruction(1, 77)}), 1);
    return require(candidate.source.find("captured_values[0]") != std::string::npos,
               "single complete capture domain was not remapped") &&
        require(candidate.capture_key_remaps == 1, "single-capture remap was not counted") &&
        require(candidate.unresolved_capture_keys == 0, "single-capture remap was marked unresolved");
}

bool testCallTargetProvenanceRemapsDenseCapture()
{
    json targetDescriptor = descriptor(2, 65, 2);
    targetDescriptor["captures"][0]["slot"] = 49;
    targetDescriptor["captures"][1]["slot"] = 64;

    json ir = {
        {"payload_root", {{"payload_prototype", 1}, {"closure_descriptor", rootDescriptor()}}},
        {"prototype_call_edges", json::array({
            {{"caller_prototype", 2}, {"caller_pc", 3}, {"callee_prototype", 5}},
        })},
        {"observed_transition_sequences", json::array()},
        {"prototypes", json::array({
            prototype(1, json::array({
                closureInstructionWithSemanticDestination(1, descriptor(5, 25, 0), 49),
                closureInstructionWithSemanticDestination(2, descriptor(23, 22, 0), 64),
                closureInstructionWithSemanticDestination(3, targetDescriptor, 65),
            })),
            prototype(2, json::array({
                upvalueInstruction(1, 188),
                registerAliasInstruction(2, 7, 1),
                callInstruction(3, 7),
            })),
            prototype(5, json::array({registerAliasInstruction(1, 1, 1)})),
            prototype(23, json::array({registerAliasInstruction(1, 1, 1)})),
        })},
    };
    json cfg = {{"prototypes", json::array({
        cfgPrototype(1, 3),
        cfgPrototype(2, 3),
        cfgPrototype(5, 1),
        cfgPrototype(23, 1),
    })}};

    const SemanticCandidate candidate = emitSemanticCandidate(ir, cfg);
    return require(candidate.source.find("captured_values[0]") != std::string::npos,
               "call-target provenance did not map the encoded key to capture zero") &&
        require(candidate.source.find("unresolved_capture_cell(2, 1, 188)") == std::string::npos,
            "call-target provenance left the mapped capture unresolved") &&
        require(candidate.capture_key_remaps == 1, "call-target capture remap was not counted") &&
        require(candidate.capture_key_resolutions.size() == 1 &&
                candidate.capture_key_resolutions[0].value("evidence", "") == "capture_provenance",
            "call-target capture provenance was not exported") &&
        require(candidate.unresolved_capture_keys == 0, "call-target capture remap was marked unresolved");
}

bool testUniqueCallableProvenanceRemapsWithoutRegisterFlow()
{
    json targetDescriptor = descriptor(2, 65, 2);
    targetDescriptor["captures"][0]["slot"] = 49;
    targetDescriptor["captures"][1]["slot"] = 64;
    json ir = {
        {"payload_root", {{"payload_prototype", 1}, {"closure_descriptor", rootDescriptor()}}},
        {"prototype_call_edges", json::array({
            {{"caller_prototype", 2}, {"caller_pc", 2}, {"callee_prototype", 5}},
        })},
        {"observed_transition_sequences", json::array()},
        {"prototypes", json::array({
            prototype(1, json::array({
                closureInstructionWithSemanticDestination(1, descriptor(5, 25, 0), 49),
                closureInstructionWithSemanticDestination(2, descriptor(23, 22, 0), 64),
                closureInstructionWithSemanticDestination(3, targetDescriptor, 65),
            })),
            prototype(2, json::array({
                callableUpvalueInstruction(1, 188),
                callInstruction(2, 7),
            })),
            prototype(5, json::array({registerAliasInstruction(1, 1, 1)})),
            prototype(23, json::array({registerAliasInstruction(1, 1, 1)})),
        })},
    };
    json cfg = {{"prototypes", json::array({
        cfgPrototype(1, 3), cfgPrototype(2, 2), cfgPrototype(5, 1), cfgPrototype(23, 1),
    })}};

    const SemanticCandidate candidate = emitSemanticCandidate(ir, cfg);
    return require(candidate.source.find("captured_values[0]") != std::string::npos,
               "unique callable provenance did not map the dense capture") &&
        require(candidate.source.find("unresolved_capture_cell(2, 1, 188)") == std::string::npos,
            "unique callable provenance remained unresolved") &&
        require(candidate.capture_key_remaps == 1, "unique callable remap was not counted") &&
        require(candidate.unresolved_capture_keys == 0, "unique callable remap was marked unresolved");
}

bool testAmbiguousCallableProvenanceStaysUnresolved()
{
    json targetDescriptor = descriptor(2, 65, 2);
    targetDescriptor["captures"][0]["slot"] = 49;
    targetDescriptor["captures"][1]["slot"] = 64;
    json ir = {
        {"payload_root", {{"payload_prototype", 1}, {"closure_descriptor", rootDescriptor()}}},
        {"prototype_call_edges", json::array({
            {{"caller_prototype", 2}, {"caller_pc", 2}, {"callee_prototype", 5}},
            {{"caller_prototype", 2}, {"caller_pc", 3}, {"callee_prototype", 23}},
        })},
        {"observed_transition_sequences", json::array()},
        {"prototypes", json::array({
            prototype(1, json::array({
                closureInstructionWithSemanticDestination(1, descriptor(5, 25, 0), 49),
                closureInstructionWithSemanticDestination(2, descriptor(23, 22, 0), 64),
                closureInstructionWithSemanticDestination(3, targetDescriptor, 65),
            })),
            prototype(2, json::array({
                callableUpvalueInstruction(1, 188),
                callInstruction(2, 7),
                callInstruction(3, 8),
            })),
            prototype(5, json::array({registerAliasInstruction(1, 1, 1)})),
            prototype(23, json::array({registerAliasInstruction(1, 1, 1)})),
        })},
    };
    json cfg = {{"prototypes", json::array({
        cfgPrototype(1, 3), cfgPrototype(2, 3), cfgPrototype(5, 1), cfgPrototype(23, 1),
    })}};

    const SemanticCandidate candidate = emitSemanticCandidate(ir, cfg);
    return require(candidate.source.find("unresolved_capture_cell(2, 1, 188)") != std::string::npos,
               "ambiguous callable provenance guessed a dense capture") &&
        require(candidate.capture_key_remaps == 0, "ambiguous callable provenance counted a remap") &&
        require(candidate.unresolved_capture_keys == 1, "ambiguous callable provenance was not counted unresolved") &&
        require(!candidate.fully_rendered(), "ambiguous callable provenance claimed full rendering");
}

bool testAmbiguousCaptureStaysUnresolved()
{
    const SemanticCandidate candidate = emitWithTarget(json::array({upvalueInstruction(1, 188)}), 2);
    return require(candidate.source.find("unresolved_capture_cell(2, 1, 188)") != std::string::npos,
               "ambiguous capture key was guessed instead of withheld") &&
        require(candidate.capture_key_remaps == 0, "ambiguous capture key was counted as remapped") &&
        require(candidate.unresolved_capture_keys == 1, "ambiguous capture key was not counted once") &&
        require(!candidate.fully_rendered(), "candidate with an unresolved capture key claimed full rendering");
}

bool testCallArgumentIdentityRemapsExactCapture()
{
    CallArgumentFixture fixture = callArgumentFixture(true, -1, true, 40);
    const SemanticCandidate candidate = emitSemanticCandidate(fixture.ir, fixture.cfg);
    const json* resolution = captureResolution(candidate, 17, 118);

    bool ok = true;
    ok &= require(candidate.source.find("registers[4] = captured_values[4]") != std::string::npos,
        "observed argument identity did not resolve prototype 17 capture key 118 to capture four");
    ok &= require(candidate.source.find("unresolved_capture_cell(17, 51, 118)") == std::string::npos,
        "the proven prototype 17 call argument remained unresolved");
    ok &= require(candidate.source.find("unresolved_capture_cell(19, 65, 6)") != std::string::npos,
        "the unexecuted prototype 19 capture was guessed without a proven consumer");
    ok &= require(candidate.capture_key_remaps == 1,
        "the exact call-argument capture remap was not counted once");
    ok &= require(candidate.unresolved_capture_keys == 1,
        "the unexecuted prototype 19 capture was not the sole unresolved key");
    ok &= require(resolution != nullptr, "the call-argument capture resolution was not exported");
    if (resolution)
    {
        ok &= require(resolution->value("pc", 0) == 51 && resolution->value("resolved", -1) == 4 &&
                resolution->value("evidence", "") == "call_argument_identity",
            "the exported capture resolution did not retain its producer site and evidence kind");
        const json details = resolution->value("evidence_details", json::object());
        const json observations = details.value("observations", json::array());
        ok &= require(details.value("kind", "") == "call_argument_identity" && observations.size() == 1 &&
                observations[0].value("caller_pc", 0) == 63 &&
                observations[0].value("argument_index", 0) == 2 &&
                observations[0].value("observed_calls", 0) == 40 &&
                observations[0].value("capture_index", -1) == 4,
            "the structured call-argument evidence was incomplete");
    }
    ok &= require(captureResolution(candidate, 19, 6) == nullptr,
        "an unexecuted capture key received a resolution record");
    return ok;
}

bool testMutatedOpcodeCallArgumentIdentityRemapsCaptureCell()
{
    CallArgumentFixture fixture = mutatedOpcodeCallArgumentFixture();
    const SemanticCandidate candidate = emitSemanticCandidate(fixture.ir, fixture.cfg);
    const json* resolution = captureResolution(candidate, 17, 118);

    bool ok = true;
    ok &= require(resolution != nullptr && resolution->value("pc", 0) == 51 &&
            resolution->value("resolved", -1) == 4 &&
            resolution->value("evidence", "") == "call_argument_identity",
        "the mutated caller opcode did not resolve prototype 17 capture key 118");
    ok &= require(candidate.source.find("unresolved_capture_cell(17, 51, 118)") == std::string::npos,
        "the canonical capture-cell dereference remained unresolved");
    ok &= require(candidate.source.find("unresolved_capture_cell(19, 65, 6)") != std::string::npos &&
            captureResolution(candidate, 19, 6) == nullptr,
        "the unexecuted indexed capture-cell read received call-frame evidence");
    if (resolution)
    {
        const json observations = resolution->value("evidence_details", json::object())
            .value("observations", json::array());
        ok &= require(observations.size() == 1 &&
                observations[0].value("call_frame_source", "") == "observed_caller_handler" &&
                observations[0].value("caller_opcode", 0) == 21 &&
                observations[0].value("observed_argument_count", 0) == 2 &&
                observations[0].value("base_lane", "") == "G" &&
                observations[0].value("base_register", -1) == 2 &&
                observations[0].value("function_register", -1) == 2 &&
                observations[0].value("argument_register", -1) == 4,
            "the mutated-opcode resolution did not export its normalized call frame");
    }

    CallArgumentFixture countMismatch = mutatedOpcodeCallArgumentFixture();
    countMismatch.ir["prototype_call_edges"][0]["observed_argument_count"] = 1;
    const SemanticCandidate rejectedCount = emitSemanticCandidate(countMismatch.ir, countMismatch.cfg);
    ok &= require(captureResolution(rejectedCount, 17, 118) == nullptr,
        "a handler frame with the wrong observed argument count was accepted");

    CallArgumentFixture laneMismatch = mutatedOpcodeCallArgumentFixture();
    laneMismatch.ir["prototype_call_edges"][0]["observed_caller_handler"]
        ["semantic_operation"]["operations"][0]["value"]["arguments"][1]["index"]["left"]["lane"] = "H";
    const SemanticCandidate rejectedLane = emitSemanticCandidate(laneMismatch.ir, laneMismatch.cfg);
    ok &= require(captureResolution(rejectedLane, 17, 118) == nullptr,
        "a handler frame with conflicting base-lane roles was accepted");
    return ok;
}

bool testCallArgumentIdentityRejectsAmbiguousCapture()
{
    CallArgumentFixture fixture = callArgumentFixture(true, 3);
    const SemanticCandidate candidate = emitSemanticCandidate(fixture.ir, fixture.cfg);
    return require(captureResolution(candidate, 17, 118) == nullptr,
               "duplicate xpcall identities guessed one capture") &&
        require(candidate.capture_key_remaps == 0,
            "ambiguous call-argument identity counted a capture remap") &&
        require(candidate.source.find("captured_values[3]") == std::string::npos &&
                candidate.source.find("captured_values[4]") == std::string::npos,
            "ambiguous call-argument identity selected a dense capture");
}

bool testCallArgumentIdentityRejectsIncompleteDomain()
{
    CallArgumentFixture fixture = callArgumentFixture(false);
    const SemanticCandidate candidate = emitSemanticCandidate(fixture.ir, fixture.cfg);
    return require(captureResolution(candidate, 17, 118) == nullptr,
               "an incomplete capture domain produced a call-argument resolution") &&
        require(candidate.capture_key_remaps == 0,
            "an incomplete capture domain counted a call-argument remap") &&
        require(candidate.source.find("captured_values[4]") == std::string::npos,
            "an incomplete capture domain selected capture four");
}

bool testCallArgumentIdentityPropagatesInheritedCell()
{
    CallArgumentFixture fixture = callArgumentFixture(true, -1, false, 1);
    fixture.ir["observed_capture_domains"] = json::array({
        observedCaptureDomain(16, true, 1, 0),
        observedCaptureDomain(17, true, 5, 4, -1, true),
    });
    json inheritedDescriptor = descriptor(17, 5, 5);
    inheritedDescriptor["captures"][4] = {
        {"capture_index", 4},
        {"capture_kind", 2},
        {"slot", 0},
    };
    fixture.ir["prototypes"].push_back(prototype(16, json::array({
        closureInstruction(1, inheritedDescriptor),
    })));
    fixture.cfg["prototypes"].push_back(cfgPrototype(16, 1));

    const SemanticCandidate candidate = emitSemanticCandidate(fixture.ir, fixture.cfg);
    const json* resolution = captureResolution(candidate, 17, 118);
    return require(candidate.source.find("[4] = captured_values[0],") != std::string::npos,
               "the inherited descriptor did not retain its parent capture cell") &&
        require(candidate.source.find("registers[4] = captured_values[4]") != std::string::npos,
            "the inherited capture identity did not resolve the child call argument") &&
        require(resolution != nullptr && resolution->value("resolved", -1) == 4 &&
                resolution->value("evidence", "") == "call_argument_identity",
            "the inherited-cell remap lost its call-argument evidence") &&
        require(candidate.unresolved_capture_keys == 0,
            "the inherited capture cell was still counted unresolved");
}

bool testNullTargetDescriptorStaysUnresolved()
{
    json incomplete = {{"complete", false}, {"target_prototype", nullptr}, {"destination_register", 2},
        {"captures", json::array()}};
    const SemanticCandidate candidate = emitWithTarget(json::array({closureInstruction(1, incomplete)}), 1);
    return require(!candidate.source.empty(), "null target descriptor aborted semantic emission") &&
        require(candidate.unresolved_closure_descriptors == 1,
            "null target descriptor was not retained as an unresolved descriptor");
}

bool testNilPreservingResultPackHelper()
{
    const SemanticCandidate candidate = emitWithTarget(json::array({upvalueInstruction(1, 0, number(0))}), 2);
    return require(candidate.source.find(
               "helper_values[53] = function(...) return select_value(\"#\", ...), {...} end") != std::string::npos,
        "result-pack helper does not preserve explicit arity and nil holes");
}

bool testClosureConstructionEmitsDirectCallback()
{
    json childDescriptor = descriptor(3, 7, 0);
    childDescriptor["captures"] = json::array({
        {{"capture_index", 0}, {"capture_kind", 0}, {"slot", 4}},
        {{"capture_index", 1}, {"capture_kind", 1}, {"slot", 5}},
        {{"capture_index", 2}, {"capture_kind", 2}, {"slot", 0}},
    });
    const SemanticCandidate candidate = emitWithTarget(
        json::array({closureInstruction(1, childDescriptor)}), 1, 1,
        json::array({prototype(3, json::array({upvalueInstruction(1, 2)}))}),
        json::array({cfgPrototype(3, 1)}));

    const std::string expected =
        "local callback_captures = {\n"
        "            [0] = capture_register_cell(open_cells, registers, 4),\n"
        "            [1] = registers[5],\n"
        "            [2] = captured_values[0],\n"
        "          }\n"
        "          registers[7] = function(...)\n"
        "            return recovered_routine_3(callback_captures, ...)\n"
        "          end";
    bool ok = true;
    ok &= require(candidate.source.find(expected) != std::string::npos,
        "complete closure descriptor was not reconstructed as a direct callback with declarative captures");
    ok &= require(candidate.source.find("make_recovered_closure") == std::string::npos,
        "generic recovered-closure factory remained in emitted source");
    ok &= require(candidate.source.find("closure_captures") == std::string::npos,
        "stepwise VM capture-table assignments remained in emitted source");
    ok &= require(candidate.closure_constructors == 2,
        "direct callback reconstruction changed the counted closure constructors");
    return ok;
}

bool testActivationScopedTransitionReplay()
{
    const json returnInstruction = {
        {"opcode", 31},
        {"semantic_operation", {{"kind", "return"}, {"values", json::array()}}},
    };
    json returnAt2 = returnInstruction;
    returnAt2["pc"] = 2;
    json returnAt3 = returnInstruction;
    returnAt3["pc"] = 3;
    json instructions = json::array({
        {{"pc", 1}, {"opcode", 2}, {"semantic_operation", {
            {"kind", "register_write"}, {"register", immediate("D", 1)},
            {"value", immediate("G", 2)},
        }}},
        std::move(returnAt2),
        std::move(returnAt3),
    });
    json ir = {
        {"payload_root", {{"payload_prototype", 2}, {"closure_descriptor", rootDescriptor()}}},
        {"prototype_call_edges", json::array()},
        {"observed_transition_sequences", json::array({{
            {"prototype", 2}, {"pc", 1}, {"next_pcs", json::array({2, 3, 3, 3})},
            {"activation_sequences", json::array({
                {{"activation", 10}, {"next_pcs", json::array({2})}},
                {{"activation", 20}, {"next_pcs", json::array({3})}},
                {{"activation", 30}, {"next_pcs", json::array({3})}},
                {{"activation", 40}, {"next_pcs", json::array({3})}},
            })},
            {"repeat_from_sequence", 2},
        }})},
        {"prototypes", json::array({prototype(2, std::move(instructions))})},
    };
    json cfg = {{"prototypes", json::array({{
        {"runtime_id", 2}, {"entry_pc", 1}, {"blocks", json::array({
            {{"id", "p2_b1"}, {"start_pc", 1}, {"end_pc", 1}, {"reachable", true},
                {"successors", json::array({"p2_b2", "p2_b3"})}, {"terminator", "observed_branch"}},
            {{"id", "p2_b2"}, {"start_pc", 2}, {"end_pc", 2}, {"reachable", true},
                {"successors", json::array()}, {"terminator", "return"}},
            {{"id", "p2_b3"}, {"start_pc", 3}, {"end_pc", 3}, {"reachable", true},
                {"successors", json::array()}, {"terminator", "return"}},
        })},
    }})}};

    const SemanticCandidate candidate = emitSemanticCandidate(ir, cfg);
    return require(candidate.source.find("local replay_positions = {}") != std::string::npos,
               "prototype invocation did not receive a private replay cursor") &&
        require(candidate.source.find(
            "replay_activation_transition(replay_positions, 2, 1, {{2}, {3}, {3}, {3}}, 2)") != std::string::npos,
            "activation-grouped transition evidence was not emitted") &&
        require(candidate.activation_scoped_transition_sites == 1,
            "activation-scoped transition site was not counted") &&
        require(candidate.stable_mutation_epoch_sites == 1,
            "stable mutation epoch was not counted");
}

bool testObservedReturnArityValidation()
{
    json instruction = {
        {"pc", 1},
        {"opcode", 31},
        {"observed_returns", json::array({{
            {"arity", 2}, {"captured", 2}, {"complete", true},
            {"values", json::array({number(7), {{"type", "nil"}, {"value", nullptr}}})},
        }})},
        {"semantic_operation", {
            {"kind", "return"},
            {"values", json::array({immediate("D", 7), {{"kind", "nil"}}})},
        }},
    };
    const SemanticCandidate verified = emitWithTarget(json::array({instruction}), 0);
    bool ok = true;
    ok &= require(verified.observed_return_events == 1, "observed return event was not counted");
    ok &= require(verified.verified_return_sites == 1, "matching return arity was not verified");
    ok &= require(verified.return_arity_mismatches == 0, "matching return arity was marked mismatched");

    instruction["observed_returns"][0]["arity"] = 3;
    const SemanticCandidate mismatched = emitWithTarget(json::array({std::move(instruction)}), 0);
    ok &= require(mismatched.return_arity_mismatches == 1, "observed return mismatch was not counted");
    ok &= require(!mismatched.fully_rendered(), "return arity mismatch claimed a fully rendered candidate");
    return ok;
}

bool testActivationScopedDynamicLaneReplay()
{
    json instruction = {
        {"pc", 1},
        {"opcode", 31},
        {"semantic_operation", {
            {"kind", "return"},
            {"values", json::array({immediate("G", 7)})},
        }},
    };
    json laneSequences = json::array({{
        {"prototype", 2},
        {"pc", 1},
        {"lanes", json::array({"G"})},
        {"activation_sequences", json::array({{
            {"activation", 10},
            {"frames", json::array({{{"G", number(41)}}, {{"G", number(42)}}})},
        }})},
        {"repeat_from_sequence", 0},
    }});

    const SemanticCandidate candidate = emitWithTarget(
        json::array({std::move(instruction)}), 0, 1, json::array(), json::array(), std::move(laneSequences));
    bool ok = true;
    ok &= require(candidate.source.find(
        "local runtime_lanes_1 = replay_runtime_lanes(replay_positions, 2, 1, {{{[\"G\"] = 41}, {[\"G\"] = 42}}}, 0)") !=
            std::string::npos,
        "activation-scoped runtime lane frames were not emitted once at instruction entry");
    ok &= require(candidate.source.find("return runtime_lanes_1[\"G\"]") != std::string::npos,
        "dynamic immediate still used its stale static lane value");
    ok &= require(candidate.dynamic_lane_replay_sites == 1,
        "dynamic lane replay site was not counted");
    ok &= require(candidate.replayed_dynamic_lane_values == 2,
        "dynamic lane replay value count was not exact");
    ok &= require(candidate.specialized_stable_lanes == 0,
        "varying lane was incorrectly counted as stable");
    ok &= require(candidate.specialized_stable_lane_values == 0,
        "varying lane observations were incorrectly counted as specialized");
    return ok;
}

bool testFullyStableLaneSiteIsSpecialized()
{
    json instruction = {
        {"pc", 1},
        {"opcode", 31},
        {"semantic_operation", {
            {"kind", "return"},
            {"values", json::array({immediate("G", 7)})},
        }},
    };
    json laneSequences = json::array({{
        {"prototype", 2},
        {"pc", 1},
        {"lanes", json::array({"G"})},
        {"activation_sequences", json::array({
            {{"activation", 10}, {"frames", json::array({{{"G", number(41)}}, {{"G", number(41)}}})}},
            {{"activation", 20}, {"frames", json::array({{{"G", number(41)}}})}},
        })},
        {"repeat_from_sequence", 0},
    }});

    const SemanticCandidate candidate = emitWithTarget(
        json::array({std::move(instruction)}), 0, 1, json::array(), json::array(), std::move(laneSequences));
    bool ok = true;
    ok &= require(candidate.source.find("return 41") != std::string::npos,
        "stable lane was not substituted as a literal");
    ok &= require(candidate.source.find("replay_runtime_lanes(replay_positions, 2, 1") == std::string::npos,
        "fully stable lane site still emitted a replay call");
    ok &= require(candidate.source.find("[\"G\"] = 41") == std::string::npos,
        "fully stable lane values were still serialized");
    ok &= require(candidate.dynamic_lane_replay_sites == 0,
        "fully stable lane site was counted as dynamic replay");
    ok &= require(candidate.replayed_dynamic_lane_values == 0,
        "fully stable lane values were counted as replayed");
    ok &= require(candidate.specialized_stable_lanes == 1,
        "stable lane specialization count was not exact");
    ok &= require(candidate.specialized_stable_lane_values == 3,
        "stable lane observation count was not exact");
    return ok;
}

bool testMixedStableAndDynamicLaneSite()
{
    json instruction = {
        {"pc", 1},
        {"opcode", 31},
        {"semantic_operation", {
            {"kind", "return"},
            {"values", json::array({immediate("G", 7), immediate("H", 8)})},
        }},
    };
    json laneSequences = json::array({{
        {"prototype", 2},
        {"pc", 1},
        {"lanes", json::array({"G", "H"})},
        {"activation_sequences", json::array({
            {{"activation", 10}, {"frames", json::array({
                {{"G", number(41)}, {"H", number(7)}},
                {{"G", number(41)}, {"H", number(8)}},
            })}},
            {{"activation", 20}, {"frames", json::array({
                {{"G", number(41)}, {"H", number(9)}},
            })}},
        })},
        {"repeat_from_sequence", 0},
    }});

    const SemanticCandidate candidate = emitWithTarget(
        json::array({std::move(instruction)}), 0, 1, json::array(), json::array(), std::move(laneSequences));
    bool ok = true;
    ok &= require(candidate.source.find(
        "replay_runtime_lanes(replay_positions, 2, 1, {{{[\"H\"] = 7}, {[\"H\"] = 8}}, {{[\"H\"] = 9}}}, 0)") !=
            std::string::npos,
        "mixed lane site did not serialize only the varying lane");
    ok &= require(candidate.source.find("[\"G\"] = 41") == std::string::npos,
        "mixed lane site still serialized its stable lane");
    ok &= require(candidate.source.find("return 41, runtime_lanes_1[\"H\"]") != std::string::npos,
        "mixed lane site did not combine the stable literal with dynamic replay");
    ok &= require(candidate.dynamic_lane_replay_sites == 1,
        "mixed lane site did not retain its dynamic replay metric");
    ok &= require(candidate.replayed_dynamic_lane_values == 3,
        "mixed lane site counted stable values as replayed");
    ok &= require(candidate.specialized_stable_lanes == 1,
        "mixed lane site stable-lane count was not exact");
    ok &= require(candidate.specialized_stable_lane_values == 3,
        "mixed lane site stable-value count was not exact");
    return ok;
}

bool testGenericIteratorPreparationUsesRecoveredCoroutineProtocol()
{
    json instruction = {
        {"pc", 1},
        {"opcode", 103},
        {"semantic_operation", {
            {"kind", "generic_for_prepare"},
            {"base_register", immediate("D", 9)},
            {"loop_target", immediate("G", 2)},
            {"protocol", "coroutine_wrapped_generic_iterator"},
        }},
    };
    json blocks = json::array({
        {{"id", "p2_b1"}, {"start_pc", 1}, {"end_pc", 1}, {"reachable", true},
            {"successors", json::array({"p2_b2", "p2_b3"})}, {"terminator", "generic_for_prepare"}},
        {{"id", "p2_b2"}, {"start_pc", 2}, {"end_pc", 2}, {"reachable", true},
            {"successors", json::array()}, {"terminator", "return"}},
        {{"id", "p2_b3"}, {"start_pc", 3}, {"end_pc", 3}, {"reachable", true},
            {"successors", json::array()}, {"terminator", "return"}},
    });
    const SemanticCandidate candidate = emitWithTarget(json::array({std::move(instruction)}), 0, 3,
        json::array(), json::array(), json::array(),
        {{"runtime_id", 2}, {"entry_pc", 1}, {"blocks", std::move(blocks)}});

    bool ok = true;
    ok &= require(candidate.source.find("local function prepare_generic_iterator(registers, state, base_register)") !=
            std::string::npos,
        "generic iterator helper did not retain the recovered coroutine protocol");
    ok &= require(candidate.source.find("coroutine.yield(true, key, value)") != std::string::npos,
        "generic iterator helper did not preserve yielded iterator values");
    ok &= require(candidate.source.find("prepare_generic_iterator(registers, state, 9)") != std::string::npos,
        "generic iterator setup did not bind the recovered base register");
    ok &= require(candidate.source.find("pc = (2) + 1") != std::string::npos,
        "generic iterator setup did not jump to the recovered loop target");
    ok &= require(candidate.source.find("Multiple destinations were observed") == std::string::npos,
        "generic iterator setup was still emitted as an unresolved dynamic edge");
    ok &= require(candidate.symbolic_transitions == 0,
        "generic iterator setup incorrectly counted a symbolic transition");
    return ok;
}

bool testObservedCaptureDomainResolvesDescriptorlessPrototype()
{
    json observedDomains = json::array({{
        {"prototype", 30},
        {"complete", true},
        {"indices", json::array({0, 1, 2})},
    }});
    const SemanticCandidate candidate = emitWithTarget(
        json::array({upvalueInstruction(1, 0)}), 1, 1,
        json::array({prototype(30, json::array({upvalueInstruction(1, 2)}))}),
        json::array({cfgPrototype(30, 1)}), json::array(), json(nullptr), std::move(observedDomains));

    bool ok = true;
    ok &= require(candidate.source.find("unresolved_capture_cell(30, 1, 2)") == std::string::npos,
        "observed complete capture domain did not resolve a descriptorless prototype");
    ok &= require(candidate.source.find("captured_values[2]") != std::string::npos,
        "observed capture index was not emitted directly");
    ok &= require(candidate.unresolved_capture_keys == 0,
        "observed complete capture domain was still counted unresolved");
    return ok;
}

bool testDescriptorSideTableSurvivesUnreachableConstructor()
{
    json sideDescriptor = descriptor(30, 99, 3);
    sideDescriptor["prototype"] = 2;
    sideDescriptor["pc"] = 500;
    const SemanticCandidate candidate = emitWithTarget(
        json::array({upvalueInstruction(1, 0)}), 1, 1,
        json::array({prototype(30, json::array({upvalueInstruction(1, 2)}))}),
        json::array({cfgPrototype(30, 1)}), json::array(), json(nullptr), json::array(),
        json::array({std::move(sideDescriptor)}));

    bool ok = true;
    ok &= require(candidate.source.find("unresolved_capture_cell(30, 1, 2)") == std::string::npos,
        "side-table descriptor did not provide the capture domain");
    ok &= require(candidate.source.find("captured_values[2]") != std::string::npos,
        "side-table capture index was not emitted directly");
    ok &= require(candidate.unresolved_capture_keys == 0,
        "side-table descriptor was still counted unresolved");
    return ok;
}

bool testTraceBackedRootArgumentsAreSpecializedWithoutGuessing()
{
    const json rootRead = {
        {"kind", "index_read"},
        {"table", {{"kind", "register_read"}, {"index", immediate("D", 1)}}},
        {"index", immediate("G", 22)},
    };
    const json unknownRead = {
        {"kind", "index_read"},
        {"table", {{"kind", "register_read"}, {"index", immediate("D", 1)}}},
        {"index", immediate("G", 3)},
    };
    json arguments = {
        {"argument_count", 1},
        {"argument_table_entries", json::array({{
            {"argument_index", 1},
            {"key", number(22)},
            {"value", {
                {"type", "global_reference"},
                {"primitive", false},
                {"path", "task"},
                {"path_hex", "7461736b"},
            }},
        }})},
    };
    const SemanticCandidate candidate = emitWithTarget(
        json::array({
            {{"pc", 1}, {"opcode", 1}, {"semantic_operation", {
                {"kind", "register_write"}, {"register", immediate("D", 4)}, {"value", rootRead}}}},
            {{"pc", 2}, {"opcode", 1}, {"semantic_operation", {
                {"kind", "register_write"}, {"register", immediate("D", 5)}, {"value", unknownRead}}}},
        }),
        1, 2, json::array(), json::array(), json::array(), json(nullptr), json::array(), json::array(),
        std::move(arguments), 2);

    bool ok = true;
    ok &= require(candidate.source.find("registers[4] = environment[\"task\"]") != std::string::npos,
        "trace-backed root argument was not specialized");
    ok &= require(candidate.source.find("registers[5] = (registers[1])[3]") != std::string::npos,
        "an unsupported root argument was guessed instead of retained symbolically");
    ok &= require(candidate.root_argument_references_specialized == 1,
        "root argument specialization metric did not count the proven read");
    ok &= require(candidate.source.find("local root_arguments = select_value(1, ...)") != std::string::npos,
        "single-argument root call frame was not specialized");
    ok &= require(candidate.source.find("registers[1] = root_arguments") != std::string::npos,
        "specialized root helper table was not installed directly");
    ok &= require(candidate.root_call_frame_specialized,
        "root call frame specialization was not reported");
    return ok;
}

bool testCompleteRootArgumentTableProvesAbsentSlotsAreNil()
{
    const json missingRead = {
        {"kind", "index_read"},
        {"table", {{"kind", "register_read"}, {"index", immediate("D", 1)}}},
        {"index", immediate("G", 3)},
    };
    json arguments = {
        {"argument_count", 1},
        {"argument_table_entries", json::array({{
            {"argument_index", 1},
            {"key", number(22)},
            {"value", {
                {"type", "global_reference"},
                {"primitive", false},
                {"path", "task"},
            }},
        }})},
        {"argument_table_domains", json::array({{
            {"argument_index", 1},
            {"complete", true},
            {"observed_entries", 1},
        }})},
    };
    const SemanticCandidate candidate = emitWithTarget(
        json::array({
            {{"pc", 1}, {"opcode", 1}, {"semantic_operation", {
                {"kind", "register_write"}, {"register", immediate("D", 4)}, {"value", missingRead}}}},
        }),
        1, 1, json::array(), json::array(), json::array(), json(nullptr), json::array(), json::array(),
        std::move(arguments), 2);

    bool ok = true;
    ok &= require(candidate.source.find("registers[4] = nil") != std::string::npos,
        "a key absent from a complete root argument snapshot was not specialized to nil");
    ok &= require(candidate.root_argument_table_complete,
        "complete root argument snapshot was not reported");
    ok &= require(candidate.absent_root_argument_references_specialized == 1,
        "absent root argument specialization metric did not count the proven read");
    return ok;
}

bool testSequenceTerminalReturnSuppressesCfgFallthrough()
{
    const json sequence = {
        {"kind", "operation_sequence"},
        {"operations", json::array({
            {
                {"kind", "register_write"},
                {"register", immediate("D", 1)},
                {"value", {{"kind", "constant"}, {"value", 42.0}}},
            },
            {
                {"kind", "return"},
                {"values", json::array({{{"kind", "register_read"}, {"index", immediate("D", 1)}}})},
            },
        })},
    };
    const SemanticCandidate candidate = emitWithTarget(json::array({
        {{"pc", 1}, {"opcode", 1}, {"semantic_operation", sequence}},
        {{"pc", 2}, {"opcode", 1}, {"semantic_operation", {{"kind", "return"}, {"values", json::array()}}}},
    }), 1, 2);

    return require(candidate.source.find("return registers[1]\n        pc = 2") == std::string::npos,
        "a sequence-wrapped return retained the CFG fallthrough transition");
}

} // namespace

int main()
{
    bool ok = true;
    ok &= testRuntimeLaneRemap();
    ok &= testAlreadySpecializedRuntimeLaneRemap();
    ok &= testInheritedCaptureReusesProvenance();
    ok &= testSingleCaptureInference();
    ok &= testCallTargetProvenanceRemapsDenseCapture();
    ok &= testUniqueCallableProvenanceRemapsWithoutRegisterFlow();
    ok &= testAmbiguousCallableProvenanceStaysUnresolved();
    ok &= testAmbiguousCaptureStaysUnresolved();
    ok &= testCallArgumentIdentityRemapsExactCapture();
    ok &= testMutatedOpcodeCallArgumentIdentityRemapsCaptureCell();
    ok &= testCallArgumentIdentityRejectsAmbiguousCapture();
    ok &= testCallArgumentIdentityRejectsIncompleteDomain();
    ok &= testCallArgumentIdentityPropagatesInheritedCell();
    ok &= testNullTargetDescriptorStaysUnresolved();
    ok &= testNilPreservingResultPackHelper();
    ok &= testClosureConstructionEmitsDirectCallback();
    ok &= testActivationScopedTransitionReplay();
    ok &= testObservedReturnArityValidation();
    ok &= testActivationScopedDynamicLaneReplay();
    ok &= testFullyStableLaneSiteIsSpecialized();
    ok &= testMixedStableAndDynamicLaneSite();
    ok &= testGenericIteratorPreparationUsesRecoveredCoroutineProtocol();
    ok &= testObservedCaptureDomainResolvesDescriptorlessPrototype();
    ok &= testDescriptorSideTableSurvivesUnreachableConstructor();
    ok &= testTraceBackedRootArgumentsAreSpecializedWithoutGuessing();
    ok &= testCompleteRootArgumentTableProvesAbsentSlotsAreNil();
    ok &= testSequenceTerminalReturnSuppressesCfgFallthrough();
    if (ok)
        std::cout << "Luraph semantic emitter capture-key provenance tests passed\n";
    return ok ? 0 : 1;
}
