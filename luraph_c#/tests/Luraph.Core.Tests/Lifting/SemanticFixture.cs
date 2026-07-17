using System.Text.Json.Nodes;

namespace Luraph.Core.Tests.Lifting;

internal static class SemanticFixture
{
    public static JsonObject Number(int value) => new()
    {
        ["primitive"] = true,
        ["type"] = "number",
        ["value"] = value.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };

    public static JsonObject Text(string value) => new()
    {
        ["primitive"] = true,
        ["type"] = "string",
        ["value"] = value,
    };

    public static JsonObject Immediate(string lane, int value) => new()
    {
        ["kind"] = "immediate",
        ["lane"] = lane,
        ["value"] = Number(value),
    };

    public static JsonObject Return(params JsonNode[] values) => new()
    {
        ["kind"] = "return",
        ["values"] = new JsonArray(values),
    };

    public static JsonObject Instruction(int pc, JsonObject operation, long opcode = 1) => new()
    {
        ["pc"] = pc,
        ["opcode"] = opcode,
        ["semantic_operation"] = operation,
    };

    public static JsonObject Prototype(ulong id, params JsonObject[] instructions) => new()
    {
        ["runtime_id"] = id,
        ["entry_pc"] = 1,
        ["instructions"] = new JsonArray(instructions),
    };

    public static JsonObject Block(
        ulong prototype,
        int pc,
        string terminator,
        params string[] successors) => new()
        {
            ["id"] = $"p{prototype}_b{pc}",
            ["start_pc"] = pc,
            ["end_pc"] = pc,
            ["reachable"] = true,
            ["successors"] = new JsonArray(successors.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray()),
            ["terminator"] = terminator,
        };

    public static JsonObject CfgPrototype(ulong id, params JsonObject[] blocks) => new()
    {
        ["runtime_id"] = id,
        ["entry_pc"] = 1,
        ["blocks"] = new JsonArray(blocks),
    };

    public static JsonObject Descriptor(ulong target, int destination, params JsonObject[] captures) => new()
    {
        ["complete"] = true,
        ["target_prototype"] = target,
        ["destination_register"] = destination,
        ["captures"] = new JsonArray(captures),
    };

    public static JsonObject Capture(int index, int kind, int slot) => new()
    {
        ["capture_index"] = index,
        ["capture_kind"] = kind,
        ["slot"] = slot,
    };

    public static JsonObject Program(params JsonObject[] prototypes) => new()
    {
        ["payload_root"] = new JsonObject
        {
            ["payload_prototype"] = 1,
            ["closure_descriptor"] = Descriptor(1, 1),
        },
        ["prototype_call_edges"] = new JsonArray(),
        ["observed_transition_sequences"] = new JsonArray(),
        ["observed_lane_sequences"] = new JsonArray(),
        ["observed_capture_domains"] = new JsonArray(),
        ["closure_descriptors"] = new JsonArray(),
        ["prototypes"] = new JsonArray(prototypes),
    };

    public static JsonObject Cfg(params JsonObject[] prototypes) => new()
    {
        ["prototypes"] = new JsonArray(prototypes),
    };
}
