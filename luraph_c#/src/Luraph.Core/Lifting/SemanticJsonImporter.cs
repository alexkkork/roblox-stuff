using System.Globalization;
using System.Text.Json;
using Luraph.Core.Ir;

namespace Luraph.Core.Lifting;

public sealed record ImportedArtifacts(SemanticProgram Program, ControlFlowGraph ControlFlow);

public sealed class SemanticJsonImporter
{
    private const int MaxDepth = 64;
    private readonly List<UnresolvedFact> unresolved = [];

    public ImportedArtifacts Import(string semanticIrJson, string cfgJson)
    {
        using JsonDocument ir = JsonDocument.Parse(semanticIrJson);
        using JsonDocument cfg = JsonDocument.Parse(cfgJson);
        return Import(ir.RootElement, cfg.RootElement);
    }

    public ImportedArtifacts Import(JsonElement semanticIr, JsonElement cfg)
    {
        unresolved.Clear();

        Dictionary<ulong, HashSet<int>> captureDomains = ReadCaptureDomains(semanticIr);
        MergeDescriptorDomains(semanticIr, captureDomains);
        Dictionary<(ulong Prototype, int Pc), Dictionary<int, int>> captureResolutions =
            ReadCaptureResolutions(semanticIr, captureDomains);

        List<LaneReplaySite> laneReplays = ReadLaneReplays(semanticIr);
        List<TransitionReplaySite> transitionReplays = ReadTransitionReplays(semanticIr);
        List<PrototypeCallEdge> callEdges = ReadCallEdges(semanticIr);
        List<SemanticPrototype> prototypes = ReadPrototypes(semanticIr, captureDomains, captureResolutions);
        PayloadRoot? root = ReadRoot(semanticIr);
        ControlFlowGraph graph = ReadCfg(cfg);

        SemanticProgram program = new(
            root,
            prototypes,
            callEdges,
            laneReplays,
            transitionReplays,
            [.. unresolved]);

        return new ImportedArtifacts(program, graph);
    }

    private List<SemanticPrototype> ReadPrototypes(
        JsonElement root,
        IReadOnlyDictionary<ulong, HashSet<int>> captureDomains,
        IReadOnlyDictionary<(ulong Prototype, int Pc), Dictionary<int, int>> captureResolutions)
    {
        List<SemanticPrototype> prototypes = [];
        if (!TryArray(root, "prototypes", out JsonElement rows))
        {
            AddIssue(0, 0, "import", "missing_prototypes", "semantic IR has no prototype array");
            return prototypes;
        }

        foreach (JsonElement row in rows.EnumerateArray())
        {
            ulong id = ReadUInt64(row, "runtime_id");
            if (id == 0)
            {
                AddIssue(0, 0, "import", "invalid_prototype", "prototype id must be positive");
                continue;
            }

            int entryPc = ReadInt32(row, "entry_pc", 1);
            List<SemanticInstruction> instructions = [];
            if (TryArray(row, "instructions", out JsonElement instructionRows))
            {
                foreach (JsonElement instruction in instructionRows.EnumerateArray())
                {
                    int pc = ReadInt32(instruction, "pc");
                    if (pc <= 0)
                    {
                        AddIssue(id, pc, "import", "invalid_pc", "instruction pc must be positive");
                        continue;
                    }

                    instructions.Add(ReadInstruction(id, pc, instruction, captureDomains, captureResolutions));
                }
            }

            IReadOnlySet<int> domain = captureDomains.TryGetValue(id, out HashSet<int>? indices)
                ? new HashSet<int>(indices)
                : new HashSet<int>();
            prototypes.Add(new SemanticPrototype(id, entryPc, instructions, domain));
        }

        return prototypes.OrderBy(item => item.RuntimeId).ToList();
    }

    private SemanticInstruction ReadInstruction(
        ulong prototype,
        int pc,
        JsonElement row,
        IReadOnlyDictionary<ulong, HashSet<int>> captureDomains,
        IReadOnlyDictionary<(ulong Prototype, int Pc), Dictionary<int, int>> captureResolutions)
    {
        Provenance provenance = Provenance.At(prototype, pc);
        long opcode = ReadInt64(row, "opcode", -1);
        Dictionary<string, SemanticExpression> staticLanes = ReadLaneObject(row, "static_lanes", provenance);
        Dictionary<string, SemanticExpression> lanes = ReadLaneObject(row, "lanes", provenance);
        Dictionary<string, SemanticExpression> overrides = ReadLaneObject(row, "runtime_lane_overrides", provenance);
        IReadOnlyDictionary<int, int> resolutions = captureResolutions.GetValueOrDefault((prototype, pc)) ??
            new Dictionary<int, int>();
        ImportContext context = new(prototype, pc, provenance, staticLanes, overrides, captureDomains, resolutions);

        SemanticOperation operation;
        if (row.TryGetProperty("semantic_operation", out JsonElement operationJson) &&
            operationJson.ValueKind == JsonValueKind.Object)
        {
            operation = ReadOperation(operationJson, context, 0);
        }
        else
        {
            operation = new UnresolvedOperation("missing", "instruction has no semantic operation", provenance);
            AddIssue(prototype, pc, "lift", "missing_semantic_operation", "instruction has no semantic operation");
        }

        ClosureDescriptor? closure = row.TryGetProperty("closure_descriptor", out JsonElement descriptor)
            ? ReadClosureDescriptor(descriptor, provenance)
            : null;

        operation = ApplyReturnEvidence(row, operation, context);
        return new SemanticInstruction(pc, opcode, operation, closure, staticLanes, lanes, provenance);
    }

    private SemanticOperation ReadOperation(JsonElement value, ImportContext context, int depth)
    {
        if (depth > MaxDepth || value.ValueKind != JsonValueKind.Object)
            return UnresolvedOperation(context, "invalid", "operation is missing or nested too deeply");

        string kind = ReadString(value, "kind");
        switch (kind)
        {
            case "operation_sequence":
            case "protector_internal_sequence":
            case "block":
                return new SequenceOperation(
                    ReadOperations(value, "operations", context, depth + 1),
                    kind == "protector_internal_sequence",
                    context.Provenance);

            case "register_write":
                return new AssignOperation(
                    [new RegisterTarget(ReadExpressionProperty(value, "register", context, depth), context.Provenance)],
                    [ReadExpressionProperty(value, "value", context, depth)],
                    context.Provenance);

            case "table_write":
                return new AssignOperation(
                    [new IndexTarget(
                        ReadExpressionProperty(value, "table", context, depth),
                        ReadExpressionProperty(value, "index", context, depth),
                        context.Provenance)],
                    [ReadExpressionProperty(value, "value", context, depth)],
                    context.Provenance);

            case "expression":
                return new ExpressionOperation(ReadExpressionProperty(value, "value", context, depth), context.Provenance);

            case "set_top":
                return new AssignOperation(
                    [new NamedTarget("top", context.Provenance)],
                    [ReadExpressionProperty(value, "value", context, depth)],
                    context.Provenance);

            case "adjust_top":
                return new CompoundAssignOperation(
                    new NamedTarget("top", context.Provenance),
                    NormalizeCompoundOperator(ReadString(value, "operator", "+")),
                    ReadExpressionProperty(value, "value", context, depth),
                    context.Provenance);

            case "assign":
                return new AssignOperation(
                    ReadTargets(value, context, depth + 1),
                    ReadExpressions(value, "values", context, depth + 1),
                    context.Provenance);

            case "compound_write":
                return new CompoundAssignOperation(
                    ReadTargetProperty(value, "target", context, depth),
                    NormalizeCompoundOperator(ReadString(value, "operator", "+")),
                    ReadExpressionProperty(value, "value", context, depth),
                    context.Provenance);

            case "prepare_vm_state":
                return ReadStateBindings(value, context, depth);

            case "prepare_register_clear":
                return new PrepareRegisterClearOperation(
                    ReadString(value, "state", "register_clear"),
                    ReadExpressionProperty(value, "from", context, depth),
                    ReadExpressionProperty(value, "to", context, depth),
                    context.Provenance);

            case "clear_prepared_register_range":
                return new ClearPreparedRegisterRangeOperation(
                    ReadString(value, "state", "register_clear"),
                    context.Provenance);

            case "capture_varargs":
                return new CaptureVarargsOperation(
                    ReadString(value, "values_slot", "varargs"),
                    ReadString(value, "count_slot", "vararg_count"),
                    context.Provenance);

            case "close_upvalues":
                return new CloseCapturesOperation(ReadExpressionProperty(value, "from", context, depth), context.Provenance);

            case "generic_for_prepare":
                return new GenericForPrepareOperation(
                    ReadExpressionProperty(value, "base_register", context, depth),
                    ReadOptionalExpression(value, "loop_target", context, depth),
                    context.Provenance);

            case "numeric_for":
                return new NumericForOperation(
                    SafeName(ReadString(value, "index", "loop_index")),
                    ReadExpressionProperty(value, "from", context, depth),
                    ReadExpressionProperty(value, "to", context, depth),
                    ReadOptionalExpression(value, "step", context, depth) ?? new NumberExpression("1", context.Provenance),
                    ReadOperations(value, "body", context, depth + 1),
                    context.Provenance);

            case "return":
                {
                    IReadOnlyList<SemanticExpression> values = ReadExpressions(value, "values", context, depth + 1);
                    bool expands = values.LastOrDefault() is CallExpression or RegisterRangeExpression or IdentifierExpression { Name: "..." };
                    return new ReturnOperation(values, new ResultArity(expands ? null : values.Count, expands), context.Provenance);
                }

            case "branch":
                return new BranchOperation(
                    ReadExpressionProperty(value, "condition", context, depth),
                    ReadOperations(value, "then", context, depth + 1),
                    ReadOperations(value, "else", context, depth + 1),
                    FindStaticJump(value, "then"),
                    FindStaticJump(value, "else"),
                    context.Provenance);

            case "jump":
                {
                    SemanticExpression target = ReadExpressionProperty(value, "target", context, depth);
                    int? staticTarget = IntegerValue(target) is int raw ? raw + 1 : null;
                    return new JumpOperation(target, staticTarget, context.Provenance);
                }

            default:
                return UnresolvedOperation(context, kind, "semantic operation is not supported");
        }
    }

    private SemanticExpression ReadExpression(JsonElement value, ImportContext context, int depth)
    {
        if (depth > MaxDepth || value.ValueKind != JsonValueKind.Object)
            return UnresolvedExpression(context, "invalid", "expression is missing or nested too deeply");

        string kind = ReadString(value, "kind");
        switch (kind)
        {
            case "immediate":
                return new LaneExpression(
                    ReadString(value, "lane"),
                    value.TryGetProperty("value", out JsonElement immediate)
                        ? ReadPrimitive(immediate, context.Provenance)
                        : new NilExpression(context.Provenance),
                    context.Provenance);
            case "constant":
                return value.TryGetProperty("value", out JsonElement constant)
                    ? ReadPrimitive(constant, context.Provenance)
                    : new NilExpression(context.Provenance);
            case "observed_register_value":
                return value.TryGetProperty("value", out JsonElement observed)
                    ? ReadPrimitive(observed, context.Provenance)
                    : new NilExpression(context.Provenance);
            case "register_read":
                return new RegisterReadExpression(ReadExpressionProperty(value, "index", context, depth), context.Provenance);
            case "register_file":
                return new IdentifierExpression("registers", context.Provenance);
            case "upvalue_file":
                return new IdentifierExpression("captured_values", context.Provenance);
            case "top_register":
                return new IdentifierExpression("top", context.Provenance);
            case "varargs":
                return new IdentifierExpression("...", context.Provenance);
            case "semantic_local":
                return new IdentifierExpression(SafeName(ReadString(value, "name", "local_value")), context.Provenance);
            case "vm_state":
                return new IndexExpression(
                    new IdentifierExpression("state", context.Provenance),
                    new StringExpression(ReadString(value, "name", "?"), context.Provenance),
                    false,
                    context.Provenance);
            case "helper_table":
                return new IdentifierExpression("helper_values", context.Provenance);
            case "opcode_table":
                return new IdentifierExpression("opcode_values", context.Provenance);
            case "operand_table":
                return new IdentifierExpression("operand_values", context.Provenance);
            case "index_read":
                return ReadIndexExpression(value, context, depth);
            case "binary":
                return new BinaryExpression(
                    ReadString(value, "operator", "+"),
                    ReadExpressionProperty(value, "left", context, depth),
                    ReadExpressionProperty(value, "right", context, depth),
                    context.Provenance);
            case "unary":
                return new UnaryExpression(
                    ReadString(value, "operator", "not"),
                    ReadExpressionProperty(value, "value", context, depth),
                    context.Provenance);
            case "table":
                return ReadTableExpression(value, context, depth);
            case "register_range":
                return new RegisterRangeExpression(
                    ReadExpressionProperty(value, "from", context, depth),
                    ReadExpressionProperty(value, "to", context, depth),
                    context.Provenance);
            case "call":
                return new CallExpression(
                    ReadExpressionProperty(value, "function", context, depth),
                    ReadExpressions(value, "arguments", context, depth + 1),
                    ResultArity.Unknown,
                    null,
                    context.Provenance);
            case "nil":
                return new NilExpression(context.Provenance);
            default:
                return UnresolvedExpression(context, kind, "semantic expression is not supported");
        }
    }

    private SemanticExpression ReadIndexExpression(JsonElement value, ImportContext context, int depth)
    {
        SemanticExpression table = ReadExpressionProperty(value, "table", context, depth);
        SemanticExpression index = ReadExpressionProperty(value, "index", context, depth);
        if (table is IdentifierExpression { Name: "captured_values" })
        {
            int? encoded = IntegerValue(index);
            string? lane = index is LaneExpression laneExpression ? laneExpression.Lane : null;
            int? runtime = lane is not null && context.RuntimeOverrides.TryGetValue(lane, out SemanticExpression? overrideValue)
                ? IntegerValue(overrideValue)
                : null;
            int? staticKey = lane is not null && context.StaticLanes.TryGetValue(lane, out SemanticExpression? staticValue)
                ? IntegerValue(staticValue)
                : encoded;
            int key = staticKey ?? encoded ?? -1;
            int? resolved = ResolveCaptureKey(context, key, runtime);
            return new CaptureReadExpression(key, resolved, lane, resolved.HasValue, context.Provenance);
        }

        return new IndexExpression(table, index, false, context.Provenance);
    }

    private int? ResolveCaptureKey(ImportContext context, int encoded, int? runtime)
    {
        if (!context.CaptureDomains.TryGetValue(context.Prototype, out HashSet<int>? domain))
            return runtime ?? (encoded >= 0 ? encoded : null);
        if (domain.Count == 0)
            return null;
        if (runtime is int runtimeKey && domain.Contains(runtimeKey))
            return runtimeKey;
        if (context.CaptureResolutions.TryGetValue(encoded, out int provenKey) && domain.Contains(provenKey))
            return provenKey;
        if (domain.Contains(encoded))
            return encoded;
        return domain.Count == 1 ? domain.Single() : null;
    }

    private TableExpression ReadTableExpression(JsonElement value, ImportContext context, int depth)
    {
        List<TableField> fields = [];
        if (TryArray(value, "entries", out JsonElement entries))
        {
            foreach (JsonElement entry in entries.EnumerateArray())
            {
                bool isList = ReadString(entry, "entry_kind", "list") == "list";
                SemanticExpression? key = isList ? null : ReadOptionalExpression(entry, "key", context, depth + 1);
                fields.Add(new TableField(
                    key,
                    ReadExpressionProperty(entry, "value", context, depth + 1),
                    isList));
            }
        }
        return new TableExpression(fields, context.Provenance);
    }

    private AssignmentTarget ReadTarget(JsonElement value, ImportContext context, int depth)
    {
        if (depth > MaxDepth || value.ValueKind != JsonValueKind.Object)
            return new UnresolvedTarget("invalid", context.Provenance);

        string kind = ReadString(value, "kind");
        return kind switch
        {
            "register" => new RegisterTarget(ReadExpressionProperty(value, "index", context, depth), context.Provenance),
            "index" => new IndexTarget(
                ReadExpressionProperty(value, "table", context, depth),
                ReadExpressionProperty(value, "index", context, depth),
                context.Provenance),
            "top_register" => new NamedTarget("top", context.Provenance),
            "program_counter" => new NamedTarget("pc", context.Provenance),
            "semantic_local" => new NamedTarget(SafeName(ReadString(value, "name", "local_value")), context.Provenance),
            "vm_state" => new IndexTarget(
                new IdentifierExpression("state", context.Provenance),
                new StringExpression(ReadString(value, "name", "?"), context.Provenance),
                context.Provenance),
            "opcode_slot" => new IndexTarget(
                new IdentifierExpression("opcode_values", context.Provenance),
                ReadExpressionProperty(value, "index", context, depth),
                context.Provenance),
            _ => new UnresolvedTarget(kind, context.Provenance),
        };
    }

    private SequenceOperation ReadStateBindings(JsonElement value, ImportContext context, int depth)
    {
        List<SemanticOperation> operations = [];
        if (TryArray(value, "bindings", out JsonElement bindings))
        {
            foreach (JsonElement binding in bindings.EnumerateArray())
            {
                operations.Add(new AssignOperation(
                    [new IndexTarget(
                        new IdentifierExpression("state", context.Provenance),
                        new StringExpression(ReadString(binding, "slot", "?"), context.Provenance),
                        context.Provenance)],
                    [ReadExpressionProperty(binding, "value", context, depth + 1)],
                    context.Provenance));
            }
        }
        return new SequenceOperation(operations, false, context.Provenance);
    }

    private ClosureDescriptor? ReadClosureDescriptor(JsonElement value, Provenance provenance)
    {
        if (value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return null;
        if (value.ValueKind != JsonValueKind.Object)
            return new ClosureDescriptor(false, 0, -1, [], provenance);

        List<CaptureBinding> captures = [];
        if (TryArray(value, "captures", out JsonElement rows))
        {
            foreach (JsonElement row in rows.EnumerateArray())
            {
                int rawKind = ReadInt32(row, "capture_kind", -1);
                CaptureKind kind = rawKind switch
                {
                    0 => CaptureKind.RegisterCell,
                    1 => CaptureKind.Value,
                    _ => CaptureKind.ParentCell,
                };
                captures.Add(new CaptureBinding(
                    ReadInt32(row, "capture_index", -1),
                    kind,
                    ReadInt32(row, "slot", -1)));
            }
        }

        return new ClosureDescriptor(
            ReadBoolean(value, "complete"),
            ReadUInt64(value, "target_prototype"),
            ReadInt32(value, "destination_register", -1),
            captures,
            provenance);
    }

    private PayloadRoot? ReadRoot(JsonElement root)
    {
        if (!root.TryGetProperty("payload_root", out JsonElement row) || row.ValueKind != JsonValueKind.Object)
            return null;
        ulong prototype = ReadUInt64(row, "payload_prototype");
        ClosureDescriptor? closure = row.TryGetProperty("closure_descriptor", out JsonElement descriptor)
            ? ReadClosureDescriptor(descriptor, Provenance.At(prototype, 0))
            : null;
        return prototype == 0 ? null : new PayloadRoot(prototype, closure, ReadPayloadArguments(root, prototype));
    }

    private IReadOnlyList<SemanticExpression> ReadPayloadArguments(JsonElement root, ulong prototype)
    {
        if (!root.TryGetProperty("payload_activation_arguments", out JsonElement payload) ||
            payload.ValueKind != JsonValueKind.Object ||
            !TryArray(payload, "arguments", out JsonElement arguments))
            return [];

        Provenance provenance = Provenance.At(prototype, 0, EvidenceKind.Runtime);
        Dictionary<int, List<TableField>> tableEntries = [];
        if (TryArray(payload, "argument_table_entries", out JsonElement entries))
        {
            foreach (JsonElement entry in entries.EnumerateArray())
            {
                int argument = ReadInt32(entry, "argument_index", -1);
                if (argument <= 0 || !entry.TryGetProperty("key", out JsonElement key) ||
                    !entry.TryGetProperty("value", out JsonElement value))
                    continue;
                if (!tableEntries.TryGetValue(argument, out List<TableField>? fields))
                    tableEntries[argument] = fields = [];
                fields.Add(new TableField(
                    ReadRuntimeValue(key, provenance, $"root argument {argument} key"),
                    ReadRuntimeValue(value, provenance, $"root argument {argument} value"),
                    false));
            }
        }

        HashSet<int> completeTables = [];
        if (TryArray(payload, "argument_table_domains", out JsonElement domains))
            foreach (JsonElement domain in domains.EnumerateArray())
                if (ReadBoolean(domain, "complete"))
                    completeTables.Add(ReadInt32(domain, "argument_index", -1));

        List<SemanticExpression> result = [];
        int index = 0;
        foreach (JsonElement argument in arguments.EnumerateArray())
        {
            index++;
            string type = ReadString(argument, "type");
            if (type == "table" && completeTables.Contains(index))
            {
                result.Add(new TableExpression(tableEntries.GetValueOrDefault(index) ?? [], provenance));
                continue;
            }
            result.Add(ReadRuntimeValue(argument, provenance, $"root argument {index}"));
        }
        return result;
    }

    private SemanticExpression ReadRuntimeValue(JsonElement value, Provenance provenance, string label)
    {
        string type = ReadString(value, "type");
        if (type == "global_reference" && ReadString(value, "path") is string path && path.Length > 0)
            return EnvironmentPath(path, provenance);
        if (type == "function" && ReadString(value, "name") is string name && name.Length > 0)
            return new CallExpression(
                new IdentifierExpression("resolve_named_function", provenance),
                [new StringExpression(name, provenance)],
                new ResultArity(1, RuntimeVerified: true),
                null,
                provenance);
        if (ReadBoolean(value, "primitive"))
            return ReadPrimitive(value, provenance);

        AddIssue(provenance.Sites.FirstOrDefault()?.Prototype ?? 0, 0, "root",
            "unresolved_root_argument", $"{label} is not reconstructable from the runtime snapshot");
        return new IdentifierExpression("unresolved_helper", provenance);
    }

    private static SemanticExpression EnvironmentPath(string path, Provenance provenance)
    {
        SemanticExpression result = new IdentifierExpression("environment", provenance);
        foreach (string segment in path.Split('.', StringSplitOptions.RemoveEmptyEntries))
            result = new IndexExpression(result, new StringExpression(segment, provenance), false, provenance);
        return result;
    }

    private List<PrototypeCallEdge> ReadCallEdges(JsonElement root)
    {
        List<PrototypeCallEdge> result = [];
        if (!TryArray(root, "prototype_call_edges", out JsonElement rows))
            return result;
        foreach (JsonElement row in rows.EnumerateArray())
        {
            ulong caller = ReadUInt64(row, "caller_prototype");
            int pc = ReadInt32(row, "caller_pc");
            ulong callee = ReadUInt64(row, "callee_prototype");
            if (caller > 0 && pc > 0 && callee > 0)
            {
                IReadOnlyList<SemanticExpression>? stableArguments = ReadStableCallArguments(row, caller, pc);
                result.Add(new PrototypeCallEdge(
                    caller,
                    pc,
                    callee,
                    stableArguments,
                    stableArguments is not null));
            }
        }
        return result;
    }

    private IReadOnlyList<SemanticExpression>? ReadStableCallArguments(JsonElement row, ulong prototype, int pc)
    {
        Provenance provenance = Provenance.At(prototype, pc, EvidenceKind.Runtime);
        if (ReadBoolean(row, "arguments_complete") &&
            TryArray(row, "stable_arguments", out JsonElement arguments))
        {
            List<SemanticExpression> result = [];
            foreach (JsonElement argument in arguments.EnumerateArray())
            {
                SemanticExpression? expression = TryReadStableCallArgument(argument, provenance);
                if (expression is null)
                    return null;
                result.Add(expression);
            }
            return result;
        }

        if (!ReadBoolean(row, "observed_argument_count_complete") ||
            !TryArray(row, "observed_argument_identities", out JsonElement identities))
            return null;
        int count = ReadInt32(row, "observed_argument_count", -1);
        int observations = ReadInt32(row, "observed_activations", -1);
        if (count is < 0 or > 16 || observations <= 0 || identities.GetArrayLength() != count)
            return null;

        SemanticExpression?[] ordered = new SemanticExpression?[count];
        foreach (JsonElement identity in identities.EnumerateArray())
        {
            int index = ReadInt32(identity, "argument_index", -1);
            if (index <= 0 || index > count || ordered[index - 1] is not null ||
                ReadInt32(identity, "observed_activations", -1) != observations ||
                !identity.TryGetProperty("identity", out JsonElement value))
                return null;
            ordered[index - 1] = TryReadStableCallArgument(value, provenance);
            if (ordered[index - 1] is null)
                return null;
        }
        return ordered.Select(item => item!).ToList();
    }

    private static SemanticExpression? TryReadStableCallArgument(JsonElement value, Provenance provenance)
    {
        string type = ReadString(value, "type");
        if (type == "global_reference" && ReadString(value, "path") is string path && path.Length > 0)
            return EnvironmentPath(path, provenance);
        if (!ReadBoolean(value, "primitive"))
            return null;
        return ReadPrimitive(value, provenance);
    }

    private List<LaneReplaySite> ReadLaneReplays(JsonElement root)
    {
        List<LaneReplaySite> result = [];
        if (!TryArray(root, "observed_lane_sequences", out JsonElement rows))
            return result;
        foreach (JsonElement row in rows.EnumerateArray())
        {
            ulong prototype = ReadUInt64(row, "prototype");
            int pc = ReadInt32(row, "pc");
            Provenance provenance = Provenance.At(prototype, pc, EvidenceKind.Runtime);
            HashSet<string> lanes = [];
            if (TryArray(row, "lanes", out JsonElement laneRows))
                foreach (JsonElement lane in laneRows.EnumerateArray())
                    if (lane.ValueKind == JsonValueKind.String && lane.GetString() is string name)
                        lanes.Add(name);

            List<ReplayActivation> activations = [];
            if (TryArray(row, "activation_sequences", out JsonElement activationRows))
            {
                foreach (JsonElement activation in activationRows.EnumerateArray())
                {
                    List<ReplayFrame> frames = [];
                    if (TryArray(activation, "frames", out JsonElement frameRows))
                    {
                        foreach (JsonElement frame in frameRows.EnumerateArray())
                        {
                            Dictionary<string, SemanticExpression> values = [];
                            foreach (string lane in lanes)
                                if (frame.TryGetProperty(lane, out JsonElement laneValue))
                                    values[lane] = ReadPrimitive(laneValue, provenance);
                            frames.Add(new ReplayFrame(values));
                        }
                    }
                    if (frames.Count > 0)
                        activations.Add(new ReplayActivation(frames));
                }
            }
            if (prototype > 0 && pc > 0 && activations.Count > 0)
                result.Add(new LaneReplaySite(prototype, pc, lanes, activations,
                    ReadInt32(row, "repeat_from_sequence"), provenance));
        }
        return result;
    }

    private List<TransitionReplaySite> ReadTransitionReplays(JsonElement root)
    {
        List<TransitionReplaySite> result = [];
        if (!TryArray(root, "observed_transition_sequences", out JsonElement rows))
            return result;
        foreach (JsonElement row in rows.EnumerateArray())
        {
            ulong prototype = ReadUInt64(row, "prototype");
            int pc = ReadInt32(row, "pc");
            List<int> legacy = ReadPositiveInts(row, "next_pcs");
            List<IReadOnlyList<int>> activations = [];
            if (TryArray(row, "activation_sequences", out JsonElement activationRows))
                foreach (JsonElement activation in activationRows.EnumerateArray())
                {
                    List<int> values = ReadPositiveInts(activation, "next_pcs");
                    if (values.Count > 0)
                        activations.Add(values);
                }
            if (prototype > 0 && pc > 0 && (legacy.Count > 0 || activations.Count > 0))
                result.Add(new TransitionReplaySite(prototype, pc, legacy, activations,
                    ReadInt32(row, "repeat_from_sequence"), Provenance.At(prototype, pc, EvidenceKind.Runtime)));
        }
        return result;
    }

    private Dictionary<ulong, HashSet<int>> ReadCaptureDomains(JsonElement root)
    {
        Dictionary<ulong, HashSet<int>> result = [];
        if (!TryArray(root, "observed_capture_domains", out JsonElement rows))
            return result;
        foreach (JsonElement row in rows.EnumerateArray())
        {
            if (!ReadBoolean(row, "complete"))
                continue;
            ulong prototype = ReadUInt64(row, "prototype");
            if (prototype == 0 || !TryArray(row, "indices", out JsonElement indices))
                continue;
            result[prototype] = indices.EnumerateArray()
                .Where(item => item.TryGetInt32(out int value) && value >= 0)
                .Select(item => item.GetInt32())
                .ToHashSet();
        }
        return result;
    }

    private Dictionary<(ulong Prototype, int Pc), Dictionary<int, int>> ReadCaptureResolutions(
        JsonElement root,
        IReadOnlyDictionary<ulong, HashSet<int>> domains)
    {
        Dictionary<(ulong Prototype, int Pc), Dictionary<int, int>> result = [];
        HashSet<(ulong Prototype, int Pc, int Encoded)> ambiguous = [];
        if (!TryArray(root, "capture_key_resolutions", out JsonElement rows))
            return result;

        foreach (JsonElement row in rows.EnumerateArray())
        {
            ulong prototype = ReadUInt64(row, "prototype");
            int pc = ReadInt32(row, "pc", -1);
            int encoded = ReadInt32(row, "encoded", -1);
            int resolved = ReadInt32(row, "resolved", -1);
            bool valid = ReadBoolean(row, "complete") && prototype > 0 && pc > 0 && encoded >= 0 &&
                resolved >= 0 && domains.TryGetValue(prototype, out HashSet<int>? domain) &&
                domain.Contains(resolved);
            if (!valid)
            {
                AddIssue(prototype, Math.Max(pc, 0), "captures", "invalid_capture_resolution",
                    "native capture evidence did not match a complete observed capture domain");
                continue;
            }

            if (!result.TryGetValue((prototype, pc), out Dictionary<int, int>? site))
                result[(prototype, pc)] = site = [];
            if (ambiguous.Contains((prototype, pc, encoded)))
                continue;
            if (site.TryGetValue(encoded, out int previous) && previous != resolved)
            {
                site.Remove(encoded);
                ambiguous.Add((prototype, pc, encoded));
                AddIssue(prototype, pc, "captures", "ambiguous_capture_resolution",
                    "native capture evidence mapped one encoded key to multiple capture cells");
                continue;
            }
            site[encoded] = resolved;
        }
        return result;
    }

    private void MergeDescriptorDomains(JsonElement root, Dictionary<ulong, HashSet<int>> domains)
    {
        IEnumerable<JsonElement> descriptors = EnumerateDescriptors(root);
        foreach (JsonElement descriptor in descriptors)
        {
            if (!ReadBoolean(descriptor, "complete"))
                continue;
            ulong target = ReadUInt64(descriptor, "target_prototype");
            if (target == 0 || !TryArray(descriptor, "captures", out JsonElement captures))
                continue;
            HashSet<int> indices = captures.EnumerateArray()
                .Select(item => ReadInt32(item, "capture_index", -1))
                .Where(index => index >= 0)
                .ToHashSet();
            if (!domains.TryGetValue(target, out HashSet<int>? current))
                domains[target] = indices;
            else if (!current.SetEquals(indices))
                domains.Remove(target);
        }
    }

    private static IEnumerable<JsonElement> EnumerateDescriptors(JsonElement root)
    {
        if (TryArray(root, "closure_descriptors", out JsonElement sideTable))
            foreach (JsonElement descriptor in sideTable.EnumerateArray())
                yield return descriptor;
        if (!TryArray(root, "prototypes", out JsonElement prototypes))
            yield break;
        foreach (JsonElement prototype in prototypes.EnumerateArray())
            if (TryArray(prototype, "instructions", out JsonElement instructions))
                foreach (JsonElement instruction in instructions.EnumerateArray())
                    if (instruction.TryGetProperty("closure_descriptor", out JsonElement descriptor))
                        yield return descriptor;
    }

    private ControlFlowGraph ReadCfg(JsonElement root)
    {
        List<PrototypeControlFlow> prototypes = [];
        List<UnresolvedFact> graphIssues = [];
        if (!TryArray(root, "prototypes", out JsonElement rows))
            return new ControlFlowGraph(prototypes, graphIssues);

        foreach (JsonElement row in rows.EnumerateArray())
        {
            ulong id = ReadUInt64(row, "runtime_id");
            int entry = ReadInt32(row, "entry_pc", 1);
            Dictionary<string, int> starts = [];
            if (TryArray(row, "blocks", out JsonElement blockRows))
                foreach (JsonElement block in blockRows.EnumerateArray())
                    starts[ReadString(block, "id")] = ReadInt32(block, "start_pc");

            List<BasicBlock> blocks = [];
            if (TryArray(row, "blocks", out blockRows))
            {
                foreach (JsonElement block in blockRows.EnumerateArray())
                {
                    string blockId = ReadString(block, "id", $"p{id}_b{ReadInt32(block, "start_pc")}");
                    List<int> successors = [];
                    if (TryArray(block, "successors", out JsonElement successorRows))
                        foreach (JsonElement successor in successorRows.EnumerateArray())
                            if (successor.ValueKind == JsonValueKind.String &&
                                starts.TryGetValue(successor.GetString() ?? string.Empty, out int start))
                                successors.Add(start);
                    blocks.Add(new BasicBlock(
                        blockId,
                        ReadInt32(block, "start_pc"),
                        ReadInt32(block, "end_pc"),
                        ReadBoolean(block, "reachable"),
                        ReadTerminator(ReadString(block, "terminator", "fallthrough"), successors.Count),
                        successors));
                }
            }
            if (id > 0)
                prototypes.Add(new PrototypeControlFlow(id, entry, blocks));
        }
        return new ControlFlowGraph(prototypes, graphIssues);
    }

    private SemanticOperation ApplyReturnEvidence(JsonElement row, SemanticOperation operation, ImportContext context)
    {
        if (!TryArray(row, "observed_returns", out JsonElement observed) || observed.GetArrayLength() == 0)
            return operation;
        if (operation is not ReturnOperation { Arity.Exact: int expected })
        {
            if (operation is not ReturnOperation)
                AddIssue(context.Prototype, context.Pc, "returns", "return_operation_missing", "runtime returned from a non-return semantic operation");
            return operation;
        }
        foreach (JsonElement item in observed.EnumerateArray())
            if (!ReadBoolean(item, "complete") || ReadInt32(item, "arity", -1) != expected)
            {
                AddIssue(context.Prototype, context.Pc, "returns", "return_arity_mismatch", "observed return arity does not match semantic IR");
                return operation;
            }
        ReturnOperation returned = (ReturnOperation)operation;
        return returned with { Arity = returned.Arity with { RuntimeVerified = true } };
    }

    private static SemanticExpression ReadPrimitive(JsonElement value, Provenance provenance)
    {
        if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty("type", out JsonElement typeElement))
        {
            string type = typeElement.GetString() ?? string.Empty;
            JsonElement raw = value.TryGetProperty("value", out JsonElement nested) ? nested : default;
            return type switch
            {
                "nil" => new NilExpression(provenance),
                "boolean" => new BooleanExpression(ReadBooleanValue(raw), provenance),
                "number" => new NumberExpression(ReadNumberText(raw), provenance),
                "string" => new StringExpression(raw.ValueKind == JsonValueKind.String ? raw.GetString() ?? string.Empty : string.Empty, provenance),
                "function" when value.TryGetProperty("name", out JsonElement name) && name.ValueKind == JsonValueKind.String =>
                    new IdentifierExpression(SafeName(name.GetString() ?? "function_value"), provenance),
                _ => new UnresolvedExpression(type, "runtime value is not a primitive", provenance),
            };
        }

        return value.ValueKind switch
        {
            JsonValueKind.Null or JsonValueKind.Undefined => new NilExpression(provenance),
            JsonValueKind.True => new BooleanExpression(true, provenance),
            JsonValueKind.False => new BooleanExpression(false, provenance),
            JsonValueKind.String => new StringExpression(value.GetString() ?? string.Empty, provenance),
            JsonValueKind.Number => new NumberExpression(value.GetRawText(), provenance),
            _ => new UnresolvedExpression("primitive", "value is not a supported primitive", provenance),
        };
    }

    private static bool ReadBooleanValue(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.String => string.Equals(value.GetString(), "true", StringComparison.OrdinalIgnoreCase),
        _ => false,
    };

    private static string ReadNumberText(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.String)
            return NormalizeNumber(value.GetString() ?? "0");
        return value.ValueKind == JsonValueKind.Number ? NormalizeNumber(value.GetRawText()) : "0";
    }

    private static string NormalizeNumber(string text)
    {
        if (string.Equals(text, "nan", StringComparison.OrdinalIgnoreCase))
            return "nan";
        if (string.Equals(text, "inf", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(text, "infinity", StringComparison.OrdinalIgnoreCase))
            return "inf";
        if (string.Equals(text, "-inf", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(text, "-infinity", StringComparison.OrdinalIgnoreCase))
            return "-inf";
        return double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out _) ? text : "0";
    }

    private Dictionary<string, SemanticExpression> ReadLaneObject(JsonElement row, string property, Provenance provenance)
    {
        Dictionary<string, SemanticExpression> result = [];
        if (!row.TryGetProperty(property, out JsonElement lanes) || lanes.ValueKind != JsonValueKind.Object)
            return result;
        foreach (JsonProperty lane in lanes.EnumerateObject())
            result[lane.Name] = ReadPrimitive(lane.Value, provenance);
        return result;
    }

    private IReadOnlyList<SemanticOperation> ReadOperations(JsonElement row, string property, ImportContext context, int depth)
    {
        if (!TryArray(row, property, out JsonElement values))
            return [];
        return values.EnumerateArray().Select(item => ReadOperation(item, context, depth + 1)).ToList();
    }

    private IReadOnlyList<SemanticExpression> ReadExpressions(JsonElement row, string property, ImportContext context, int depth)
    {
        if (!TryArray(row, property, out JsonElement values))
            return [];
        return values.EnumerateArray().Select(item => ReadExpression(item, context, depth + 1)).ToList();
    }

    private IReadOnlyList<AssignmentTarget> ReadTargets(JsonElement row, ImportContext context, int depth)
    {
        if (!TryArray(row, "targets", out JsonElement values))
            return [];
        return values.EnumerateArray().Select(item => ReadTarget(item, context, depth + 1)).ToList();
    }

    private SemanticExpression ReadExpressionProperty(JsonElement row, string property, ImportContext context, int depth) =>
        row.TryGetProperty(property, out JsonElement value)
            ? ReadExpression(value, context, depth + 1)
            : UnresolvedExpression(context, property, "expression property is missing");

    private SemanticExpression? ReadOptionalExpression(JsonElement row, string property, ImportContext context, int depth) =>
        row.TryGetProperty(property, out JsonElement value) && value.ValueKind == JsonValueKind.Object
            ? ReadExpression(value, context, depth + 1)
            : null;

    private AssignmentTarget ReadTargetProperty(JsonElement row, string property, ImportContext context, int depth) =>
        row.TryGetProperty(property, out JsonElement value)
            ? ReadTarget(value, context, depth + 1)
            : new UnresolvedTarget(property, context.Provenance);

    private UnresolvedOperation UnresolvedOperation(ImportContext context, string kind, string reason)
    {
        AddIssue(context.Prototype, context.Pc, "lift", "unsupported_operation", $"{kind}: {reason}");
        return new UnresolvedOperation(kind, reason, context.Provenance);
    }

    private UnresolvedExpression UnresolvedExpression(ImportContext context, string kind, string reason)
    {
        AddIssue(context.Prototype, context.Pc, "lift", "unsupported_expression", $"{kind}: {reason}");
        return new UnresolvedExpression(kind, reason, context.Provenance);
    }

    private void AddIssue(ulong prototype, int pc, string stage, string code, string message) =>
        unresolved.Add(new UnresolvedFact(stage, code, message, Provenance.At(prototype, pc)));

    private static int? FindStaticJump(JsonElement row, string side)
    {
        if (!TryArray(row, side, out JsonElement operations))
            return null;
        foreach (JsonElement operation in operations.EnumerateArray())
        {
            if (ReadString(operation, "kind") != "jump" || !operation.TryGetProperty("target", out JsonElement target))
                continue;
            if (target.TryGetProperty("value", out JsonElement value) && TryPrimitiveInt(value, out int result))
                return result + 1;
        }
        return null;
    }

    private static int? IntegerValue(SemanticExpression expression) => expression switch
    {
        NumberExpression number when int.TryParse(number.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value) => value,
        LaneExpression lane => IntegerValue(lane.Fallback),
        _ => null,
    };

    private static List<int> ReadPositiveInts(JsonElement row, string property)
    {
        List<int> result = [];
        if (!TryArray(row, property, out JsonElement values))
            return result;
        foreach (JsonElement value in values.EnumerateArray())
            if (value.TryGetInt32(out int number) && number > 0)
                result.Add(number);
        return result;
    }

    private static BlockTerminatorKind ReadTerminator(string value, int successorCount) => value switch
    {
        "return" => BlockTerminatorKind.Return,
        "branch" => BlockTerminatorKind.Branch,
        "jump" => BlockTerminatorKind.Jump,
        "stop" => BlockTerminatorKind.Stop,
        _ when successorCount > 1 => BlockTerminatorKind.Dynamic,
        _ => BlockTerminatorKind.Fallthrough,
    };

    private static string NormalizeCompoundOperator(string value) => value.EndsWith('=') ? value : value + "=";

    private static string SafeName(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "value";
        Span<char> result = stackalloc char[value.Length];
        for (int index = 0; index < value.Length; index++)
        {
            char current = value[index];
            result[index] = char.IsLetterOrDigit(current) || current == '_' ? current : '_';
        }
        string name = result.ToString();
        return char.IsDigit(name[0]) ? "value_" + name : name;
    }

    private static bool TryArray(JsonElement row, string property, out JsonElement value)
    {
        if (row.ValueKind == JsonValueKind.Object && row.TryGetProperty(property, out value) && value.ValueKind == JsonValueKind.Array)
            return true;
        value = default;
        return false;
    }

    private static string ReadString(JsonElement row, string property, string fallback = "") =>
        row.ValueKind == JsonValueKind.Object && row.TryGetProperty(property, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? fallback
            : fallback;

    private static bool ReadBoolean(JsonElement row, string property, bool fallback = false) =>
        row.ValueKind == JsonValueKind.Object && row.TryGetProperty(property, out JsonElement value)
            ? value.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => fallback,
            }
            : fallback;

    private static int ReadInt32(JsonElement row, string property, int fallback = 0) =>
        row.ValueKind == JsonValueKind.Object && row.TryGetProperty(property, out JsonElement value) &&
            value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int number)
            ? number
            : fallback;

    private static long ReadInt64(JsonElement row, string property, long fallback = 0) =>
        row.ValueKind == JsonValueKind.Object && row.TryGetProperty(property, out JsonElement value) &&
            value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out long number)
            ? number
            : fallback;

    private static ulong ReadUInt64(JsonElement row, string property, ulong fallback = 0) =>
        row.ValueKind == JsonValueKind.Object && row.TryGetProperty(property, out JsonElement value) &&
            value.ValueKind == JsonValueKind.Number && value.TryGetUInt64(out ulong number)
            ? number
            : fallback;

    private static bool TryPrimitiveInt(JsonElement value, out int result)
    {
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out result))
            return true;
        if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty("value", out JsonElement nested))
            return TryPrimitiveInt(nested, out result);
        if (value.ValueKind == JsonValueKind.String)
            return int.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out result);
        result = 0;
        return false;
    }

    private sealed record ImportContext(
        ulong Prototype,
        int Pc,
        Provenance Provenance,
        IReadOnlyDictionary<string, SemanticExpression> StaticLanes,
        IReadOnlyDictionary<string, SemanticExpression> RuntimeOverrides,
        IReadOnlyDictionary<ulong, HashSet<int>> CaptureDomains,
        IReadOnlyDictionary<int, int> CaptureResolutions);
}
