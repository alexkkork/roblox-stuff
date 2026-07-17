using System.Globalization;
using System.Text;
using Luraph.Core.Ir;
using Luraph.Core.Lifting;

namespace Luraph.Core.Emission;

public sealed record LuauEmitterOptions
{
    public int DispatchBucketWidth { get; init; } = 64;
    public int SemanticStepBudget { get; init; } = 1_000_000;
}

public sealed class LuauEmitter
{
    private readonly LuauEmitterOptions options;
    private readonly LuauWriter writer = new();
    private readonly List<SourceMapping> mapping = [];
    private readonly MetricCounter metrics = new();
    private readonly List<UnresolvedFact> unresolved = [];
    private SemanticProgram program = null!;
    private ControlFlowGraph graph = null!;

    public LuauEmitter(LuauEmitterOptions? options = null)
    {
        this.options = options ?? new LuauEmitterOptions();
    }

    public SemanticCandidate Emit(LiftResult lift)
    {
        program = lift.Program;
        graph = lift.ControlFlow;
        unresolved.AddRange(program.Unresolved);
        WritePrelude();
        WriteDeclarations();

        foreach (SemanticPrototype prototype in program.Prototypes.OrderBy(item => item.RuntimeId))
            WritePrototype(prototype);

        WriteRoot();
        metrics.Prototypes = program.Prototypes.Count;
        metrics.UnresolvedClosureDescriptors += unresolved.Count(item => item.Code == "incomplete_closure_descriptor");
        metrics.UnresolvedCaptureKeys += unresolved.Count(item => item.Code == "unresolved_capture_key");
        metrics.ReturnArityMismatches += unresolved.Count(item => item.Code == "return_arity_mismatch");

        return new SemanticCandidate(writer.ToString(), mapping, metrics.ToMetrics(), unresolved);
    }

    private void WritePrelude()
    {
        writer.WriteLine(0, "local environment = getfenv and getfenv(0) or _ENV or _G");
        writer.WriteLine(0, "local select_value = select");
        writer.WriteLine(0, "local unpack_values = table.unpack or unpack");
        writer.WriteLine(0, "local function unresolved_helper(...) return nil end");
        writer.WriteLine(0, "local function resolve_named_function(name)");
        writer.WriteLine(1, "return environment[name]");
        writer.WriteLine(2, "or (environment.string and environment.string[name])");
        writer.WriteLine(2, "or (environment.table and environment.table[name])");
        writer.WriteLine(2, "or (environment.coroutine and environment.coroutine[name])");
        writer.WriteLine(2, "or (environment.task and environment.task[name])");
        writer.WriteLine(2, "or (environment.debug and environment.debug[name])");
        writer.WriteLine(2, "or unresolved_helper");
        writer.WriteLine(0, "end");
        writer.WriteLine(0, "local helper_values = setmetatable({}, { __index = function() return unresolved_helper end })");
        writer.WriteLine(0, "helper_values[23] = function(first, values, last) return unpack_values(values, first, last) end;");
        writer.WriteLine(0, "helper_values[34] = function(value, target_environment) return setfenv and setfenv(value, target_environment) or value end;");
        writer.WriteLine(0, "helper_values[36] = table.move or unresolved_helper;");
        writer.WriteLine(0, "helper_values[39] = bit32 and bit32.bxor or unresolved_helper;");
        writer.WriteLine(0, "helper_values[41] = table.create or function() return {} end;");
        writer.WriteLine(0, "helper_values[53] = function(...) return select_value(\"#\", ...), {...} end;");
        writer.WriteLine(0, "local opcode_values = {}");
        writer.WriteLine(0, "local operand_values = {}");
        writer.WriteLine(0, "local function unresolved_capture_cell(prototype, pc, key)");
        writer.WriteLine(1, "error(\"unresolved capture key at prototype \" .. tostring(prototype) .. \" pc \" .. tostring(pc) .. \" key \" .. tostring(key), 0)");
        writer.WriteLine(0, "end");
        writer.WriteLine(0, "local function call_recovered(value, fallback, captures, ...)");
        writer.WriteLine(1, "if type(value) == \"function\" then return value(...) end");
        writer.WriteLine(1, "return fallback(captures, ...)");
        writer.WriteLine(0, "end");
        writer.WriteLine(0, "local function capture_register_cell(open_cells, registers, slot)");
        writer.WriteLine(1, "local cell = open_cells[slot]");
        writer.WriteLine(1, "if not cell then cell = { [2] = slot, [3] = registers }; open_cells[slot] = cell end");
        writer.WriteLine(1, "return cell");
        writer.WriteLine(0, "end");
        writer.WriteLine(0, "local function close_captured_values(open_cells, registers, from_slot)");
        writer.WriteLine(1, "for slot, cell in open_cells do");
        writer.WriteLine(2, "if slot >= from_slot and cell[3] == registers then");
        writer.WriteLine(3, "cell[3] = { [slot] = registers[slot] }");
        writer.WriteLine(3, "open_cells[slot] = nil");
        writer.WriteLine(2, "end");
        writer.WriteLine(1, "end");
        writer.WriteLine(0, "end");
        writer.WriteLine(0, "local transition_positions = {}");
        writer.WriteLine(0, "local transition_activations = {}");
        writer.WriteLine(0, "local semantic_recent_sites = {}");
        writer.WriteLine(0, "local function semantic_trace_tail() return table.concat(semantic_recent_sites, \" -> \") end");
        writer.WriteLine(0, "local function missing_semantic_state(prototype, pc)");
        writer.WriteLine(1, "error(\"missing semantic state at prototype \" .. tostring(prototype) .. \" pc \" .. tostring(pc) .. \"; recent path: \" .. semantic_trace_tail(), 0)");
        writer.WriteLine(0, "end");
        writer.WriteLine(0, "local function replay_transition(local_positions, key, sequences, repeat_from)");
        writer.WriteLine(1, "local position = (local_positions[key] or 0) + 1");
        writer.WriteLine(1, "local_positions[key] = position");
        writer.WriteLine(1, "local activation = local_positions[key .. \":activation\"]");
        writer.WriteLine(1, "if not activation then");
        writer.WriteLine(2, "activation = (transition_activations[key] or 0) + 1");
        writer.WriteLine(2, "transition_activations[key] = activation");
        writer.WriteLine(2, "local_positions[key .. \":activation\"] = activation");
        writer.WriteLine(1, "end");
        writer.WriteLine(1, "if activation > #sequences and repeat_from > 0 then activation = #sequences end");
        writer.WriteLine(1, "local sequence = sequences[activation]");
        writer.WriteLine(1, "if not sequence or not sequence[position] then");
        writer.WriteLine(2, "error(\"observed replay exhausted at \" .. key .. \" activation \" .. tostring(activation) .. \" visit \" .. tostring(position) .. \"; recent path: \" .. semantic_trace_tail(), 0)");
        writer.WriteLine(1, "end");
        writer.WriteLine(1, "return sequence[position]");
        writer.WriteLine(0, "end");
        writer.WriteLine(0, "local function replay_lanes(local_positions, key, sequences, repeat_from)");
        writer.WriteLine(1, "return replay_transition(local_positions, key, sequences, repeat_from)");
        writer.WriteLine(0, "end");
        writer.WriteLine(0, "local function prepare_generic_iterator(registers, state, base_register)");
        writer.WriteLine(1, "local iterator = registers[base_register]");
        writer.WriteLine(1, "local invariant = registers[base_register + 1]");
        writer.WriteLine(1, "local control = registers[base_register + 2]");
        writer.WriteLine(1, "local runner = coroutine.wrap(function()");
        writer.WriteLine(2, "coroutine.yield()");
        writer.WriteLine(2, "for key, value in iterator, invariant, control do coroutine.yield(true, key, value) end");
        writer.WriteLine(1, "end)");
        writer.WriteLine(1, "runner()");
        writer.WriteLine(1, "state.f = runner");
        writer.WriteLine(0, "end");
        writer.WriteLine(0, "local semantic_steps = 0");
        writer.WriteLine(0, "local semantic_site_counts = {}");
        writer.WriteLine(0, "local function semantic_step(prototype, pc)");
        writer.WriteLine(1, "semantic_steps += 1");
        writer.WriteLine(1, "local key = tostring(prototype) .. \":\" .. tostring(pc)");
        writer.WriteLine(1, "semantic_site_counts[key] = (semantic_site_counts[key] or 0) + 1");
        writer.WriteLine(1, "semantic_recent_sites[#semantic_recent_sites + 1] = key");
        writer.WriteLine(1, "if #semantic_recent_sites > 96 then table.remove(semantic_recent_sites, 1) end");
        writer.WriteLine(1, $"if semantic_steps > {options.SemanticStepBudget.ToString(CultureInfo.InvariantCulture)} then");
        writer.WriteLine(2, "local hottest_site, hottest_count = key, 0");
        writer.WriteLine(2, "for site, count in semantic_site_counts do if count > hottest_count then hottest_site, hottest_count = site, count end end");
        writer.WriteLine(2, "error(\"semantic step budget exhausted at \" .. key .. \"; hottest site \" .. hottest_site .. \" (\" .. tostring(hottest_count) .. \" visits); recent path: \" .. semantic_trace_tail(), 0)");
        writer.WriteLine(1, "end");
        writer.WriteLine(0, "end");
        writer.WriteLine(0);
    }

    private void WriteDeclarations()
    {
        if (program.Prototypes.Count == 0)
            return;
        writer.Write("local ");
        writer.Write(string.Join(", ", program.Prototypes.OrderBy(item => item.RuntimeId).Select(item => PrototypeName(item.RuntimeId))));
        writer.Write("\n\n");
    }

    private void WritePrototype(SemanticPrototype prototype)
    {
        PrototypeControlFlow? cfg = graph.Prototypes.FirstOrDefault(item => item.RuntimeId == prototype.RuntimeId);
        if (cfg is null)
        {
            AddIssue(prototype.RuntimeId, prototype.EntryPc, "missing_cfg", "prototype has no CFG");
            return;
        }

        writer.WriteLine(0, $"{PrototypeName(prototype.RuntimeId)} = function(captured_values, ...)");
        writer.WriteLine(1, "captured_values = captured_values or {}");
        writer.WriteLine(1, "local registers = {}");
        writer.WriteLine(1, "local open_cells = {}");
        writer.WriteLine(1, "local replay_positions = {}");
        writer.WriteLine(1, "local state = { Q = environment }");
        if (prototype.Locals is { Count: > 0 })
            writer.WriteLine(1, "local " + string.Join(", ", prototype.Locals));
        writer.WriteLine(1, "local argument_count = select_value(\"#\", ...)");
        writer.WriteLine(1, "for argument_index = 1, argument_count do registers[argument_index] = select_value(argument_index, ...) end");
        writer.WriteLine(1, "local top = argument_count");
        writer.WriteLine(1, $"local pc = {cfg.EntryPc.ToString(CultureInfo.InvariantCulture)}");
        writer.WriteLine(1, "while pc ~= nil do");
        writer.WriteLine(2, $"semantic_step({prototype.RuntimeId.ToString(CultureInfo.InvariantCulture)}, pc)");

        List<IGrouping<int, BasicBlock>> buckets = cfg.Blocks
            .Where(block => block.Reachable)
            .OrderBy(block => block.StartPc)
            .GroupBy(block => Math.Max(0, (block.StartPc - 1) / options.DispatchBucketWidth))
            .ToList();

        writer.WriteLine(2, $"local dispatch_bucket = math.floor((pc - 1) / {options.DispatchBucketWidth.ToString(CultureInfo.InvariantCulture)})");
        for (int bucketIndex = 0; bucketIndex < buckets.Count; bucketIndex++)
        {
            IGrouping<int, BasicBlock> bucket = buckets[bucketIndex];
            writer.WriteLine(2, $"{(bucketIndex == 0 ? "if" : "elseif")} dispatch_bucket == {bucket.Key.ToString(CultureInfo.InvariantCulture)} then");
            int blockIndex = 0;
            foreach (BasicBlock block in bucket)
            {
                int lineStart = writer.Line;
                writer.WriteLine(3, $"{(blockIndex == 0 ? "if" : "elseif")} pc == {block.StartPc.ToString(CultureInfo.InvariantCulture)} then");
                WriteBlock(prototype, block, 4);
                mapping.Add(new SourceMapping(
                    prototype.RuntimeId,
                    block.Id,
                    block.StartPc,
                    block.EndPc,
                    lineStart,
                    writer.Line - 1,
                    block.Successors));
                metrics.Blocks++;
                blockIndex++;
            }
            writer.WriteLine(3, "else");
            writer.WriteLine(4, $"return missing_semantic_state({prototype.RuntimeId.ToString(CultureInfo.InvariantCulture)}, pc)");
            writer.WriteLine(3, "end");
        }
        writer.WriteLine(2, "else");
        writer.WriteLine(3, $"return missing_semantic_state({prototype.RuntimeId.ToString(CultureInfo.InvariantCulture)}, pc)");
        writer.WriteLine(2, "end");
        writer.WriteLine(1, "end");
        writer.WriteLine(1, "return nil");
        writer.WriteLine(0, "end");
        writer.WriteLine(0);
    }

    private void WriteBlock(SemanticPrototype prototype, BasicBlock block, int depth)
    {
        List<SemanticInstruction> instructions = prototype.Instructions
            .Where(instruction => instruction.Pc >= block.StartPc && instruction.Pc <= block.EndPc)
            .OrderBy(instruction => instruction.Pc)
            .ToList();
        SemanticInstruction? last = instructions.LastOrDefault();

        foreach (SemanticInstruction instruction in instructions)
        {
            EmissionContext context = BuildContext(prototype.RuntimeId, instruction.Pc, depth);
            WriteLaneReplay(context, depth);
            WriteOperation(instruction.Operation, context, depth, instruction.Pc == block.EndPc);
        }

        WriteTransition(prototype.RuntimeId, block, last?.Operation, depth);
    }

    private EmissionContext BuildContext(ulong prototype, int pc, int depth)
    {
        LaneReplaySite? replay = program.LaneReplays.FirstOrDefault(item => item.Prototype == prototype && item.Pc == pc);
        HashSet<string> dynamic = [];
        if (replay is not null)
        {
            foreach (string lane in replay.Lanes)
            {
                List<SemanticExpression> values = replay.Activations.SelectMany(item => item.Frames)
                    .Where(frame => frame.Lanes.ContainsKey(lane))
                    .Select(frame => frame.Lanes[lane])
                    .ToList();
                if (values.Count == 0 || values.Skip(1).Any(value => !PrimitiveEquals(values[0], value)))
                    dynamic.Add(lane);
                else
                    metrics.SpecializedStableLanes++;
            }
        }
        return new EmissionContext(prototype, pc, depth, replay, dynamic, replay is null ? null : $"runtime_lanes_{pc}");
    }

    private void WriteLaneReplay(EmissionContext context, int depth)
    {
        if (context.Replay is null || context.DynamicLanes.Count == 0 || context.RuntimeLaneVariable is null)
            return;

        writer.WriteLine(depth, $"local {context.RuntimeLaneVariable} = replay_lanes(replay_positions, {Quote($"lane:{context.Prototype}:{context.Pc}")}, {{");
        foreach (ReplayActivation activation in context.Replay.Activations)
        {
            writer.WriteLine(depth + 1, "{");
            foreach (ReplayFrame frame in activation.Frames)
            {
                string fields = string.Join(", ", context.DynamicLanes.Order()
                    .Where(frame.Lanes.ContainsKey)
                    .Select(lane => $"[{Quote(lane)}] = {WriteExpression(frame.Lanes[lane], context)}"));
                writer.WriteLine(depth + 2, $"{{ {fields} }},");
            }
            writer.WriteLine(depth + 1, "},");
        }
        writer.WriteLine(depth, $"}}, {context.Replay.RepeatFrom.ToString(CultureInfo.InvariantCulture)});");
        metrics.DynamicLaneReplaySites++;
    }

    private void WriteOperation(
        SemanticOperation operation,
        EmissionContext context,
        int depth,
        bool controlHandled,
        bool nested = false)
    {
        metrics.Operations++;
        switch (operation)
        {
            case SequenceOperation sequence:
                foreach (SemanticOperation child in sequence.Operations)
                    WriteOperation(child, context, depth, controlHandled, nested: true);
                break;

            case AssignOperation assign:
                writer.WriteLine(depth,
                    $"{string.Join(", ", assign.Targets.Select(target => WriteTarget(target, context)))} = " +
                    (assign.Values.Count == 0 ? "nil;" : string.Join(", ", assign.Values.Select(value => WriteExpression(value, context))) + ";"));
                break;

            case CompoundAssignOperation compound:
                writer.WriteLine(depth, $"{WriteTarget(compound.Target, context)} {compound.Operator} {WriteExpression(compound.Value, context)};");
                break;

            case ExpressionOperation expression:
                writer.WriteLine(depth, $"do local _ = {WriteExpression(expression.Expression, context)} end;");
                break;

            case ReturnOperation returned:
                writer.WriteLine(depth, returned.Values.Count == 0
                    ? "return"
                    : "return " + string.Join(", ", returned.Values.Select(value => WriteExpression(value, context))));
                metrics.VerifiedReturnSites += returned.Arity.RuntimeVerified ? 1 : 0;
                break;

            case BranchOperation branch when !controlHandled || nested:
                writer.WriteLine(depth, $"if {WriteExpression(branch.Condition, context)} then");
                foreach (SemanticOperation child in branch.Then)
                    WriteOperation(child, context, depth + 1, controlHandled, nested: true);
                if (branch.Else.Count > 0)
                {
                    writer.WriteLine(depth, "else");
                    foreach (SemanticOperation child in branch.Else)
                        WriteOperation(child, context, depth + 1, controlHandled, nested: true);
                }
                writer.WriteLine(depth, "end");
                break;

            case BranchOperation when controlHandled:
                break;

            case JumpOperation when controlHandled:
                break;

            case JumpOperation jump:
                writer.WriteLine(depth, $"pc = ({WriteExpression(jump.Target, context)}) + 1;");
                break;

            case CloseCapturesOperation close:
                writer.WriteLine(depth, $"close_captured_values(open_cells, registers, {WriteExpression(close.From, context)});");
                break;

            case CaptureVarargsOperation capture:
                writer.WriteLine(depth, $"state[{Quote(capture.ValuesSlot)}] = {{...}};");
                writer.WriteLine(depth, $"state[{Quote(capture.CountSlot)}] = select_value(\"#\", ...);");
                break;

            case ClearRegisterRangeOperation clear:
                writer.WriteLine(depth, $"for register_index = {WriteExpression(clear.From, context)}, {WriteExpression(clear.To, context)} do registers[register_index] = nil end");
                break;

            case GenericForPrepareOperation generic:
                writer.WriteLine(depth, $"prepare_generic_iterator(registers, state, {WriteExpression(generic.BaseRegister, context)});");
                break;

            case NumericForOperation numeric:
                writer.WriteLine(depth, $"for {numeric.IndexName} = {WriteExpression(numeric.From, context)}, {WriteExpression(numeric.To, context)}, {WriteExpression(numeric.Step, context)} do");
                foreach (SemanticOperation child in numeric.Body)
                    WriteOperation(child, context, depth + 1, false);
                writer.WriteLine(depth, "end");
                break;

            case UnresolvedOperation unresolvedOperation:
                writer.WriteLine(depth, $"-- unresolved: {unresolvedOperation.SourceKind}");
                metrics.UnresolvedOperations++;
                break;

            default:
                writer.WriteLine(depth, "-- unresolved operation");
                metrics.UnresolvedOperations++;
                break;
        }
    }

    private void WriteTransition(ulong prototype, BasicBlock block, SemanticOperation? last, int depth)
    {
        SemanticOperation? directTerminal = DirectSequenceTerminal(last);
        if (directTerminal is ReturnOperation)
            return;

        if (last is BranchOperation && block.Successors.Count == 1)
        {
            writer.WriteLine(depth, $"pc = {block.Successors[0].ToString(CultureInfo.InvariantCulture)}");
            return;
        }

        if (last is BranchOperation branch)
        {
            int? trueTarget = branch.TrueTarget;
            int? falseTarget = branch.FalseTarget;
            int fallthrough = block.EndPc + 1;
            if (trueTarget is null && falseTarget is null && block.Successors.Count >= 2)
            {
                trueTarget = block.Successors[0];
                falseTarget = block.Successors[1];
                metrics.SymbolicTransitions++;
            }
            else
            {
                trueTarget ??= block.Successors.FirstOrDefault(item => item != falseTarget, fallthrough);
                falseTarget ??= block.Successors.FirstOrDefault(item => item != trueTarget, fallthrough);
            }
            EmissionContext context = BuildContext(prototype, block.EndPc, depth);
            writer.WriteLine(depth, $"if {WriteExpression(branch.Condition, context)} then");
            writer.WriteLine(depth + 1, $"pc = {TargetText(trueTarget)}");
            writer.WriteLine(depth, "else");
            writer.WriteLine(depth + 1, $"pc = {TargetText(falseTarget)}");
            writer.WriteLine(depth, "end");
            return;
        }

        if (directTerminal is JumpOperation jump)
        {
            writer.WriteLine(depth,
                $"pc = ({WriteExpression(jump.Target, BuildContext(prototype, block.EndPc, depth))}) + 1");
            return;
        }

        if (directTerminal is GenericForPrepareOperation { LoopTarget: not null } generic)
        {
            writer.WriteLine(depth, $"pc = ({WriteExpression(generic.LoopTarget, BuildContext(prototype, block.EndPc, depth))}) + 1");
            return;
        }

        if (block.Successors.Count == 0)
        {
            writer.WriteLine(depth, "pc = nil");
            return;
        }
        if (block.Successors.Count == 1)
        {
            writer.WriteLine(depth, $"pc = {block.Successors[0].ToString(CultureInfo.InvariantCulture)}");
            return;
        }

        metrics.DynamicEdgeSites++;
        TransitionReplaySite? replay = program.TransitionReplays
            .FirstOrDefault(item => item.Prototype == prototype && item.Pc == block.EndPc);
        if (replay is null)
        {
            writer.WriteLine(depth, $"pc = {block.Successors[0].ToString(CultureInfo.InvariantCulture)}");
            metrics.SymbolicTransitions++;
            AddIssue(prototype, block.EndPc, "unresolved_dynamic_edge", "multiple successors have no ordered trace");
            return;
        }

        IReadOnlyList<IReadOnlyList<int>> sequences = replay.Activations.Count > 0
            ? replay.Activations
            : [replay.LegacyTargets];
        string encoded = "{" + string.Join(", ", sequences.Select(sequence =>
            "{" + string.Join(", ", sequence.Select(value => value.ToString(CultureInfo.InvariantCulture))) + "}")) + "}";
        writer.WriteLine(depth,
            $"pc = replay_transition(replay_positions, {Quote($"{prototype}:{block.EndPc}")}, {encoded}, {replay.RepeatFrom.ToString(CultureInfo.InvariantCulture)})");
        metrics.ReplayedDynamicEdgeSites++;
    }

    private static SemanticOperation? DirectSequenceTerminal(SemanticOperation? operation)
    {
        while (operation is SequenceOperation { Operations.Count: > 0 } sequence)
            operation = sequence.Operations[^1];
        return operation;
    }

    private string WriteTarget(AssignmentTarget target, EmissionContext context) => target switch
    {
        RegisterTarget register => $"registers[{WriteExpression(register.Index, context)}]",
        IndexTarget index => $"({WriteExpression(index.Table, context)})[{WriteExpression(index.Index, context)}]",
        NamedTarget named => named.Name,
        UnresolvedTarget unresolvedTarget => UnresolvedTargetText(unresolvedTarget),
        _ => UnresolvedTargetText(new UnresolvedTarget("unknown", target.Provenance)),
    };

    private string UnresolvedTargetText(UnresolvedTarget target)
    {
        metrics.UnresolvedOperations++;
        return $"state[{Quote("unresolved_" + target.SourceKind)}]";
    }

    private string WriteExpression(SemanticExpression expression, EmissionContext context) => expression switch
    {
        NilExpression => "nil",
        BooleanExpression boolean => boolean.Value ? "true" : "false",
        NumberExpression number => NumberLiteral(number.Text),
        StringExpression text => Quote(text.Value),
        IdentifierExpression identifier => identifier.Name,
        RegisterReadExpression register => $"registers[{WriteExpression(register.Index, context)}]",
        CaptureReadExpression capture => WriteCapture(capture),
        IndexExpression index => $"({WriteExpression(index.Table, context)})[{WriteExpression(index.Index, context)}]",
        BinaryExpression binary => $"({WriteExpression(binary.Left, context)} {binary.Operator} {WriteExpression(binary.Right, context)})",
        UnaryExpression unary => $"({unary.Operator} {WriteExpression(unary.Value, context)})",
        TableExpression table => WriteTable(table, context),
        CallExpression call => WriteCall(call, context),
        RegisterRangeExpression range => $"unpack_values(registers, {WriteExpression(range.From, context)}, {WriteExpression(range.To, context)})",
        DynamicLaneExpression lane => context.RuntimeLaneVariable is null
            ? UnresolvedExpressionText(lane)
            : $"{context.RuntimeLaneVariable}[{Quote(lane.Lane)}]",
        LaneExpression lane => WriteExpression(lane.Fallback, context),
        ClosureExpression closure => WriteClosure(closure, context),
        UnresolvedExpression unresolvedExpression => UnresolvedExpressionText(unresolvedExpression),
        _ => UnresolvedExpressionText(new UnresolvedExpression("unknown", "unknown expression", expression.Provenance)),
    };

    private string WriteCapture(CaptureReadExpression capture)
    {
        if (capture.ResolvedKey is int resolved && capture.Proven)
        {
            if (resolved != capture.EncodedKey)
                metrics.CaptureKeyRemaps++;
            return $"captured_values[{resolved.ToString(CultureInfo.InvariantCulture)}]";
        }
        metrics.UnresolvedCaptureKeys++;
        return $"unresolved_capture_cell({capture.Provenance.Sites.FirstOrDefault()?.Prototype ?? 0}, {capture.Provenance.Sites.FirstOrDefault()?.Pc ?? 0}, {capture.EncodedKey.ToString(CultureInfo.InvariantCulture)})";
    }

    private string WriteCall(CallExpression call, EmissionContext context)
    {
        if (call.RuntimeSpecialized)
            metrics.RuntimeSpecializedCallSites++;
        if (call.Function is IndexExpression { Index: StringExpression method } indexed &&
            IsIdentifier(method.Value) && call.Arguments.FirstOrDefault() is SemanticExpression self &&
            self == indexed.Table)
        {
            string methodArguments = string.Join(", ", call.Arguments.Skip(1).Select(argument => WriteExpression(argument, context)));
            return $"{WriteExpression(indexed.Table, context)}:{method.Value}({methodArguments})";
        }
        string function = WriteExpression(call.Function, context);
        string arguments = string.Join(", ", call.Arguments.Select(argument => WriteExpression(argument, context)));
        if (call.RecoveredPrototype is ulong prototype)
            return $"call_recovered({function}, {PrototypeName(prototype)}, captured_values{(arguments.Length == 0 ? string.Empty : ", " + arguments)})";
        return $"({function})({arguments})";
    }

    private string WriteClosure(ClosureExpression closure, EmissionContext context)
    {
        string captures = string.Join(", ", closure.Captures.OrderBy(item => item.Index).Select(capture =>
            $"[{capture.Index.ToString(CultureInfo.InvariantCulture)}] = {WriteCaptureBinding(capture)}"));
        metrics.ClosureConstructors++;
        return $"(function() local callback_captures = {{ {captures} }}; return function(...) return {PrototypeName(closure.Prototype)}(callback_captures, ...) end end)()";
    }

    private string WriteCaptureBinding(CaptureBinding capture)
    {
        if (capture.Kind == CaptureKind.RegisterCell)
            return $"capture_register_cell(open_cells, registers, {capture.Slot.ToString(CultureInfo.InvariantCulture)})";
        if (capture.Kind == CaptureKind.Value)
            return $"registers[{capture.Slot.ToString(CultureInfo.InvariantCulture)}]";
        if (capture.ResolvedIndex is int resolved && capture.Proven)
        {
            if (resolved != capture.Slot)
                metrics.CaptureKeyRemaps++;
            return $"captured_values[{resolved.ToString(CultureInfo.InvariantCulture)}]";
        }
        return $"unresolved_capture_cell(0, 0, {capture.Slot.ToString(CultureInfo.InvariantCulture)})";
    }

    private string WriteTable(TableExpression table, EmissionContext context)
    {
        return "{" + string.Join(", ", table.Fields.Select(field => field.IsList
            ? WriteExpression(field.Value, context)
            : $"[{WriteExpression(field.Key ?? new NilExpression(field.Value.Provenance), context)}] = {WriteExpression(field.Value, context)}")) + "}";
    }

    private string UnresolvedExpressionText(SemanticExpression expression)
    {
        metrics.UnresolvedExpressions++;
        return "nil";
    }

    private void WriteRoot()
    {
        if (program.Root is null || program.Prototypes.All(item => item.RuntimeId != program.Root.Prototype))
        {
            AddIssue(0, 0, "missing_payload_root", "payload root is missing");
            writer.WriteLine(0, "return nil");
            return;
        }

        List<string> rootArguments = [];
        if (program.Root.Arguments is { Count: > 0 } arguments)
        {
            for (int index = 0; index < arguments.Count; index++)
            {
                string name = $"root_argument_{index + 1}";
                WriteRootArgument(name, arguments[index]);
                rootArguments.Add(name);
            }
        }
        else
        {
            writer.WriteLine(0, "local root_argument_1 = { [1] = rawset, [2] = environment, [12] = environment.coroutine, [52] = environment.debug }");
            rootArguments.Add("root_argument_1");
        }
        writer.WriteLine(0, "local root_captures = {}");
        writer.WriteLine(0, "local root_registers = {}");
        writer.WriteLine(0, "local root_inherited_registers = {}");
        writer.WriteLine(0, "local root_open_cells = {}");
        if (program.Root.Closure is ClosureDescriptor closure)
            foreach (CaptureBinding capture in closure.Captures.OrderBy(item => item.Index))
            {
                string index = capture.Index.ToString(CultureInfo.InvariantCulture);
                string slot = capture.Slot.ToString(CultureInfo.InvariantCulture);
                if (capture.Kind is CaptureKind.RegisterCell or CaptureKind.ParentCell)
                {
                    string storage = capture.Kind == CaptureKind.RegisterCell
                        ? "root_registers"
                        : "root_inherited_registers";
                    writer.WriteLine(0, $"{storage}[{slot}] = unresolved_helper");
                    writer.WriteLine(0, $"root_captures[{index}] = capture_register_cell(root_open_cells, {storage}, {slot})");
                }
                else
                {
                    writer.WriteLine(0, $"root_captures[{index}] = unresolved_helper");
                }
                AddIssue(program.Root.Prototype, 0, "unresolved_root_capture",
                    $"root capture {capture.Index} has no value snapshot");
            }
        writer.WriteLine(0, $"return {PrototypeName(program.Root.Prototype)}(root_captures, {string.Join(", ", rootArguments)})");
    }

    private void WriteRootArgument(string name, SemanticExpression argument)
    {
        EmissionContext context = BuildContext(program.Root?.Prototype ?? 0, 0, 0);
        if (argument is not TableExpression table)
        {
            writer.WriteLine(0, $"local {name} = {WriteExpression(argument, context)}");
            return;
        }

        writer.WriteLine(0, $"local {name} = {{");
        foreach (TableField field in table.Fields)
        {
            string value = WriteExpression(field.Value, context);
            if (field.IsList)
                writer.WriteLine(1, $"{value},");
            else
                writer.WriteLine(1, $"[{WriteExpression(field.Key ?? new NilExpression(field.Value.Provenance), context)}] = {value},");
        }
        writer.WriteLine(0, "}");
    }

    private void AddIssue(ulong prototype, int pc, string code, string message) =>
        unresolved.Add(new UnresolvedFact("emit", code, message, Provenance.At(prototype, pc)));

    private static string TargetText(int? target) => target?.ToString(CultureInfo.InvariantCulture) ?? "nil";
    private static string PrototypeName(ulong id) => $"recovered_routine_{id.ToString(CultureInfo.InvariantCulture)}";
    private static bool IsIdentifier(string value) => value.Length > 0 &&
        (char.IsLetter(value[0]) || value[0] == '_') &&
        value.Skip(1).All(character => char.IsLetterOrDigit(character) || character == '_');

    private static string NumberLiteral(string value) => value.ToLowerInvariant() switch
    {
        "nan" => "(0 / 0)",
        "inf" or "infinity" => "math.huge",
        "-inf" or "-infinity" => "-math.huge",
        _ => double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out _) ? value : "0",
    };

    private static string Quote(string value)
    {
        StringBuilder result = new(value.Length + 2);
        result.Append('"');
        foreach (char character in value)
        {
            result.Append(character switch
            {
                '\\' => "\\\\",
                '"' => "\\\"",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                _ when char.IsControl(character) => $"\\{(int)character:D3}",
                _ => character.ToString(),
            });
        }
        result.Append('"');
        return result.ToString();
    }

    private static bool PrimitiveEquals(SemanticExpression left, SemanticExpression right) => (left, right) switch
    {
        (NilExpression, NilExpression) => true,
        (BooleanExpression a, BooleanExpression b) => a.Value == b.Value,
        (NumberExpression a, NumberExpression b) => a.Text == b.Text,
        (StringExpression a, StringExpression b) => a.Value == b.Value,
        _ => false,
    };

    private sealed record EmissionContext(
        ulong Prototype,
        int Pc,
        int Depth,
        LaneReplaySite? Replay,
        IReadOnlySet<string> DynamicLanes,
        string? RuntimeLaneVariable);

    private sealed class MetricCounter
    {
        public int Prototypes;
        public int Blocks;
        public int Operations;
        public int UnresolvedExpressions;
        public int UnresolvedOperations;
        public int SymbolicTransitions;
        public int DynamicEdgeSites;
        public int ReplayedDynamicEdgeSites;
        public int DynamicLaneReplaySites;
        public int SpecializedStableLanes;
        public int ClosureConstructors;
        public int UnresolvedClosureDescriptors;
        public int CaptureKeyRemaps;
        public int UnresolvedCaptureKeys;
        public int RuntimeSpecializedCallSites;
        public int VerifiedReturnSites;
        public int ReturnArityMismatches;

        public CandidateMetrics ToMetrics() => new()
        {
            Prototypes = Prototypes,
            Blocks = Blocks,
            Operations = Operations,
            UnsupportedExpressions = UnresolvedExpressions,
            UnsupportedOperations = UnresolvedOperations,
            SymbolicTransitions = SymbolicTransitions,
            DynamicEdgeSites = DynamicEdgeSites,
            ReplayedDynamicEdgeSites = ReplayedDynamicEdgeSites,
            DynamicLaneReplaySites = DynamicLaneReplaySites,
            SpecializedStableLanes = SpecializedStableLanes,
            ClosureConstructors = ClosureConstructors,
            UnresolvedClosureDescriptors = UnresolvedClosureDescriptors,
            CaptureKeyRemaps = CaptureKeyRemaps,
            UnresolvedCaptureKeys = UnresolvedCaptureKeys,
            RuntimeSpecializedCallSites = RuntimeSpecializedCallSites,
            VerifiedReturnSites = VerifiedReturnSites,
            ReturnArityMismatches = ReturnArityMismatches,
        };
    }
}
