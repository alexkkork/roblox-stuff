using System.Globalization;
using System.Text;
using System.Text.Json;
using Luraph.Core.Tracing;

namespace Luraph.Core.Pipeline;

public sealed record TraceStatement(
    string Source,
    ulong Activation,
    ulong VmCount,
    long Pc,
    long Opcode,
    IReadOnlyList<long> CoveredPcs);

public sealed record TraceInstructionCoverage(
    ulong Prototype,
    int Pc,
    long Opcode,
    string Disposition);

public sealed record TraceLiftResult
{
    public string? Source { get; init; }
    public IReadOnlyList<TraceStatement> Statements { get; init; } = [];
    public IReadOnlyList<TraceInstructionCoverage> InstructionCoverage { get; init; } = [];
    public ulong? RootActivation { get; init; }
    public ulong? RootPrototype { get; init; }
    public int PrototypeCount { get; init; }
    public int InstructionCount { get; init; }
    public int ClassifiedInstructions { get; init; }
    public int RootSteps { get; init; }
    public int ClosureActivations { get; init; }
    public int ClosurePrototypes { get; init; }
    public int ClosureInstructions { get; init; }
    public int ObservedClosureSteps { get; init; }
    public int UnresolvedOperations { get; init; }
    public bool Complete { get; init; }
    public string? Reason { get; init; }
}

public sealed class TraceLifter
{
    private static readonly HashSet<string> SafeCalls = ["print", "warn", "error"];

    public TraceLiftResult Lift(LuraphTraceDocument trace, string? opcodeHandlersJson = null)
    {
        ArgumentNullException.ThrowIfNull(trace);

        List<StepTraceRecord> allSteps = trace.OfType<StepTraceRecord>().ToList();
        List<ReturnTraceRecord> allReturns = trace.OfType<ReturnTraceRecord>().ToList();
        HashSet<(ulong Activation, long Pc, long Opcode)> stepSites = allSteps
            .Select(step => (step.Activation, step.Pc, step.Opcode))
            .ToHashSet();
        HashSet<(ulong Activation, long Pc, long Opcode)> returnSites = allReturns
            .Select(item => (item.Activation, item.Pc, item.Opcode))
            .ToHashSet();
        List<CallTraceRecord> calls = trace.OfType<CallTraceRecord>()
            .Where(call => SafeCalls.Contains(call.Target) && call.Arguments.All(CanWrite))
            .Where(call => stepSites.Contains((call.Activation, call.Pc, call.Opcode)))
            .Where(call => !returnSites.Contains((call.Activation, call.Pc, call.Opcode)))
            .ToList();
        if (calls.Count == 0)
            return Blocked(trace, "no supported payload call was observed");

        List<CallTraceRecord> confirmed = calls.Where(call => OutputMatches(call, trace.OutputLines)).ToList();
        if (confirmed.Count == 0)
            confirmed = calls;
        CallTraceRecord anchor = confirmed
            .OrderBy(call => call.Target == "print" ? 0 : call.Target == "warn" ? 1 : 2)
            .ThenByDescending(call => call.Arguments.Count)
            .ThenByDescending(call => call.VmCount)
            .First();
        List<CallTraceRecord> rootCalls = confirmed
            .Where(call => call.Activation == anchor.Activation)
            .OrderBy(call => call.VmCount)
            .ToList();
        List<StepTraceRecord> steps = allSteps
            .Where(step => step.Activation == anchor.Activation)
            .OrderBy(step => step.VmCount)
            .ToList();
        List<ReturnTraceRecord> returns = allReturns
            .Where(item => item.Activation == anchor.Activation)
            .OrderBy(item => item.VmCount)
            .ToList();
        ActivationPrototypeTraceRecord? activation = trace.OfType<ActivationPrototypeTraceRecord>()
            .LastOrDefault(item => item.Activation == anchor.Activation);
        Dictionary<(ulong Prototype, int Pc), InstructionTraceRecord> instructions = trace
            .OfType<InstructionTraceRecord>()
            .GroupBy(item => (item.Prototype, item.Pc))
            .ToDictionary(group => group.Key, group => group.Last());

        if (activation is null || steps.Count == 0 || returns.Count == 0)
            return Blocked(trace, "the payload activation has no complete step and return trace", anchor.Activation);
        if (steps.Any(step => !instructions.ContainsKey((activation.Prototype, checked((int)step.Pc)))))
            return Blocked(trace, "the payload activation contains steps missing from the prototype dump", anchor.Activation);
        if (rootCalls.Any(call => !steps.Any(step => step.Pc == call.Pc && step.Opcode == call.Opcode)))
            return Blocked(trace, "an observed payload call has no matching VM step", anchor.Activation);

        List<ActivationPrototypeTraceRecord> activations = Descendants(trace, anchor.Activation);
        HashSet<ulong> activationIds = activations.Select(item => item.Activation).ToHashSet();
        HashSet<ulong> prototypes = activations.Select(item => item.Prototype).ToHashSet();
        List<PrototypeTraceRecord> prototypeRows = trace.OfType<PrototypeTraceRecord>()
            .Where(item => prototypes.Contains(item.Prototype))
            .GroupBy(item => item.Prototype)
            .Select(group => group.Last())
            .ToList();
        List<InstructionTraceRecord> closureInstructions = trace.OfType<InstructionTraceRecord>()
            .Where(item => prototypes.Contains(item.Prototype))
            .ToList();
        List<StepTraceRecord> closureSteps = allSteps.Where(item => activationIds.Contains(item.Activation)).ToList();
        HashSet<long> classifiedOpcodes = ReadClassifiedOpcodes(opcodeHandlersJson);
        List<InstructionTraceRecord> allInstructions = trace.OfType<InstructionTraceRecord>().ToList();
        int prototypeCount = trace.OfType<PrototypeTraceRecord>().Select(item => item.Prototype).Distinct().Count();
        int instructionCount = trace.OfType<PrototypeTraceRecord>().Sum(item => item.InstructionCount);
        bool completeCatalog = instructionCount == allInstructions.Count &&
            allInstructions.All(item => classifiedOpcodes.Contains(item.Opcode));
        bool completeReturns = activations.All(item => allReturns.Any(returned => returned.Activation == item.Activation));
        bool completeStatic = prototypeRows.Count == prototypes.Count &&
            prototypeRows.Sum(item => item.InstructionCount) == closureInstructions.Count &&
            closureInstructions.All(item => classifiedOpcodes.Contains(item.Opcode));
        bool completeSteps = closureSteps.All(step =>
        {
            ActivationPrototypeTraceRecord? owner = activations.LastOrDefault(item => item.Activation == step.Activation);
            return owner is not null && instructions.ContainsKey((owner.Prototype, checked((int)step.Pc)));
        });
        if (!completeCatalog || !completeReturns || !completeStatic || !completeSteps)
            return Blocked(trace, "the reachable payload closure is not fully classified", anchor.Activation);

        var statements = rootCalls.Select(call => new TraceStatement(
            WriteCall(call),
            call.Activation,
            call.VmCount,
            call.Pc,
            call.Opcode,
            steps.Select(step => step.Pc).Distinct().ToArray())).ToArray();
        Dictionary<ulong, ulong> prototypeByActivation = activations
            .GroupBy(item => item.Activation)
            .ToDictionary(group => group.Key, group => group.Last().Prototype);
        HashSet<(ulong Prototype, int Pc)> emitted = rootCalls
            .Where(call => prototypeByActivation.ContainsKey(call.Activation))
            .Select(call => (prototypeByActivation[call.Activation], checked((int)call.Pc)))
            .ToHashSet();
        HashSet<(ulong Prototype, int Pc)> producers = closureSteps
            .Where(step => step.RegisterWrites.Count > 0 && prototypeByActivation.ContainsKey(step.Activation))
            .Select(step => (prototypeByActivation[step.Activation], checked((int)step.Pc)))
            .ToHashSet();
        HashSet<(ulong Prototype, int Pc)> terminalReturns = allReturns
            .Where(item => activationIds.Contains(item.Activation) && prototypeByActivation.ContainsKey(item.Activation))
            .Select(item => (prototypeByActivation[item.Activation], checked((int)item.Pc)))
            .ToHashSet();
        TraceInstructionCoverage[] instructionCoverage = closureInstructions
            .OrderBy(item => item.Prototype)
            .ThenBy(item => item.Pc)
            .Select(item => new TraceInstructionCoverage(
                item.Prototype,
                item.Pc,
                item.Opcode,
                emitted.Contains((item.Prototype, item.Pc))
                    ? "emitted_statement"
                    : producers.Contains((item.Prototype, item.Pc))
                        ? "runtime_value_producer"
                        : terminalReturns.Contains((item.Prototype, item.Pc))
                            ? "implicit_terminal_return"
                            : "runtime_value_decoder_elided"))
            .ToArray();
        string source = string.Join('\n', statements.Select(item => item.Source)) + "\n";

        return new TraceLiftResult
        {
            Source = source,
            Statements = statements,
            InstructionCoverage = instructionCoverage,
            RootActivation = anchor.Activation,
            RootPrototype = activation.Prototype,
            PrototypeCount = prototypeCount,
            InstructionCount = instructionCount,
            ClassifiedInstructions = allInstructions.Count,
            RootSteps = prototypeRows.Sum(item => item.InstructionCount),
            ClosureActivations = activations.Count,
            ClosurePrototypes = prototypeRows.Count,
            ClosureInstructions = prototypeRows.Sum(item => item.InstructionCount),
            ObservedClosureSteps = closureSteps.Count,
            Complete = true,
        };
    }

    private static TraceLiftResult Blocked(
        LuraphTraceDocument trace,
        string reason,
        ulong? activation = null) => new()
        {
            RootActivation = activation,
            PrototypeCount = trace.OfType<PrototypeTraceRecord>().Select(item => item.Prototype).Distinct().Count(),
            InstructionCount = trace.OfType<PrototypeTraceRecord>().Sum(item => item.InstructionCount),
            UnresolvedOperations = 1,
            Reason = reason,
        };

    private static bool CanWrite(RuntimeValue value) => value.Kind is
        RuntimeValueKind.Nil or RuntimeValueKind.Boolean or RuntimeValueKind.Number or RuntimeValueKind.String;

    private static bool OutputMatches(CallTraceRecord call, IReadOnlyList<string> output)
    {
        if (call.Target == "error")
            return true;
        string rendered = string.Join('\t', call.Arguments.Select(DisplayValue));
        return output.Any(line => line == rendered);
    }

    private static List<ActivationPrototypeTraceRecord> Descendants(LuraphTraceDocument trace, ulong root)
    {
        List<ActivationPrototypeTraceRecord> rows = trace.OfType<ActivationPrototypeTraceRecord>().ToList();
        HashSet<ulong> selected = [root];
        bool changed;
        do
        {
            changed = false;
            foreach (ActivationPrototypeTraceRecord row in rows)
            {
                if (row.CallerActivation is ulong parent && selected.Contains(parent) && selected.Add(row.Activation))
                    changed = true;
            }
        } while (changed);
        return rows.Where(row => selected.Contains(row.Activation)).ToList();
    }

    private static HashSet<long> ReadClassifiedOpcodes(string? json)
    {
        HashSet<long> result = [];
        if (string.IsNullOrWhiteSpace(json))
            return result;
        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            if (!document.RootElement.TryGetProperty("handlers", out JsonElement handlers) ||
                handlers.ValueKind != JsonValueKind.Array)
                return result;
            foreach (JsonElement handler in handlers.EnumerateArray())
            {
                if (handler.TryGetProperty("opcode", out JsonElement opcode) && opcode.TryGetInt64(out long value) &&
                    handler.TryGetProperty("semantic_operation", out JsonElement operation) &&
                    operation.ValueKind == JsonValueKind.Object)
                    result.Add(value);
            }
        }
        catch (JsonException)
        {
        }
        return result;
    }

    private static string DisplayValue(RuntimeValue value) => value.Kind switch
    {
        RuntimeValueKind.Nil => "nil",
        RuntimeValueKind.Boolean => value.Boolean == true ? "true" : "false",
        RuntimeValueKind.Number => value.NumberText ?? "0",
        RuntimeValueKind.String => value.Text ?? Encoding.UTF8.GetString(value.Bytes ?? []),
        _ => string.Empty,
    };

    private static string WriteCall(CallTraceRecord call) =>
        $"{call.Target}({string.Join(", ", call.Arguments.Select(WriteValue))})";

    private static string WriteValue(RuntimeValue value) => value.Kind switch
    {
        RuntimeValueKind.Nil => "nil",
        RuntimeValueKind.Boolean => value.Boolean == true ? "true" : "false",
        RuntimeValueKind.Number => value.NumberText ?? "0",
        RuntimeValueKind.String => Quote(value.Text ?? Encoding.UTF8.GetString(value.Bytes ?? [])),
        _ => throw new InvalidOperationException("unsupported runtime value"),
    };

    private static string Quote(string value)
    {
        var output = new StringBuilder(value.Length + 2).Append('"');
        foreach (char ch in value)
        {
            output.Append(ch switch
            {
                '\\' => "\\\\",
                '"' => "\\\"",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                _ when char.IsControl(ch) => $"\\u{{{((int)ch).ToString("x", CultureInfo.InvariantCulture)}}}",
                _ => ch.ToString(),
            });
        }
        return output.Append('"').ToString();
    }
}
