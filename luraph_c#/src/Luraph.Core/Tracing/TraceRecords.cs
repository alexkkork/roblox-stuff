namespace Luraph.Core.Tracing;

public abstract record LuraphTraceRecord(int Line);

public sealed record CallTraceRecord(
    int Line,
    ulong VmCount,
    ulong Activation,
    ulong? CallerActivation,
    long? CallerPc,
    long? CallerOpcode,
    long Pc,
    long Opcode,
    long? RegisterIndex,
    string Target,
    IReadOnlyList<RuntimeValue> Arguments) : LuraphTraceRecord(Line);

public sealed record VmOperandSnapshot(
    long? RegisterIndex,
    string Type,
    string? Value,
    string? FunctionName);

public sealed record VmTraceRecord(
    int Line,
    ulong VmCount,
    ulong Activation,
    ulong? CallerActivation,
    long? CallerPc,
    long? CallerOpcode,
    long Pc,
    long Opcode,
    VmOperandSnapshot? Primary,
    VmOperandSnapshot? Next,
    VmOperandSnapshot? T,
    VmOperandSnapshot? U,
    string? LaneF,
    string? LaneT,
    string? LaneX) : LuraphTraceRecord(Line);

public sealed record ActivationTraceRecord(
    int Line,
    ulong VmCount,
    ulong Activation,
    ulong? CallerActivation,
    long? CallerPc,
    long? CallerOpcode,
    int ArgumentCount,
    string? ArgumentSummary) : LuraphTraceRecord(Line);

public sealed record PrototypeTraceRecord(
    int Line,
    ulong Prototype,
    int InstructionCount,
    IReadOnlyList<string> Lanes) : LuraphTraceRecord(Line);

public sealed record PrototypeObjectTraceRecord(
    int Line,
    ulong Prototype,
    ulong ObjectId) : LuraphTraceRecord(Line);

public sealed record InstructionTraceRecord(
    int Line,
    ulong Prototype,
    int Pc,
    long Opcode,
    IReadOnlyDictionary<string, RuntimeValue> Lanes) : LuraphTraceRecord(Line);

public sealed record LaneTopTraceRecord(
    int Line,
    ulong Prototype,
    int Pc,
    string LaneName,
    RuntimeValue Key,
    RuntimeValue Value) : LuraphTraceRecord(Line);

public sealed record LaneTableTraceRecord(
    int Line,
    ulong Prototype,
    int Pc,
    string LaneName,
    int Depth,
    string Path,
    RuntimeValue Key,
    RuntimeValue Value) : LuraphTraceRecord(Line);

public sealed record ActivationPrototypeTraceRecord(
    int Line,
    ulong Activation,
    ulong Prototype,
    ulong? CallerActivation,
    long? CallerPc,
    long? CallerOpcode,
    int ArgumentCount,
    long? EntryPc,
    IReadOnlyList<RuntimeValue> Arguments,
    ulong? EntryVmCount) : LuraphTraceRecord(Line);

public sealed record ActivationArgumentTableTraceRecord(
    int Line,
    ulong Activation,
    ulong Prototype,
    int ArgumentIndex,
    RuntimeValue Key,
    RuntimeValue Value) : LuraphTraceRecord(Line);

public sealed record CaptureDomainTraceRecord(
    int Line,
    ulong Activation,
    ulong Prototype,
    bool Complete,
    IReadOnlyList<int> Indices) : LuraphTraceRecord(Line);

public sealed record RegisterWrite(int Register, RuntimeValue Value);

public sealed record StepTraceRecord(
    int Line,
    ulong VmCount,
    ulong Activation,
    long Pc,
    long Opcode,
    long NextPc,
    IReadOnlyList<RegisterWrite> RegisterWrites,
    IReadOnlyDictionary<string, RuntimeValue> RuntimeLanes) : LuraphTraceRecord(Line);

public sealed record ReturnTraceRecord(
    int Line,
    ulong VmCount,
    ulong Activation,
    long Pc,
    long Opcode,
    int Arity,
    IReadOnlyList<RuntimeValue> Values) : LuraphTraceRecord(Line)
{
    public bool Complete => Arity == Values.Count;
}
