using System.Text.Json.Serialization;

namespace Luraph.Core.Ir;

public enum EvidenceKind
{
    Static,
    Runtime,
    Inferred,
}

public enum CaptureKind
{
    RegisterCell = 0,
    Value = 1,
    ParentCell = 2,
}

public sealed record SourceSite(ulong Prototype, int Pc, int? SourceLine = null);

public sealed record Provenance(
    IReadOnlyList<SourceSite> Sites,
    EvidenceKind Evidence = EvidenceKind.Static)
{
    public static Provenance At(ulong prototype, int pc, EvidenceKind evidence = EvidenceKind.Static) =>
        new([new SourceSite(prototype, pc)], evidence);

    public static Provenance Empty { get; } = new([], EvidenceKind.Inferred);
}

public sealed record ResultArity(int? Exact, bool ExpandsFinal = false, bool RuntimeVerified = false)
{
    public static ResultArity Unknown { get; } = new((int?)null);
    public static ResultArity None { get; } = new(0);
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "$kind")]
[JsonDerivedType(typeof(NilExpression), "nil")]
[JsonDerivedType(typeof(BooleanExpression), "boolean")]
[JsonDerivedType(typeof(NumberExpression), "number")]
[JsonDerivedType(typeof(StringExpression), "string")]
[JsonDerivedType(typeof(IdentifierExpression), "identifier")]
[JsonDerivedType(typeof(RegisterReadExpression), "register_read")]
[JsonDerivedType(typeof(CaptureReadExpression), "capture_read")]
[JsonDerivedType(typeof(IndexExpression), "index")]
[JsonDerivedType(typeof(BinaryExpression), "binary")]
[JsonDerivedType(typeof(UnaryExpression), "unary")]
[JsonDerivedType(typeof(TableExpression), "table")]
[JsonDerivedType(typeof(CallExpression), "call")]
[JsonDerivedType(typeof(RegisterRangeExpression), "register_range")]
[JsonDerivedType(typeof(LaneExpression), "lane")]
[JsonDerivedType(typeof(DynamicLaneExpression), "dynamic_lane")]
[JsonDerivedType(typeof(ClosureExpression), "closure")]
[JsonDerivedType(typeof(UnresolvedExpression), "unresolved")]
public abstract record SemanticExpression(Provenance Provenance);

public sealed record NilExpression(Provenance Provenance) : SemanticExpression(Provenance);

public sealed record BooleanExpression(bool Value, Provenance Provenance) : SemanticExpression(Provenance);

public sealed record NumberExpression(string Text, Provenance Provenance) : SemanticExpression(Provenance);

public sealed record StringExpression(string Value, Provenance Provenance) : SemanticExpression(Provenance);

public sealed record IdentifierExpression(string Name, Provenance Provenance) : SemanticExpression(Provenance);

public sealed record RegisterReadExpression(SemanticExpression Index, Provenance Provenance) : SemanticExpression(Provenance);

public sealed record CaptureReadExpression(
    int EncodedKey,
    int? ResolvedKey,
    string? Lane,
    bool Proven,
    Provenance Provenance) : SemanticExpression(Provenance);

public sealed record IndexExpression(
    SemanticExpression Table,
    SemanticExpression Index,
    bool IsCaptureCell,
    Provenance Provenance) : SemanticExpression(Provenance);

public sealed record BinaryExpression(
    string Operator,
    SemanticExpression Left,
    SemanticExpression Right,
    Provenance Provenance) : SemanticExpression(Provenance);

public sealed record UnaryExpression(
    string Operator,
    SemanticExpression Value,
    Provenance Provenance) : SemanticExpression(Provenance);

public sealed record TableField(
    SemanticExpression? Key,
    SemanticExpression Value,
    bool IsList);

public sealed record TableExpression(
    IReadOnlyList<TableField> Fields,
    Provenance Provenance) : SemanticExpression(Provenance);

public sealed record CallExpression(
    SemanticExpression Function,
    IReadOnlyList<SemanticExpression> Arguments,
    ResultArity Results,
    ulong? RecoveredPrototype,
    Provenance Provenance,
    bool RuntimeSpecialized = false) : SemanticExpression(Provenance);

public sealed record RegisterRangeExpression(
    SemanticExpression From,
    SemanticExpression To,
    Provenance Provenance) : SemanticExpression(Provenance);

public sealed record LaneExpression(
    string Lane,
    SemanticExpression Fallback,
    Provenance Provenance) : SemanticExpression(Provenance);

public sealed record DynamicLaneExpression(
    string Lane,
    string ReplayKey,
    Provenance Provenance) : SemanticExpression(Provenance);

public sealed record ClosureExpression(
    ulong Prototype,
    IReadOnlyList<CaptureBinding> Captures,
    Provenance Provenance) : SemanticExpression(Provenance);

public sealed record UnresolvedExpression(
    string SourceKind,
    string Reason,
    Provenance Provenance) : SemanticExpression(Provenance);

[JsonPolymorphic(TypeDiscriminatorPropertyName = "$kind")]
[JsonDerivedType(typeof(RegisterTarget), "register")]
[JsonDerivedType(typeof(IndexTarget), "index")]
[JsonDerivedType(typeof(NamedTarget), "named")]
[JsonDerivedType(typeof(UnresolvedTarget), "unresolved")]
public abstract record AssignmentTarget(Provenance Provenance);

public sealed record RegisterTarget(SemanticExpression Index, Provenance Provenance) : AssignmentTarget(Provenance);

public sealed record IndexTarget(
    SemanticExpression Table,
    SemanticExpression Index,
    Provenance Provenance) : AssignmentTarget(Provenance);

public sealed record NamedTarget(string Name, Provenance Provenance) : AssignmentTarget(Provenance);

public sealed record UnresolvedTarget(string SourceKind, Provenance Provenance) : AssignmentTarget(Provenance);

[JsonPolymorphic(TypeDiscriminatorPropertyName = "$kind")]
[JsonDerivedType(typeof(AssignOperation), "assign")]
[JsonDerivedType(typeof(CompoundAssignOperation), "compound_assign")]
[JsonDerivedType(typeof(ExpressionOperation), "expression")]
[JsonDerivedType(typeof(ReturnOperation), "return")]
[JsonDerivedType(typeof(BranchOperation), "branch")]
[JsonDerivedType(typeof(JumpOperation), "jump")]
[JsonDerivedType(typeof(CloseCapturesOperation), "close_captures")]
[JsonDerivedType(typeof(CaptureVarargsOperation), "capture_varargs")]
[JsonDerivedType(typeof(PrepareRegisterClearOperation), "prepare_register_clear")]
[JsonDerivedType(typeof(ClearPreparedRegisterRangeOperation), "clear_prepared_register_range")]
[JsonDerivedType(typeof(ClearRegisterRangeOperation), "clear_register_range")]
[JsonDerivedType(typeof(GenericForPrepareOperation), "generic_for_prepare")]
[JsonDerivedType(typeof(NumericForOperation), "numeric_for")]
[JsonDerivedType(typeof(SequenceOperation), "sequence")]
[JsonDerivedType(typeof(UnresolvedOperation), "unresolved")]
public abstract record SemanticOperation(Provenance Provenance);

public sealed record AssignOperation(
    IReadOnlyList<AssignmentTarget> Targets,
    IReadOnlyList<SemanticExpression> Values,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record CompoundAssignOperation(
    AssignmentTarget Target,
    string Operator,
    SemanticExpression Value,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record ExpressionOperation(
    SemanticExpression Expression,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record ReturnOperation(
    IReadOnlyList<SemanticExpression> Values,
    ResultArity Arity,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record BranchOperation(
    SemanticExpression Condition,
    IReadOnlyList<SemanticOperation> Then,
    IReadOnlyList<SemanticOperation> Else,
    int? TrueTarget,
    int? FalseTarget,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record JumpOperation(
    SemanticExpression Target,
    int? StaticTarget,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record CloseCapturesOperation(
    SemanticExpression From,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record CaptureVarargsOperation(
    string ValuesSlot,
    string CountSlot,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record PrepareRegisterClearOperation(
    string State,
    SemanticExpression From,
    SemanticExpression To,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record ClearPreparedRegisterRangeOperation(
    string State,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record ClearRegisterRangeOperation(
    SemanticExpression From,
    SemanticExpression To,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record GenericForPrepareOperation(
    SemanticExpression BaseRegister,
    SemanticExpression? LoopTarget,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record NumericForOperation(
    string IndexName,
    SemanticExpression From,
    SemanticExpression To,
    SemanticExpression Step,
    IReadOnlyList<SemanticOperation> Body,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record SequenceOperation(
    IReadOnlyList<SemanticOperation> Operations,
    bool ProtectorInternal,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record UnresolvedOperation(
    string SourceKind,
    string Reason,
    Provenance Provenance) : SemanticOperation(Provenance);

public sealed record CaptureBinding(
    int Index,
    CaptureKind Kind,
    int Slot,
    int? ResolvedIndex = null,
    bool Proven = false);

public sealed record ClosureDescriptor(
    bool Complete,
    ulong TargetPrototype,
    int DestinationRegister,
    IReadOnlyList<CaptureBinding> Captures,
    Provenance Provenance);

public sealed record SemanticInstruction(
    int Pc,
    long Opcode,
    SemanticOperation Operation,
    ClosureDescriptor? Closure,
    IReadOnlyDictionary<string, SemanticExpression> StaticLanes,
    IReadOnlyDictionary<string, SemanticExpression> Lanes,
    Provenance Provenance);

public sealed record ReplayFrame(IReadOnlyDictionary<string, SemanticExpression> Lanes);

public sealed record ReplayActivation(IReadOnlyList<ReplayFrame> Frames);

public sealed record LaneReplaySite(
    ulong Prototype,
    int Pc,
    IReadOnlySet<string> Lanes,
    IReadOnlyList<ReplayActivation> Activations,
    int RepeatFrom,
    Provenance Provenance);

public sealed record TransitionReplaySite(
    ulong Prototype,
    int Pc,
    IReadOnlyList<int> LegacyTargets,
    IReadOnlyList<IReadOnlyList<int>> Activations,
    int RepeatFrom,
    Provenance Provenance);

public sealed record SemanticPrototype(
    ulong RuntimeId,
    int EntryPc,
    IReadOnlyList<SemanticInstruction> Instructions,
    IReadOnlySet<int> ObservedCaptureIndices,
    IReadOnlyList<string>? Locals = null);

public sealed record PayloadRoot(
    ulong Prototype,
    ClosureDescriptor? Closure,
    IReadOnlyList<SemanticExpression>? Arguments = null);

public sealed record PrototypeCallEdge(
    ulong CallerPrototype,
    int CallerPc,
    ulong CalleePrototype,
    IReadOnlyList<SemanticExpression>? StableArguments = null,
    bool ArgumentsComplete = false);

public sealed record UnresolvedFact(string Stage, string Code, string Message, Provenance Provenance);

public sealed record SemanticProgram(
    PayloadRoot? Root,
    IReadOnlyList<SemanticPrototype> Prototypes,
    IReadOnlyList<PrototypeCallEdge> CallEdges,
    IReadOnlyList<LaneReplaySite> LaneReplays,
    IReadOnlyList<TransitionReplaySite> TransitionReplays,
    IReadOnlyList<UnresolvedFact> Unresolved);
