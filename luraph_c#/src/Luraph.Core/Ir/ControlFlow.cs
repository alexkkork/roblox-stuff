namespace Luraph.Core.Ir;

public enum BlockTerminatorKind
{
    Fallthrough,
    Branch,
    Jump,
    Return,
    Dynamic,
    Stop,
}

public sealed record BasicBlock(
    string Id,
    int StartPc,
    int EndPc,
    bool Reachable,
    BlockTerminatorKind Terminator,
    IReadOnlyList<int> Successors);

public sealed record PrototypeControlFlow(
    ulong RuntimeId,
    int EntryPc,
    IReadOnlyList<BasicBlock> Blocks);

public sealed record ControlFlowGraph(
    IReadOnlyList<PrototypeControlFlow> Prototypes,
    IReadOnlyList<UnresolvedFact> Unresolved);

public sealed record GraphValidationResult(
    bool Valid,
    IReadOnlyList<UnresolvedFact> Issues);
