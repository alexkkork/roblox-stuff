using Luraph.Core.Ir;

namespace Luraph.Core.Lifting;

public sealed class ControlFlowValidator
{
    public GraphValidationResult Validate(ControlFlowGraph graph)
    {
        List<UnresolvedFact> issues = [.. graph.Unresolved];
        HashSet<ulong> prototypeIds = [];

        foreach (PrototypeControlFlow prototype in graph.Prototypes)
        {
            if (!prototypeIds.Add(prototype.RuntimeId))
                issues.Add(Issue(prototype.RuntimeId, prototype.EntryPc, "duplicate_prototype", "CFG prototype id is duplicated"));

            Dictionary<int, BasicBlock> starts = [];
            int previousEnd = 0;
            foreach (BasicBlock block in prototype.Blocks.OrderBy(item => item.StartPc))
            {
                if (block.StartPc <= 0 || block.EndPc < block.StartPc)
                    issues.Add(Issue(prototype.RuntimeId, block.StartPc, "invalid_block_range", "CFG block range is invalid"));
                if (!starts.TryAdd(block.StartPc, block))
                    issues.Add(Issue(prototype.RuntimeId, block.StartPc, "duplicate_block", "CFG block start is duplicated"));
                if (previousEnd >= block.StartPc)
                    issues.Add(Issue(prototype.RuntimeId, block.StartPc, "overlapping_blocks", "CFG blocks overlap"));
                previousEnd = Math.Max(previousEnd, block.EndPc);
            }

            if (!starts.ContainsKey(prototype.EntryPc))
                issues.Add(Issue(prototype.RuntimeId, prototype.EntryPc, "missing_entry", "CFG entry does not name a block"));

            foreach (BasicBlock block in prototype.Blocks)
            {
                foreach (int successor in block.Successors)
                    if (!starts.ContainsKey(successor))
                        issues.Add(Issue(prototype.RuntimeId, block.EndPc, "invalid_edge", $"CFG edge targets missing pc {successor}"));

                if (block.Terminator == BlockTerminatorKind.Return && block.Successors.Count > 0)
                    issues.Add(Issue(prototype.RuntimeId, block.EndPc, "return_has_edge", "return block has a successor"));
                if (block.Terminator == BlockTerminatorKind.Branch && block.Successors.Count is < 1 or > 2)
                    issues.Add(Issue(prototype.RuntimeId, block.EndPc, "invalid_branch", "branch needs one or two observed successors"));
                if (block.Terminator == BlockTerminatorKind.Fallthrough && block.Successors.Count > 1)
                    issues.Add(Issue(prototype.RuntimeId, block.EndPc, "invalid_fallthrough", "fallthrough block has multiple successors"));
            }
        }

        return new GraphValidationResult(issues.Count == 0, issues);
    }

    private static UnresolvedFact Issue(ulong prototype, int pc, string code, string message) =>
        new("cfg", code, message, Provenance.At(prototype, pc));
}
