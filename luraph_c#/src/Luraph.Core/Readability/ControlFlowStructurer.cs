using Luraph.Core.Ir;

namespace Luraph.Core.Readability;

public sealed record StructuredBranch(int Header, int TrueEntry, int FalseEntry, int Join);
public sealed record StructuredLoop(int Header, IReadOnlySet<int> Body, int? Exit);

public sealed record ControlFlowStructure(
    ulong Prototype,
    IReadOnlyList<StructuredBranch> Branches,
    IReadOnlyList<StructuredLoop> Loops,
    IReadOnlySet<int> StructuredBlocks,
    IReadOnlySet<int> ResidualBlocks);

public sealed class ControlFlowStructurer
{
    public ControlFlowStructure Analyze(PrototypeControlFlow cfg)
    {
        Dictionary<int, BasicBlock> blocks = cfg.Blocks
            .Where(block => block.Reachable)
            .ToDictionary(block => block.StartPc);
        Dictionary<int, HashSet<int>> predecessors = BuildPredecessors(blocks);
        Dictionary<int, HashSet<int>> dominators = BuildDominators(cfg.EntryPc, blocks, predecessors);
        Dictionary<int, HashSet<int>> postDominators = BuildPostDominators(blocks);
        List<StructuredLoop> loops = FindLoops(blocks, predecessors, dominators);
        List<StructuredBranch> branches = FindBranches(blocks, postDominators);
        HashSet<int> structured = [];

        foreach (StructuredLoop loop in loops)
            structured.UnionWith(loop.Body);
        foreach (StructuredBranch branch in branches)
        {
            structured.Add(branch.Header);
            structured.Add(branch.TrueEntry);
            structured.Add(branch.FalseEntry);
            structured.Add(branch.Join);
        }
        foreach (BasicBlock block in blocks.Values)
            if (block.Successors.Count <= 1)
                structured.Add(block.StartPc);

        HashSet<int> residual = blocks.Keys.Where(pc => !structured.Contains(pc)).ToHashSet();
        return new ControlFlowStructure(cfg.RuntimeId, branches, loops, structured, residual);
    }

    private static Dictionary<int, HashSet<int>> BuildPredecessors(IReadOnlyDictionary<int, BasicBlock> blocks)
    {
        Dictionary<int, HashSet<int>> result = blocks.Keys.ToDictionary(pc => pc, _ => new HashSet<int>());
        foreach (BasicBlock block in blocks.Values)
            foreach (int successor in block.Successors)
                if (result.TryGetValue(successor, out HashSet<int>? incoming))
                    incoming.Add(block.StartPc);
        return result;
    }

    private static Dictionary<int, HashSet<int>> BuildDominators(
        int entry,
        IReadOnlyDictionary<int, BasicBlock> blocks,
        IReadOnlyDictionary<int, HashSet<int>> predecessors)
    {
        HashSet<int> all = [.. blocks.Keys];
        Dictionary<int, HashSet<int>> result = blocks.Keys.ToDictionary(
            pc => pc,
            pc => pc == entry ? new HashSet<int> { pc } : new HashSet<int>(all));
        bool changed;
        do
        {
            changed = false;
            foreach (int pc in blocks.Keys.Where(value => value != entry))
            {
                HashSet<int> next = predecessors[pc].Count == 0
                    ? []
                    : new HashSet<int>(result[predecessors[pc].First()]);
                foreach (int predecessor in predecessors[pc].Skip(1))
                    next.IntersectWith(result[predecessor]);
                next.Add(pc);
                if (!next.SetEquals(result[pc]))
                {
                    result[pc] = next;
                    changed = true;
                }
            }
        } while (changed);
        return result;
    }

    private static Dictionary<int, HashSet<int>> BuildPostDominators(IReadOnlyDictionary<int, BasicBlock> blocks)
    {
        HashSet<int> all = [.. blocks.Keys];
        HashSet<int> exits = blocks.Values.Where(block => block.Successors.Count == 0).Select(block => block.StartPc).ToHashSet();
        Dictionary<int, HashSet<int>> result = blocks.Keys.ToDictionary(
            pc => pc,
            pc => exits.Contains(pc) ? new HashSet<int> { pc } : new HashSet<int>(all));
        bool changed;
        do
        {
            changed = false;
            foreach (BasicBlock block in blocks.Values.Where(item => !exits.Contains(item.StartPc)))
            {
                List<int> successors = block.Successors.Where(blocks.ContainsKey).ToList();
                HashSet<int> next = successors.Count == 0 ? [] : new HashSet<int>(result[successors[0]]);
                foreach (int successor in successors.Skip(1))
                    next.IntersectWith(result[successor]);
                next.Add(block.StartPc);
                if (!next.SetEquals(result[block.StartPc]))
                {
                    result[block.StartPc] = next;
                    changed = true;
                }
            }
        } while (changed);
        return result;
    }

    private static List<StructuredLoop> FindLoops(
        IReadOnlyDictionary<int, BasicBlock> blocks,
        IReadOnlyDictionary<int, HashSet<int>> predecessors,
        IReadOnlyDictionary<int, HashSet<int>> dominators)
    {
        List<StructuredLoop> loops = [];
        foreach (BasicBlock tail in blocks.Values)
            foreach (int header in tail.Successors)
            {
                if (!dominators.TryGetValue(tail.StartPc, out HashSet<int>? tailDominators) || !tailDominators.Contains(header))
                    continue;
                HashSet<int> body = [header, tail.StartPc];
                Stack<int> work = tail.StartPc == header ? new Stack<int>() : new Stack<int>([tail.StartPc]);
                while (work.Count > 0)
                {
                    int current = work.Pop();
                    foreach (int predecessor in predecessors[current])
                        if (body.Add(predecessor) && predecessor != header)
                            work.Push(predecessor);
                }
                int? exit = body.SelectMany(pc => blocks[pc].Successors)
                    .Where(successor => !body.Contains(successor))
                    .Distinct()
                    .Order()
                    .Cast<int?>()
                    .FirstOrDefault();
                loops.Add(new StructuredLoop(header, body, exit));
            }
        return loops.GroupBy(loop => loop.Header).Select(group => group.First()).ToList();
    }

    private static List<StructuredBranch> FindBranches(
        IReadOnlyDictionary<int, BasicBlock> blocks,
        IReadOnlyDictionary<int, HashSet<int>> postDominators)
    {
        List<StructuredBranch> branches = [];
        foreach (BasicBlock block in blocks.Values.Where(item => item.Successors.Count == 2))
        {
            int whenTrue = block.Successors[0];
            int whenFalse = block.Successors[1];
            if (!postDominators.TryGetValue(whenTrue, out HashSet<int>? truePosts) ||
                !postDominators.TryGetValue(whenFalse, out HashSet<int>? falsePosts))
                continue;
            int? join = truePosts.Intersect(falsePosts)
                .Where(pc => pc != block.StartPc)
                .OrderBy(pc => postDominators[pc].Count)
                .Cast<int?>()
                .FirstOrDefault();
            if (join.HasValue)
                branches.Add(new StructuredBranch(block.StartPc, whenTrue, whenFalse, join.Value));
        }
        return branches;
    }
}
