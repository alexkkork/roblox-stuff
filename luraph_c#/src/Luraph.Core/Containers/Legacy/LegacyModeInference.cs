namespace Luraph.Core.Containers.Legacy;

internal sealed record LegacyModeResult(
    LegacyModeMetadata Metadata,
    IReadOnlyList<LegacyPrototypeReference> References);

internal static class LegacyModeInference
{
    public static LegacyModeResult Infer(
        IReadOnlyList<LegacyPrototype> prototypes,
        int constantCount)
    {
        var scores = BuildScores(prototypes, constantCount);
        var bestScore = long.MinValue;
        var bestCount = 0;
        var evaluated = 0;
        uint bestConstant = 0;
        uint bestForward = 0;
        uint bestBackward = 0;
        uint bestPrototype = 0;
        var bestSlot = LegacyOperandSlot.C;

        for (uint constant = 0; constant < 8; constant++)
            for (uint forward = 0; forward < 8; forward++)
                for (uint backward = 0; backward < 8; backward++)
                    for (uint prototype = 0; prototype < 8; prototype++)
                    {
                        if (constant == forward || constant == backward || constant == prototype ||
                            forward == backward || forward == prototype || backward == prototype)
                            continue;
                        foreach (var slot in Enum.GetValues<LegacyOperandSlot>())
                        {
                            evaluated++;
                            var score = Value(scores, LegacyOperandRole.Constant, constant, null) +
                                Value(scores, LegacyOperandRole.Forward, forward, null) +
                                Value(scores, LegacyOperandRole.Backward, backward, null) +
                                Value(scores, LegacyOperandRole.Prototype, prototype, slot);
                            if (score < bestScore)
                                continue;
                            if (score == bestScore)
                            {
                                bestCount++;
                                continue;
                            }
                            bestScore = score;
                            bestCount = 1;
                            bestConstant = constant;
                            bestForward = forward;
                            bestBackward = backward;
                            bestPrototype = prototype;
                            bestSlot = slot;
                        }
                    }

        var references = new List<LegacyPrototypeReference>();
        foreach (var prototype in prototypes)
            foreach (var instruction in prototype.Instructions)
            {
                var raw = instruction.Lane(bestSlot);
                var residue = raw % 8;
                if (residue != bestPrototype)
                    continue;
                var target = raw / 8;
                references.Add(new(prototype.Index, instruction.Index, bestSlot, checked((int)Math.Min(target, int.MaxValue)),
                    target >= 1 && target <= (ulong)prototypes.Count));
            }

        return new(new()
        {
            ConstantResidue = bestConstant,
            ForwardResidue = bestForward,
            BackwardResidue = bestBackward,
            PrototypeResidue = bestPrototype,
            PrototypeSlot = bestSlot,
            CandidatesEvaluated = evaluated,
            UniqueBest = bestCount == 1,
            ArrayPermutationResolved = false,
            Scores = scores,
        }, references);
    }

    private static List<LegacyModeScore> BuildScores(IReadOnlyList<LegacyPrototype> prototypes, int constantCount)
    {
        var totals = new Dictionary<(LegacyOperandRole Role, uint Residue, LegacyOperandSlot? Slot), (int Valid, int Invalid)>();
        foreach (var prototype in prototypes)
            foreach (var instruction in prototype.Instructions)
                foreach (var slot in Enum.GetValues<LegacyOperandSlot>())
                {
                    var raw = instruction.Lane(slot);
                    var residue = (uint)(raw % 8);
                    var value = raw / 8;
                    Add(LegacyOperandRole.Constant, residue, null, value >= 1 && value <= (ulong)constantCount);
                    Add(LegacyOperandRole.Forward, residue, null, value <= int.MaxValue && instruction.Index + (int)value <= prototype.Instructions.Count);
                    Add(LegacyOperandRole.Backward, residue, null, value <= int.MaxValue && instruction.Index - (int)value >= 1);
                    Add(LegacyOperandRole.Prototype, residue, slot, value >= 1 && value <= (ulong)prototypes.Count);
                }

        return totals
            .OrderBy(item => item.Key.Role)
            .ThenBy(item => item.Key.Residue)
            .ThenBy(item => item.Key.Slot)
            .Select(item => new LegacyModeScore(item.Key.Role, item.Key.Residue, item.Key.Slot, item.Value.Valid, item.Value.Invalid))
            .ToList();

        void Add(LegacyOperandRole role, uint residue, LegacyOperandSlot? slot, bool valid)
        {
            var key = (role, residue, slot);
            totals.TryGetValue(key, out var value);
            totals[key] = valid ? (value.Valid + 1, value.Invalid) : (value.Valid, value.Invalid + 1);
        }
    }

    private static long Value(
        IReadOnlyList<LegacyModeScore> scores,
        LegacyOperandRole role,
        uint residue,
        LegacyOperandSlot? slot)
    {
        var score = scores.FirstOrDefault(item => item.Role == role && item.Residue == residue && item.Slot == slot);
        return score is null ? 0 : score.Valid * 8L - score.Invalid;
    }
}
