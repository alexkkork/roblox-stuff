using Luraph.Core.Ir;

namespace Luraph.Core.Lifting;

public sealed record LiftResult(
    SemanticProgram Program,
    ControlFlowGraph ControlFlow,
    GraphValidationResult Validation);

public sealed class SemanticLifter
{
    public LiftResult Lift(ImportedArtifacts artifacts)
    {
        GraphValidationResult validation = new ControlFlowValidator().Validate(artifacts.ControlFlow);
        SemanticProgram program = ResolveProgram(artifacts.Program, validation.Issues);
        return new LiftResult(program, artifacts.ControlFlow, validation);
    }

    private static SemanticProgram ResolveProgram(SemanticProgram source, IReadOnlyList<UnresolvedFact> graphIssues)
    {
        Dictionary<(ulong Prototype, int Pc), CallResolution> calls = source.CallEdges
            .GroupBy(edge => (edge.CallerPrototype, edge.CallerPc))
            .Where(group => group.Select(edge => edge.CalleePrototype).Distinct().Count() == 1)
            .ToDictionary(group => group.Key, BuildCallResolution);

        Dictionary<(ulong Prototype, int Pc), LaneResolution> lanes = source.LaneReplays
            .ToDictionary(site => (site.Prototype, site.Pc), BuildLaneResolution);
        HashSet<ulong> prototypes = source.Prototypes.Select(item => item.RuntimeId).ToHashSet();
        List<UnresolvedFact> unresolved = [.. source.Unresolved, .. graphIssues];
        List<SemanticPrototype> lifted = [];

        foreach (SemanticPrototype prototype in source.Prototypes)
        {
            PreparedClearResolution clearRanges = FindPreparedClearRanges(prototype);
            List<SemanticInstruction> instructions = [];
            foreach (SemanticInstruction instruction in prototype.Instructions)
            {
                LaneResolution? laneResolution = lanes.GetValueOrDefault((prototype.RuntimeId, instruction.Pc));
                CallResolution? callee = calls.GetValueOrDefault((prototype.RuntimeId, instruction.Pc));
                SemanticOperation operation = RewriteOperation(instruction.Operation, laneResolution, callee);
                operation = ResolvePreparedClears(operation, instruction.Pc, clearRanges, unresolved);

                if (instruction.Closure is ClosureDescriptor descriptor)
                {
                    if (CanBuildClosure(descriptor, prototypes))
                    {
                        IReadOnlyList<CaptureBinding> captures = ResolveCaptures(
                            descriptor,
                            prototype.ObservedCaptureIndices,
                            unresolved);
                        ClosureExpression closure = new(
                            descriptor.TargetPrototype,
                            captures,
                            descriptor.Provenance);
                        AssignOperation write = new(
                            [new RegisterTarget(
                                new NumberExpression(descriptor.DestinationRegister.ToString(System.Globalization.CultureInfo.InvariantCulture), descriptor.Provenance),
                                descriptor.Provenance)],
                            [closure],
                            descriptor.Provenance);
                        operation = operation is SequenceOperation { ProtectorInternal: true }
                            ? write
                            : new SequenceOperation([operation, write], false, descriptor.Provenance);
                    }
                    else
                    {
                        unresolved.Add(new UnresolvedFact(
                            "closures",
                            "incomplete_closure_descriptor",
                            $"closure at pc {instruction.Pc} cannot be proven",
                            descriptor.Provenance));
                    }
                }

                instructions.Add(instruction with { Operation = operation });
            }
            lifted.Add(prototype with { Instructions = instructions });
        }

        return source with { Prototypes = lifted, Unresolved = unresolved };
    }

    private static PreparedClearResolution FindPreparedClearRanges(SemanticPrototype prototype)
    {
        Dictionary<(int Pc, string State), RegisterClearRange> clears = [];
        List<SemanticInstruction> ordered = prototype.Instructions.OrderBy(item => item.Pc).ToList();
        for (int index = 1; index < ordered.Count; index++)
        {
            List<PrepareRegisterClearOperation> previous = [];
            List<ClearPreparedRegisterRangeOperation> current = [];
            CollectPreparedClears(ordered[index - 1].Operation, previous, null);
            CollectPreparedClears(ordered[index].Operation, null, current);
            foreach (ClearPreparedRegisterRangeOperation clear in current)
            {
                List<PrepareRegisterClearOperation> matches = previous
                    .Where(prepare => prepare.State == clear.State)
                    .ToList();
                if (matches.Count != 1)
                    continue;
                PrepareRegisterClearOperation prepare = matches[0];
                clears[(ordered[index].Pc, clear.State)] = new RegisterClearRange(prepare.From, prepare.To);
            }
        }
        return new PreparedClearResolution(clears);
    }

    private static void CollectPreparedClears(
        SemanticOperation operation,
        List<PrepareRegisterClearOperation>? prepares,
        List<ClearPreparedRegisterRangeOperation>? clears)
    {
        if (operation is PrepareRegisterClearOperation prepare && prepares is not null)
            prepares.Add(prepare);
        if (operation is ClearPreparedRegisterRangeOperation clear && clears is not null)
            clears.Add(clear);
        if (operation is SequenceOperation sequence)
            foreach (SemanticOperation child in sequence.Operations)
                CollectPreparedClears(child, prepares, clears);
    }

    private static SemanticOperation ResolvePreparedClears(
        SemanticOperation operation,
        int pc,
        PreparedClearResolution ranges,
        List<UnresolvedFact> unresolved)
    {
        if (operation is PrepareRegisterClearOperation prepare)
            return new SequenceOperation([], false, prepare.Provenance);
        if (operation is ClearPreparedRegisterRangeOperation clear)
        {
            if (ranges.Clears.TryGetValue((pc, clear.State), out RegisterClearRange? range))
                return new ClearRegisterRangeOperation(range.From, range.To, clear.Provenance);
            unresolved.Add(new UnresolvedFact(
                "registers",
                "ambiguous_register_clear",
                $"register clear state {clear.State} has no adjacent producer",
                clear.Provenance));
            return new UnresolvedOperation("clear_prepared_register_range", "register clear state has no adjacent producer", clear.Provenance);
        }
        if (operation is SequenceOperation sequence)
            return sequence with
            {
                Operations = sequence.Operations.Select(item => ResolvePreparedClears(item, pc, ranges, unresolved)).ToList(),
            };
        return operation;
    }

    private static IReadOnlyList<CaptureBinding> ResolveCaptures(
        ClosureDescriptor descriptor,
        IReadOnlySet<int> parentDomain,
        List<UnresolvedFact> unresolved)
    {
        List<CaptureBinding> captures = [];
        foreach (CaptureBinding capture in descriptor.Captures)
        {
            if (capture.Kind is CaptureKind.RegisterCell or CaptureKind.Value)
            {
                captures.Add(capture with { Proven = true });
                continue;
            }
            int? resolved = parentDomain.Contains(capture.Slot)
                ? capture.Slot
                : parentDomain.Count == 1 ? parentDomain.Single() : null;
            if (resolved.HasValue)
                captures.Add(capture with { ResolvedIndex = resolved, Proven = true });
            else
            {
                captures.Add(capture);
                unresolved.Add(new UnresolvedFact(
                    "captures",
                    "unresolved_capture_key",
                    $"capture {capture.Index} has no proven parent key",
                    descriptor.Provenance));
            }
        }
        return captures;
    }

    private static bool CanBuildClosure(ClosureDescriptor descriptor, IReadOnlySet<ulong> prototypes) =>
        descriptor.Complete &&
        descriptor.TargetPrototype > 0 &&
        prototypes.Contains(descriptor.TargetPrototype) &&
        descriptor.DestinationRegister >= 0 &&
        descriptor.Captures.All(capture => capture.Index >= 0 && capture.Slot >= 0);

    private static SemanticOperation RewriteOperation(
        SemanticOperation operation,
        LaneResolution? lanes,
        CallResolution? callee)
    {
        return operation switch
        {
            AssignOperation assign => assign with
            {
                Targets = assign.Targets.Select(target => RewriteTarget(target, lanes)).ToList(),
                Values = assign.Values.Select(value => RewriteExpression(value, lanes, callee)).ToList(),
            },
            CompoundAssignOperation compound => compound with
            {
                Target = RewriteTarget(compound.Target, lanes),
                Value = RewriteExpression(compound.Value, lanes, callee),
            },
            ExpressionOperation expression => expression with
            {
                Expression = RewriteExpression(expression.Expression, lanes, callee),
            },
            ReturnOperation returned => returned with
            {
                Values = returned.Values.Select(value => RewriteExpression(value, lanes, callee)).ToList(),
            },
            BranchOperation branch => branch with
            {
                Condition = RewriteExpression(branch.Condition, lanes, callee),
                Then = branch.Then.Select(item => RewriteOperation(item, lanes, callee)).ToList(),
                Else = branch.Else.Select(item => RewriteOperation(item, lanes, callee)).ToList(),
            },
            JumpOperation jump => jump with { Target = RewriteExpression(jump.Target, lanes, callee) },
            CloseCapturesOperation close => close with { From = RewriteExpression(close.From, lanes, callee) },
            PrepareRegisterClearOperation prepare => prepare with
            {
                From = RewriteExpression(prepare.From, lanes, callee),
                To = RewriteExpression(prepare.To, lanes, callee),
            },
            ClearRegisterRangeOperation clear => clear with
            {
                From = RewriteExpression(clear.From, lanes, callee),
                To = RewriteExpression(clear.To, lanes, callee),
            },
            GenericForPrepareOperation generic => generic with
            {
                BaseRegister = RewriteExpression(generic.BaseRegister, lanes, callee),
                LoopTarget = generic.LoopTarget is null ? null : RewriteExpression(generic.LoopTarget, lanes, callee),
            },
            NumericForOperation numeric => numeric with
            {
                From = RewriteExpression(numeric.From, lanes, callee),
                To = RewriteExpression(numeric.To, lanes, callee),
                Step = RewriteExpression(numeric.Step, lanes, callee),
                Body = numeric.Body.Select(item => RewriteOperation(item, lanes, callee)).ToList(),
            },
            SequenceOperation sequence => sequence with
            {
                Operations = sequence.Operations.Select(item => RewriteOperation(item, lanes, callee)).ToList(),
            },
            _ => operation,
        };
    }

    private static AssignmentTarget RewriteTarget(AssignmentTarget target, LaneResolution? lanes) => target switch
    {
        RegisterTarget register => register with { Index = RewriteExpression(register.Index, lanes, null) },
        IndexTarget index => index with
        {
            Table = RewriteExpression(index.Table, lanes, null),
            Index = RewriteExpression(index.Index, lanes, null),
        },
        _ => target,
    };

    private static SemanticExpression RewriteExpression(
        SemanticExpression expression,
        LaneResolution? lanes,
        CallResolution? callee)
    {
        switch (expression)
        {
            case LaneExpression lane:
                if (lanes?.Stable.GetValueOrDefault(lane.Lane) is SemanticExpression stable)
                    return stable;
                if (lanes is not null && lanes.Dynamic.Contains(lane.Lane))
                    return new DynamicLaneExpression(lane.Lane, lanes.Key, lane.Provenance);
                return RewriteExpression(lane.Fallback, lanes, null);

            case RegisterReadExpression register:
                return register with { Index = RewriteExpression(register.Index, lanes, null) };

            case IndexExpression index:
                return index with
                {
                    Table = RewriteExpression(index.Table, lanes, null),
                    Index = RewriteExpression(index.Index, lanes, null),
                };

            case BinaryExpression binary:
                return binary with
                {
                    Left = RewriteExpression(binary.Left, lanes, null),
                    Right = RewriteExpression(binary.Right, lanes, null),
                };

            case UnaryExpression unary:
                return unary with { Value = RewriteExpression(unary.Value, lanes, null) };

            case TableExpression table:
                return table with
                {
                    Fields = table.Fields.Select(field => field with
                    {
                        Key = field.Key is null ? null : RewriteExpression(field.Key, lanes, null),
                        Value = RewriteExpression(field.Value, lanes, null),
                    }).ToList(),
                };

            case CallExpression call:
                return RewriteCall(call, lanes, callee);

            case RegisterRangeExpression range:
                return range with
                {
                    From = RewriteExpression(range.From, lanes, null),
                    To = RewriteExpression(range.To, lanes, null),
                };

            default:
                return expression;
        }
    }

    private static LaneResolution BuildLaneResolution(LaneReplaySite site)
    {
        Dictionary<string, SemanticExpression> stable = [];
        HashSet<string> dynamic = [];

        foreach (string lane in site.Lanes)
        {
            List<SemanticExpression> values = site.Activations
                .SelectMany(activation => activation.Frames)
                .Where(frame => frame.Lanes.ContainsKey(lane))
                .Select(frame => frame.Lanes[lane])
                .ToList();
            if (values.Count > 0 && values.Skip(1).All(value => PrimitiveEquals(values[0], value)))
                stable[lane] = values[0];
            else
                dynamic.Add(lane);
        }

        return new LaneResolution($"lane:{site.Prototype}:{site.Pc}", stable, dynamic);
    }

    private static bool PrimitiveEquals(SemanticExpression left, SemanticExpression right) => (left, right) switch
    {
        (NilExpression, NilExpression) => true,
        (BooleanExpression a, BooleanExpression b) => a.Value == b.Value,
        (NumberExpression a, NumberExpression b) => a.Text == b.Text,
        (StringExpression a, StringExpression b) => a.Value == b.Value,
        _ => false,
    };

    private static CallExpression RewriteCall(
        CallExpression call,
        LaneResolution? lanes,
        CallResolution? resolution)
    {
        ulong? prototype = call.RecoveredPrototype;
        IReadOnlyList<SemanticExpression> arguments = call.Arguments
            .Select(argument => RewriteExpression(argument, lanes, null))
            .ToList();
        bool runtimeSpecialized = call.RuntimeSpecialized;
        if (resolution is { Consumed: false })
        {
            prototype = resolution.Prototype;
            if (resolution.StableArguments is { } stable && stable.Count == arguments.Count)
            {
                arguments = stable;
                runtimeSpecialized = true;
            }
            resolution.Consumed = true;
        }
        return call with
        {
            Function = RewriteExpression(call.Function, lanes, null),
            Arguments = arguments,
            RecoveredPrototype = prototype,
            RuntimeSpecialized = runtimeSpecialized,
        };
    }

    private static CallResolution BuildCallResolution(
        IGrouping<(ulong CallerPrototype, int CallerPc), PrototypeCallEdge> group)
    {
        PrototypeCallEdge first = group.First();
        IReadOnlyList<SemanticExpression>? stable = null;
        List<PrototypeCallEdge> complete = group
            .Where(edge => edge.ArgumentsComplete && edge.StableArguments is not null)
            .ToList();
        if (complete.Count == group.Count())
        {
            IReadOnlyList<SemanticExpression> candidate = complete[0].StableArguments!;
            if (complete.All(edge => StableArgumentsEqual(candidate, edge.StableArguments!)))
                stable = candidate;
        }
        return new CallResolution(first.CalleePrototype, stable);
    }

    private static bool StableArgumentsEqual(
        IReadOnlyList<SemanticExpression> left,
        IReadOnlyList<SemanticExpression> right) =>
        left.Count == right.Count && left.Zip(right).All(pair => pair.First == pair.Second);

    private sealed record LaneResolution(
        string Key,
        IReadOnlyDictionary<string, SemanticExpression> Stable,
        IReadOnlySet<string> Dynamic);

    private sealed record RegisterClearRange(SemanticExpression From, SemanticExpression To);

    private sealed record PreparedClearResolution(
        IReadOnlyDictionary<(int Pc, string State), RegisterClearRange> Clears);

    private sealed class CallResolution(ulong prototype, IReadOnlyList<SemanticExpression>? stableArguments)
    {
        public ulong Prototype { get; } = prototype;
        public IReadOnlyList<SemanticExpression>? StableArguments { get; } = stableArguments;
        public bool Consumed { get; set; }
    }
}
