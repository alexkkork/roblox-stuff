using System.Globalization;
using Luraph.Core.Ir;

namespace Luraph.Core.Readability;

public sealed record RegisterScalarizationResult(
    SemanticProgram Program,
    int PrototypesChanged,
    int SlotsScalarized,
    int AccessesRewritten);

public sealed class RegisterScalarizer
{
    public RegisterScalarizationResult Apply(SemanticProgram program)
    {
        int prototypesChanged = 0;
        int slotsScalarized = 0;
        int accessesRewritten = 0;
        List<SemanticPrototype> prototypes = [];

        foreach (SemanticPrototype prototype in program.Prototypes)
        {
            AccessScan scan = Scan(prototype);
            if (scan.HasDynamicAccess)
            {
                prototypes.Add(prototype);
                continue;
            }

            HashSet<int> safe = [.. scan.Slots];
            safe.ExceptWith(scan.CapturedSlots);
            safe.ExceptWith(scan.ClearedSlots);
            if (safe.Count == 0)
            {
                prototypes.Add(prototype);
                continue;
            }

            Dictionary<int, string> names = safe.Order()
                .Select((slot, index) => (slot, name: $"local_{index + 1}"))
                .ToDictionary(item => item.slot, item => item.name);
            RewriteCounter rewrites = new();
            List<SemanticInstruction> instructions = prototype.Instructions
                .Select(instruction => instruction with
                {
                    Operation = RewriteOperation(instruction.Operation, names, rewrites),
                })
                .ToList();

            prototypes.Add(prototype with
            {
                Instructions = instructions,
                Locals = [.. (prototype.Locals ?? []), .. names.Values],
            });
            prototypesChanged++;
            slotsScalarized += safe.Count;
            accessesRewritten += rewrites.Value;
        }

        return new RegisterScalarizationResult(
            program with { Prototypes = prototypes },
            prototypesChanged,
            slotsScalarized,
            accessesRewritten);
    }

    private static AccessScan Scan(SemanticPrototype prototype)
    {
        AccessScan scan = new();
        foreach (SemanticInstruction instruction in prototype.Instructions)
        {
            if (instruction.Closure is not null)
                foreach (CaptureBinding capture in instruction.Closure.Captures)
                    scan.CapturedSlots.Add(capture.Slot);
            ScanOperation(instruction.Operation, scan);
        }
        return scan;
    }

    private static void ScanOperation(SemanticOperation operation, AccessScan scan)
    {
        switch (operation)
        {
            case AssignOperation assign:
                foreach (AssignmentTarget target in assign.Targets)
                    ScanTarget(target, scan);
                foreach (SemanticExpression value in assign.Values)
                    ScanExpression(value, scan);
                break;
            case CompoundAssignOperation compound:
                ScanTarget(compound.Target, scan);
                ScanExpression(compound.Value, scan);
                break;
            case ExpressionOperation expression:
                ScanExpression(expression.Expression, scan);
                break;
            case ReturnOperation returned:
                foreach (SemanticExpression value in returned.Values)
                    ScanExpression(value, scan);
                break;
            case BranchOperation branch:
                ScanExpression(branch.Condition, scan);
                foreach (SemanticOperation child in branch.Then.Concat(branch.Else))
                    ScanOperation(child, scan);
                break;
            case JumpOperation jump:
                ScanExpression(jump.Target, scan);
                break;
            case CloseCapturesOperation close:
                ScanExpression(close.From, scan);
                break;
            case PrepareRegisterClearOperation prepare:
                ScanExpression(prepare.From, scan);
                ScanExpression(prepare.To, scan);
                break;
            case ClearRegisterRangeOperation clear:
                ScanExpression(clear.From, scan);
                ScanExpression(clear.To, scan);
                if (ConstantSlot(clear.From) is int from && ConstantSlot(clear.To) is int to && to >= from && to - from <= 4096)
                    for (int slot = from; slot <= to; slot++)
                        scan.ClearedSlots.Add(slot);
                else
                    scan.HasDynamicAccess = true;
                break;
            case GenericForPrepareOperation generic:
                ScanExpression(generic.BaseRegister, scan);
                scan.HasDynamicAccess = true;
                break;
            case NumericForOperation numeric:
                ScanExpression(numeric.From, scan);
                ScanExpression(numeric.To, scan);
                ScanExpression(numeric.Step, scan);
                foreach (SemanticOperation child in numeric.Body)
                    ScanOperation(child, scan);
                break;
            case SequenceOperation sequence:
                foreach (SemanticOperation child in sequence.Operations)
                    ScanOperation(child, scan);
                break;
        }
    }

    private static void ScanTarget(AssignmentTarget target, AccessScan scan)
    {
        switch (target)
        {
            case RegisterTarget register:
                AddSlot(register.Index, scan);
                break;
            case IndexTarget index:
                ScanExpression(index.Table, scan);
                ScanExpression(index.Index, scan);
                break;
        }
    }

    private static void ScanExpression(SemanticExpression expression, AccessScan scan)
    {
        switch (expression)
        {
            case RegisterReadExpression register:
                AddSlot(register.Index, scan);
                break;
            case IndexExpression index:
                ScanExpression(index.Table, scan);
                ScanExpression(index.Index, scan);
                break;
            case BinaryExpression binary:
                ScanExpression(binary.Left, scan);
                ScanExpression(binary.Right, scan);
                break;
            case UnaryExpression unary:
                ScanExpression(unary.Value, scan);
                break;
            case TableExpression table:
                foreach (TableField field in table.Fields)
                {
                    if (field.Key is not null)
                        ScanExpression(field.Key, scan);
                    ScanExpression(field.Value, scan);
                }
                break;
            case CallExpression call:
                ScanExpression(call.Function, scan);
                foreach (SemanticExpression argument in call.Arguments)
                    ScanExpression(argument, scan);
                break;
            case RegisterRangeExpression:
                scan.HasDynamicAccess = true;
                break;
            case ClosureExpression closure:
                foreach (CaptureBinding capture in closure.Captures)
                    scan.CapturedSlots.Add(capture.Slot);
                break;
        }
    }

    private static void AddSlot(SemanticExpression index, AccessScan scan)
    {
        if (ConstantSlot(index) is int slot && slot >= 0)
            scan.Slots.Add(slot);
        else
            scan.HasDynamicAccess = true;
    }

    private static int? ConstantSlot(SemanticExpression expression)
    {
        double? value = ConstantNumber(expression);
        if (value is not double number || !double.IsFinite(number) ||
            number < int.MinValue || number > int.MaxValue || number != Math.Truncate(number))
            return null;
        return checked((int)number);
    }

    private static double? ConstantNumber(SemanticExpression expression) => expression switch
    {
        NumberExpression number when double.TryParse(
            number.Text,
            NumberStyles.Float,
            CultureInfo.InvariantCulture,
            out double value) => value,
        UnaryExpression { Operator: "-" } unary when ConstantNumber(unary.Value) is double value => -value,
        BinaryExpression binary when ConstantNumber(binary.Left) is double left &&
                                     ConstantNumber(binary.Right) is double right => binary.Operator switch
        {
            "+" => left + right,
            "-" => left - right,
            "*" => left * right,
            _ => null,
        },
        _ => null,
    };

    private static SemanticOperation RewriteOperation(
        SemanticOperation operation,
        IReadOnlyDictionary<int, string> names,
        RewriteCounter rewrites)
    {
        switch (operation)
        {
            case AssignOperation assign:
                return assign with
                {
                    Targets = assign.Targets.Select(target => RewriteTarget(target, names, rewrites)).ToList(),
                    Values = assign.Values.Select(value => RewriteExpression(value, names, rewrites)).ToList(),
                };
            case CompoundAssignOperation compound:
                return compound with
                {
                    Target = RewriteTarget(compound.Target, names, rewrites),
                    Value = RewriteExpression(compound.Value, names, rewrites),
                };
            case ExpressionOperation expression:
                return expression with { Expression = RewriteExpression(expression.Expression, names, rewrites) };
            case ReturnOperation returned:
                return returned with { Values = returned.Values.Select(value => RewriteExpression(value, names, rewrites)).ToList() };
            case BranchOperation branch:
                return branch with
                {
                    Condition = RewriteExpression(branch.Condition, names, rewrites),
                    Then = branch.Then.Select(item => RewriteOperation(item, names, rewrites)).ToList(),
                    Else = branch.Else.Select(item => RewriteOperation(item, names, rewrites)).ToList(),
                };
            case JumpOperation jump:
                return jump with { Target = RewriteExpression(jump.Target, names, rewrites) };
            case CloseCapturesOperation close:
                return close with { From = RewriteExpression(close.From, names, rewrites) };
            case PrepareRegisterClearOperation prepare:
                return prepare with
                {
                    From = RewriteExpression(prepare.From, names, rewrites),
                    To = RewriteExpression(prepare.To, names, rewrites),
                };
            case ClearRegisterRangeOperation clear:
                return clear with
                {
                    From = RewriteExpression(clear.From, names, rewrites),
                    To = RewriteExpression(clear.To, names, rewrites),
                };
            case NumericForOperation numeric:
                return numeric with
                {
                    From = RewriteExpression(numeric.From, names, rewrites),
                    To = RewriteExpression(numeric.To, names, rewrites),
                    Step = RewriteExpression(numeric.Step, names, rewrites),
                    Body = numeric.Body.Select(item => RewriteOperation(item, names, rewrites)).ToList(),
                };
            case SequenceOperation sequence:
                return sequence with { Operations = sequence.Operations.Select(item => RewriteOperation(item, names, rewrites)).ToList() };
            default:
                return operation;
        }
    }

    private static AssignmentTarget RewriteTarget(
        AssignmentTarget target,
        IReadOnlyDictionary<int, string> names,
        RewriteCounter rewrites)
    {
        if (target is RegisterTarget register && ConstantSlot(register.Index) is int slot && names.TryGetValue(slot, out string? name))
        {
            rewrites.Value++;
            return new NamedTarget(name, target.Provenance);
        }
        if (target is IndexTarget index)
            return index with
            {
                Table = RewriteExpression(index.Table, names, rewrites),
                Index = RewriteExpression(index.Index, names, rewrites),
            };
        return target;
    }

    private static SemanticExpression RewriteExpression(
        SemanticExpression expression,
        IReadOnlyDictionary<int, string> names,
        RewriteCounter rewrites)
    {
        if (expression is RegisterReadExpression register && ConstantSlot(register.Index) is int slot && names.TryGetValue(slot, out string? name))
        {
            rewrites.Value++;
            return new IdentifierExpression(name, expression.Provenance);
        }

        return expression switch
        {
            IndexExpression index => index with
            {
                Table = RewriteExpression(index.Table, names, rewrites),
                Index = RewriteExpression(index.Index, names, rewrites),
            },
            BinaryExpression binary => binary with
            {
                Left = RewriteExpression(binary.Left, names, rewrites),
                Right = RewriteExpression(binary.Right, names, rewrites),
            },
            UnaryExpression unary => unary with { Value = RewriteExpression(unary.Value, names, rewrites) },
            TableExpression table => table with
            {
                Fields = table.Fields.Select(field => field with
                {
                    Key = field.Key is null ? null : RewriteExpression(field.Key, names, rewrites),
                    Value = RewriteExpression(field.Value, names, rewrites),
                }).ToList(),
            },
            CallExpression call => call with
            {
                Function = RewriteExpression(call.Function, names, rewrites),
                Arguments = call.Arguments.Select(argument => RewriteExpression(argument, names, rewrites)).ToList(),
            },
            _ => expression,
        };
    }

    private sealed class AccessScan
    {
        public HashSet<int> Slots { get; } = [];
        public HashSet<int> CapturedSlots { get; } = [];
        public HashSet<int> ClearedSlots { get; } = [];
        public bool HasDynamicAccess { get; set; }
    }

    private sealed class RewriteCounter
    {
        public int Value { get; set; }
    }
}
