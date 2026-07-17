using System.Text;
using Luraph.Core.Ir;

namespace Luraph.Core.Readability;

public sealed record SemanticNamingResult(SemanticProgram Program, int NamesChanged);

public sealed class SemanticNamer
{
    public SemanticNamingResult Apply(SemanticProgram program)
    {
        int changed = 0;
        List<SemanticPrototype> prototypes = [];
        foreach (SemanticPrototype prototype in program.Prototypes)
        {
            Dictionary<string, string> names = FindNames(prototype);
            if (names.Count == 0)
            {
                prototypes.Add(prototype);
                continue;
            }
            List<SemanticInstruction> instructions = prototype.Instructions
                .Select(instruction => instruction with
                {
                    Operation = RenameOperation(instruction.Operation, names),
                })
                .ToList();
            IReadOnlyList<string>? locals = prototype.Locals?.Select(name => names.GetValueOrDefault(name, name)).ToList();
            prototypes.Add(prototype with { Instructions = instructions, Locals = locals });
            changed += names.Count;
        }
        return new SemanticNamingResult(program with { Prototypes = prototypes }, changed);
    }

    private static Dictionary<string, string> FindNames(SemanticPrototype prototype)
    {
        Dictionary<string, List<SemanticExpression>> definitions = [];
        foreach (SemanticInstruction instruction in prototype.Instructions)
            CollectDefinitions(instruction.Operation, definitions);

        HashSet<string> used = new(prototype.Locals ?? [], StringComparer.Ordinal);
        Dictionary<string, string> result = [];
        foreach ((string local, List<SemanticExpression> values) in definitions.OrderBy(item => item.Key))
        {
            if (!IsGeneratedLocal(local) || values.Count != 1)
                continue;
            string? baseName = NameFromExpression(values[0]);
            if (baseName is null)
                continue;
            string candidate = baseName;
            int suffix = 2;
            while (used.Contains(candidate) && candidate != local)
                candidate = $"{baseName}_{suffix++}";
            if (candidate == local)
                continue;
            used.Add(candidate);
            result[local] = candidate;
        }
        return result;
    }

    private static void CollectDefinitions(
        SemanticOperation operation,
        Dictionary<string, List<SemanticExpression>> definitions)
    {
        switch (operation)
        {
            case AssignOperation { Targets.Count: 1, Values.Count: 1 } assign when assign.Targets[0] is NamedTarget target:
                if (!definitions.TryGetValue(target.Name, out List<SemanticExpression>? values))
                    definitions[target.Name] = values = [];
                values.Add(assign.Values[0]);
                break;
            case SequenceOperation sequence:
                foreach (SemanticOperation child in sequence.Operations)
                    CollectDefinitions(child, definitions);
                break;
            case BranchOperation branch:
                foreach (SemanticOperation child in branch.Then.Concat(branch.Else))
                    CollectDefinitions(child, definitions);
                break;
            case NumericForOperation numeric:
                foreach (SemanticOperation child in numeric.Body)
                    CollectDefinitions(child, definitions);
                break;
        }
    }

    private static string? NameFromExpression(SemanticExpression expression)
    {
        if (expression is ClosureExpression)
            return "callback";
        if (expression is TableExpression)
            return "data";
        if (expression is IndexExpression { Index: StringExpression key })
            return ToSnakeCase(key.Value);
        if (expression is not CallExpression call)
            return null;

        if (call.Function is IdentifierExpression function)
            return function.Name switch
            {
                "pcall" or "xpcall" => "success",
                "require" => "module",
                "tostring" => "text",
                "tonumber" => "number",
                _ => null,
            };

        if (call.Function is IndexExpression { Table: IdentifierExpression { Name: "game" }, Index: StringExpression { Value: "GetService" } } &&
            call.Arguments.LastOrDefault() is StringExpression service)
            return ToSnakeCase(service.Value);
        if (call.Function is IndexExpression { Table: IdentifierExpression { Name: "Instance" }, Index: StringExpression { Value: "new" } } &&
            call.Arguments.LastOrDefault() is StringExpression className)
            return ToSnakeCase(className.Value);
        if (call.Function is IndexExpression { Index: StringExpression method })
            return method.Value switch
            {
                "Connect" => "connection",
                "Clone" => "clone",
                "FindFirstChild" or "WaitForChild" => "child",
                _ => ToSnakeCase(method.Value) + "_result",
            };
        return null;
    }

    private static SemanticOperation RenameOperation(SemanticOperation operation, IReadOnlyDictionary<string, string> names) =>
        operation switch
        {
            AssignOperation assign => assign with
            {
                Targets = assign.Targets.Select(target => RenameTarget(target, names)).ToList(),
                Values = assign.Values.Select(value => RenameExpression(value, names)).ToList(),
            },
            CompoundAssignOperation compound => compound with
            {
                Target = RenameTarget(compound.Target, names),
                Value = RenameExpression(compound.Value, names),
            },
            ExpressionOperation expression => expression with { Expression = RenameExpression(expression.Expression, names) },
            ReturnOperation returned => returned with { Values = returned.Values.Select(value => RenameExpression(value, names)).ToList() },
            BranchOperation branch => branch with
            {
                Condition = RenameExpression(branch.Condition, names),
                Then = branch.Then.Select(item => RenameOperation(item, names)).ToList(),
                Else = branch.Else.Select(item => RenameOperation(item, names)).ToList(),
            },
            JumpOperation jump => jump with { Target = RenameExpression(jump.Target, names) },
            PrepareRegisterClearOperation prepare => prepare with
            {
                From = RenameExpression(prepare.From, names),
                To = RenameExpression(prepare.To, names),
            },
            SequenceOperation sequence => sequence with { Operations = sequence.Operations.Select(item => RenameOperation(item, names)).ToList() },
            NumericForOperation numeric => numeric with
            {
                From = RenameExpression(numeric.From, names),
                To = RenameExpression(numeric.To, names),
                Step = RenameExpression(numeric.Step, names),
                Body = numeric.Body.Select(item => RenameOperation(item, names)).ToList(),
            },
            _ => operation,
        };

    private static AssignmentTarget RenameTarget(AssignmentTarget target, IReadOnlyDictionary<string, string> names) => target switch
    {
        NamedTarget named => named with { Name = names.GetValueOrDefault(named.Name, named.Name) },
        IndexTarget index => index with
        {
            Table = RenameExpression(index.Table, names),
            Index = RenameExpression(index.Index, names),
        },
        RegisterTarget register => register with { Index = RenameExpression(register.Index, names) },
        _ => target,
    };

    private static SemanticExpression RenameExpression(SemanticExpression expression, IReadOnlyDictionary<string, string> names) => expression switch
    {
        IdentifierExpression identifier => identifier with { Name = names.GetValueOrDefault(identifier.Name, identifier.Name) },
        RegisterReadExpression register => register with { Index = RenameExpression(register.Index, names) },
        IndexExpression index => index with
        {
            Table = RenameExpression(index.Table, names),
            Index = RenameExpression(index.Index, names),
        },
        BinaryExpression binary => binary with
        {
            Left = RenameExpression(binary.Left, names),
            Right = RenameExpression(binary.Right, names),
        },
        UnaryExpression unary => unary with { Value = RenameExpression(unary.Value, names) },
        CallExpression call => call with
        {
            Function = RenameExpression(call.Function, names),
            Arguments = call.Arguments.Select(argument => RenameExpression(argument, names)).ToList(),
        },
        TableExpression table => table with
        {
            Fields = table.Fields.Select(field => field with
            {
                Key = field.Key is null ? null : RenameExpression(field.Key, names),
                Value = RenameExpression(field.Value, names),
            }).ToList(),
        },
        _ => expression,
    };

    private static bool IsGeneratedLocal(string name) =>
        name.StartsWith("local_", StringComparison.Ordinal) &&
        int.TryParse(name.AsSpan("local_".Length), out _);

    private static string ToSnakeCase(string value)
    {
        StringBuilder result = new();
        foreach (char character in value)
        {
            if (!char.IsLetterOrDigit(character))
            {
                if (result.Length > 0 && result[^1] != '_')
                    result.Append('_');
                continue;
            }
            if (char.IsUpper(character) && result.Length > 0 && result[^1] != '_')
                result.Append('_');
            result.Append(char.ToLowerInvariant(character));
        }
        string name = result.ToString().Trim('_');
        return string.IsNullOrEmpty(name) ? "value" : name;
    }
}
