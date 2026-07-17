using Luraph.Core.Ir;
using Luraph.Core.Readability;

namespace Luraph.Core.Tests.Readability;

public sealed class RegisterScalarizerTests
{
    private static readonly Provenance Site = Provenance.At(2, 1);

    [Fact]
    public void ConstantRegisterFrameBecomesLocals()
    {
        SemanticPrototype prototype = Prototype(
            new AssignOperation([Register(4)], [new NumberExpression("7", Site)], Site),
            new ReturnOperation([Read(4)], new ResultArity(1), Site));
        SemanticProgram program = Program(prototype);

        RegisterScalarizationResult result = new RegisterScalarizer().Apply(program);
        SemanticPrototype rewritten = Assert.Single(result.Program.Prototypes);
        AssignOperation assignment = Assert.IsType<AssignOperation>(rewritten.Instructions[0].Operation);
        ReturnOperation returned = Assert.IsType<ReturnOperation>(rewritten.Instructions[1].Operation);

        Assert.Equal(["local_1"], rewritten.Locals);
        Assert.IsType<NamedTarget>(Assert.Single(assignment.Targets));
        Assert.IsType<IdentifierExpression>(Assert.Single(returned.Values));
        Assert.Equal(2, result.AccessesRewritten);
    }

    [Fact]
    public void CapturedRegisterStaysTableBacked()
    {
        ClosureDescriptor closure = new(true, 3, 8, [new CaptureBinding(0, CaptureKind.RegisterCell, 4)], Site);
        SemanticInstruction instruction = new(
            1,
            22,
            new AssignOperation([Register(4)], [new NumberExpression("7", Site)], Site),
            closure,
            new Dictionary<string, SemanticExpression>(),
            new Dictionary<string, SemanticExpression>(),
            Site);
        SemanticPrototype prototype = new(2, 1, [instruction], new HashSet<int>());

        RegisterScalarizationResult result = new RegisterScalarizer().Apply(Program(prototype));

        Assert.Equal(0, result.SlotsScalarized);
        AssignOperation assignment = Assert.IsType<AssignOperation>(result.Program.Prototypes[0].Instructions[0].Operation);
        Assert.IsType<RegisterTarget>(Assert.Single(assignment.Targets));
    }

    [Fact]
    public void LuauNumericRegisterAddressBecomesLocal()
    {
        SemanticExpression address = new BinaryExpression(
            "+",
            new NumberExpression("106", Site),
            new NumberExpression("1.0", Site),
            Site);
        SemanticPrototype prototype = Prototype(
            new AssignOperation([new RegisterTarget(address, Site)], [new NumberExpression("7", Site)], Site),
            new ReturnOperation([new RegisterReadExpression(address, Site)], new ResultArity(1), Site));

        RegisterScalarizationResult result = new RegisterScalarizer().Apply(Program(prototype));

        Assert.Equal(1, result.SlotsScalarized);
        Assert.Equal(2, result.AccessesRewritten);
        Assert.IsType<NamedTarget>(Assert.Single(Assert.IsType<AssignOperation>(
            result.Program.Prototypes[0].Instructions[0].Operation).Targets));
    }

    private static SemanticPrototype Prototype(params SemanticOperation[] operations) => new(
        2,
        1,
        operations.Select((operation, index) => new SemanticInstruction(
            index + 1,
            1,
            operation,
            null,
            new Dictionary<string, SemanticExpression>(),
            new Dictionary<string, SemanticExpression>(),
            Provenance.At(2, index + 1))).ToList(),
        new HashSet<int>());

    private static SemanticProgram Program(SemanticPrototype prototype) =>
        new(new PayloadRoot(2, null), [prototype], [], [], [], []);

    private static RegisterTarget Register(int slot) => new(new NumberExpression(slot.ToString(), Site), Site);
    private static RegisterReadExpression Read(int slot) => new(new NumberExpression(slot.ToString(), Site), Site);
}
