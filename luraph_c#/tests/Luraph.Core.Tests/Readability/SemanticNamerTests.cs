using Luraph.Core.Ir;
using Luraph.Core.Readability;

namespace Luraph.Core.Tests.Readability;

public sealed class SemanticNamerTests
{
    [Fact]
    public void ServiceLocalGetsAStableSemanticName()
    {
        Provenance site = Provenance.At(1, 1);
        IdentifierExpression game = new("game", site);
        CallExpression getService = new(
            new IndexExpression(game, new StringExpression("GetService", site), false, site),
            [game, new StringExpression("Players", site)],
            new ResultArity(1),
            null,
            site);
        SemanticPrototype prototype = new(
            1,
            1,
            [
                new SemanticInstruction(
                    1,
                    1,
                    new AssignOperation([new NamedTarget("local_1", site)], [getService], site),
                    null,
                    new Dictionary<string, SemanticExpression>(),
                    new Dictionary<string, SemanticExpression>(),
                    site),
                new SemanticInstruction(
                    2,
                    1,
                    new ReturnOperation([new IdentifierExpression("local_1", site)], new ResultArity(1), site),
                    null,
                    new Dictionary<string, SemanticExpression>(),
                    new Dictionary<string, SemanticExpression>(),
                    Provenance.At(1, 2)),
            ],
            new HashSet<int>(),
            ["local_1"]);
        SemanticProgram program = new(new PayloadRoot(1, null), [prototype], [], [], [], []);

        SemanticNamingResult result = new SemanticNamer().Apply(program);
        SemanticPrototype renamed = result.Program.Prototypes[0];
        AssignOperation assignment = Assert.IsType<AssignOperation>(renamed.Instructions[0].Operation);
        ReturnOperation returned = Assert.IsType<ReturnOperation>(renamed.Instructions[1].Operation);

        Assert.Equal(["players"], renamed.Locals);
        Assert.Equal("players", Assert.IsType<NamedTarget>(assignment.Targets[0]).Name);
        Assert.Equal("players", Assert.IsType<IdentifierExpression>(returned.Values[0]).Name);
        Assert.Equal(1, result.NamesChanged);
    }
}
