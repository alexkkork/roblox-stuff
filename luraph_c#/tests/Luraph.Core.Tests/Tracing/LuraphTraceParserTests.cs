using System.Text;
using Luraph.Core.Tracing;

namespace Luraph.Core.Tests.Tracing;

public sealed class LuraphTraceParserTests
{
    private const string SyntheticTrace = """
        @@LPH_PROTO_V1@@	1	2	D,G
        @@LPH_PROTO_OBJECT_V1@@	1	101
        @@LPH_INSN_V1@@	1	1	77	D=n:4|G=S:6869
        @@LPH_LANE_TOP_V1@@	1	1	D	n:5	t:303
        @@LPH_LANE_TABLE_V1@@	1	1	D	1	/n:5	n:1	f:44:6362
        @@LPH_ACT_PROTO_V1@@	9	1	nil	nil	nil	12	1	s:6869|z:	123
        @@LPH_ACT_ARG_TABLE_V1@@	9	1	1	n:3	f:74726163656261636b
        @@LPH_CAPTURE_DOMAIN_V1@@	9	1	1	2	0,7
        @@LPH_ACTIVATION@@	123	9	nil	nil	nil	2	1:string:hi|2:nil:nil
        @@LPH_CALL_V2@@	124	9	nil	nil	nil	1	77	4	print	2	s:6869|n:2
        @@LPH_VM@@	125	9	nil	nil	nil	1	77	4	function	print	print	string	hi		5	number	2		6	table	table		nil	nil	nil
        @@LPH_STEP_V1@@	126	9	1	77	2	2	4=n:5|5=z:	D=n:4|G=S:6869
        @@LPH_RETURN_V1@@	127	9	2	31	3	3	n:1|z:|s:6869
        ordinary output
        """;

    [Fact]
    public void ParsesEveryCurrentMarker()
    {
        var trace = new LuraphTraceParser().Parse(SyntheticTrace);

        Assert.Equal(13, trace.Summary.MarkerRows);
        Assert.Equal(0, trace.Summary.MalformedRows);
        Assert.Equal(13, trace.Records.Count);
        Assert.Equal("ordinary output", Assert.Single(trace.OutputLines));

        var call = Assert.Single(trace.OfType<CallTraceRecord>());
        Assert.Equal("print", call.Target);
        Assert.Equal("hi", call.Arguments[0].Text);

        var instruction = Assert.Single(trace.OfType<InstructionTraceRecord>());
        Assert.Equal(RuntimeReadProvenance.MetatableIndex, instruction.Lanes["G"].ReadProvenance);

        var activation = Assert.Single(trace.OfType<ActivationPrototypeTraceRecord>());
        Assert.Equal(12, activation.ArgumentCount);
        Assert.Equal(2, activation.Arguments.Count);
        Assert.Equal(123UL, activation.EntryVmCount);

        var step = Assert.Single(trace.OfType<StepTraceRecord>());
        Assert.Equal(2, step.RegisterWrites.Count);
        Assert.Equal(2, step.NextPc);

        var returned = Assert.Single(trace.OfType<ReturnTraceRecord>());
        Assert.True(returned.Complete);
        Assert.Equal(RuntimeValueKind.Nil, returned.Values[1].Kind);
    }

    [Fact]
    public void CountsMalformedRowsWithoutKeepingThem()
    {
        var trace = new LuraphTraceParser().Parse(
            "@@LPH_RETURN_V1@@\t1\t2\t3\t4\t1\t2\tn:1|n:2\n" +
            "@@LPH_WHATEVER@@\t1\n");

        Assert.Empty(trace.Records);
        Assert.Equal(2, trace.Summary.MalformedRows);
        Assert.Equal(["bad_return", "unknown_marker"], trace.Diagnostics.Select(item => item.Code));
    }

    [Fact]
    public async Task StopsAtByteAndRowLimits()
    {
        var rows = string.Join('\n', Enumerable.Repeat("@@LPH_PROTO_OBJECT_V1@@\t1\t2", 8)) + "\n";
        await using var input = new MemoryStream(Encoding.UTF8.GetBytes(rows));
        var parser = new LuraphTraceParser();
        var byBytes = await parser.ParseAsync(input, new TraceParseOptions { MaxBytes = 40 });

        Assert.True(byBytes.Summary.ByteLimitHit);
        Assert.InRange(byBytes.Records.Count, 0, 1);

        var byRows = parser.Parse(rows, new TraceParseOptions { MaxRows = 3 });
        Assert.True(byRows.Summary.RowLimitHit);
        Assert.Equal(3, byRows.Records.Count);
    }
}
