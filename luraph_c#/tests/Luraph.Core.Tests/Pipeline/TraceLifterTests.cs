using Luraph.Core.Pipeline;
using Luraph.Core.Tracing;

namespace Luraph.Core.Tests.Pipeline;

public sealed class TraceLifterTests
{
    [Fact]
    public void RecoversTheCommittedPayloadClosure()
    {
        string fixtures = Path.Combine(AppContext.BaseDirectory, "Fixtures");
        string traceText = File.ReadAllText(Path.Combine(fixtures, "subject_1b642e9523c1_refined_trace.log"));
        string handlers = File.ReadAllText(Path.Combine(fixtures, "opcode_handlers.json"));

        LuraphTraceDocument trace = new LuraphTraceParser().Parse(traceText);
        TraceLiftResult result = new TraceLifter().Lift(trace, handlers);

        Assert.True(result.Complete, result.Reason);
        Assert.Equal(29, result.PrototypeCount);
        Assert.Equal(8548, result.InstructionCount);
        Assert.Equal(8548, result.ClassifiedInstructions);
        Assert.Equal(5, result.ClosureActivations);
        Assert.Equal(3, result.ClosurePrototypes);
        Assert.Equal(385, result.ClosureInstructions);
        Assert.Equal(757, result.ObservedClosureSteps);
        Assert.Equal(385, result.InstructionCoverage.Count);
        Assert.Contains(result.InstructionCoverage, item => item.Disposition == "emitted_statement");
        Assert.Contains(result.InstructionCoverage, item => item.Disposition == "runtime_value_producer");
        Assert.Contains(result.InstructionCoverage, item => item.Disposition == "runtime_value_decoder_elided");
        Assert.Equal("print(\"anti tamper BYPASSED\")\n", result.Source);
    }
}
