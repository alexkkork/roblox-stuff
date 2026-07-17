using Luraph.Core.Tracing;

namespace Luraph.Core.Tests.Tracing;

public sealed class RuntimeValueTests
{
    [Theory]
    [InlineData("z:", RuntimeValueKind.Nil)]
    [InlineData("b:1", RuntimeValueKind.Boolean)]
    [InlineData("n:-0", RuntimeValueKind.Number)]
    [InlineData("s:6869", RuntimeValueKind.String)]
    [InlineData("t:303", RuntimeValueKind.Table)]
    [InlineData("f:12:7072696E74", RuntimeValueKind.Function)]
    [InlineData("x:userdata", RuntimeValueKind.Opaque)]
    public void DecodesRuntimeValues(string encoded, RuntimeValueKind kind)
    {
        Assert.True(RuntimeValue.TryDecode(encoded, out var value));
        Assert.Equal(kind, value!.Kind);
    }

    [Fact]
    public void KeepsBytesObjectIdsAndVirtualReads()
    {
        Assert.True(RuntimeValue.TryDecode("S:6869", out var text));
        Assert.Equal("hi", text!.Text);
        Assert.Equal(RuntimeReadProvenance.MetatableIndex, text.ReadProvenance);

        Assert.True(RuntimeValue.TryDecode("f:42:7072696e74", out var function));
        Assert.Equal(42UL, function!.ObjectId);
        Assert.Equal("print", function.Text);
    }

    [Theory]
    [InlineData("s:0")]
    [InlineData("n:nope")]
    [InlineData("b:2")]
    [InlineData("t:-1")]
    [InlineData("f:x:00")]
    public void RejectsMalformedValues(string encoded)
    {
        Assert.False(RuntimeValue.TryDecode(encoded, out _));
    }
}
