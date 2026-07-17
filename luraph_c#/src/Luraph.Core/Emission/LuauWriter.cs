using System.Text;

namespace Luraph.Core.Emission;

internal sealed class LuauWriter
{
    private readonly StringBuilder source = new();

    public int Line { get; private set; } = 1;

    public void Write(string value)
    {
        source.Append(value);
        Line += value.Count(character => character == '\n');
    }

    public void WriteLine(int depth, string value = "")
    {
        source.Append(' ', depth * 2);
        source.AppendLine(value);
        Line++;
    }

    public override string ToString() => source.ToString();
}
