using System.Globalization;
using System.Text;

namespace Luraph.Core.Tracing;

public enum RuntimeValueKind
{
    Nil,
    Boolean,
    Number,
    String,
    Table,
    Function,
    Opaque,
}

public enum RuntimeReadProvenance
{
    RawTable,
    MetatableIndex,
}

public sealed record RuntimeValue
{
    public required RuntimeValueKind Kind { get; init; }
    public required string Encoded { get; init; }
    public RuntimeReadProvenance ReadProvenance { get; init; }
    public string? Text { get; init; }
    public string? NumberText { get; init; }
    public bool? Boolean { get; init; }
    public ulong? ObjectId { get; init; }
    public string? TypeName { get; init; }
    public byte[]? Bytes { get; init; }

    public static bool TryDecode(string encoded, out RuntimeValue? value)
    {
        value = null;
        if (encoded.Length < 2 || encoded[1] != ':')
            return false;

        var virtualRead = char.IsAsciiLetterUpper(encoded[0]);
        var tag = char.ToLowerInvariant(encoded[0]);
        var body = encoded[2..];
        var provenance = virtualRead
            ? RuntimeReadProvenance.MetatableIndex
            : RuntimeReadProvenance.RawTable;

        switch (tag)
        {
            case 'z' when body.Length == 0:
                value = Make(RuntimeValueKind.Nil);
                return true;
            case 'b' when body is "0" or "1":
                value = Make(RuntimeValueKind.Boolean) with { Boolean = body == "1" };
                return true;
            case 'n' when IsLuauNumber(body):
                value = Make(RuntimeValueKind.Number) with { NumberText = body };
                return true;
            case 's':
                if (!TryHex(body, out var bytes))
                    return false;
                value = Make(RuntimeValueKind.String) with
                {
                    Bytes = bytes,
                    Text = DecodeUtf8(bytes),
                };
                return true;
            case 't':
                if (!ulong.TryParse(body, NumberStyles.None, CultureInfo.InvariantCulture, out var tableId))
                    return false;
                value = Make(RuntimeValueKind.Table) with { ObjectId = tableId };
                return true;
            case 'f':
                return TryFunction(body, Make(RuntimeValueKind.Function), out value);
            case 'x' when body.Length > 0:
                value = Make(RuntimeValueKind.Opaque) with { TypeName = body };
                return true;
            default:
                return false;
        }

        RuntimeValue Make(RuntimeValueKind kind) => new()
        {
            Kind = kind,
            Encoded = encoded,
            ReadProvenance = provenance,
        };
    }

    private static bool TryFunction(string body, RuntimeValue seed, out RuntimeValue? value)
    {
        value = null;
        var colon = body.IndexOf(':');
        ulong? objectId = null;
        var nameHex = body;
        if (colon >= 0)
        {
            if (!ulong.TryParse(body.AsSpan(0, colon), NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
                return false;
            objectId = parsed;
            nameHex = body[(colon + 1)..];
        }

        if (!TryHex(nameHex, out var bytes))
            return false;
        value = seed with
        {
            ObjectId = objectId,
            Bytes = bytes,
            Text = DecodeUtf8(bytes),
        };
        return true;
    }

    private static bool TryHex(string text, out byte[] bytes)
    {
        bytes = [];
        if ((text.Length & 1) != 0)
            return false;
        try
        {
            bytes = Convert.FromHexString(text);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string? DecodeUtf8(byte[] bytes)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    private static bool IsLuauNumber(string text)
    {
        if (text is "nan" or "-nan" or "inf" or "+inf" or "-inf")
            return true;
        return double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out _);
    }
}
