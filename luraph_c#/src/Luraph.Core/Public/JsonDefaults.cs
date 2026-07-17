using System.Text.Json;
using System.Text.Json.Serialization;

namespace Luraph.Core;

public static class JsonDefaults
{
    public static JsonSerializerOptions Create(bool indented = true) => new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = indented,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };
}
