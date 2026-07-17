using System.Security.Cryptography;

namespace Luraph.Core.Pipeline;

public static class FileHash
{
    public static string Sha256(ReadOnlySpan<byte> value) => Convert.ToHexStringLower(SHA256.HashData(value));
}
