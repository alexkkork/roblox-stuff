using System.Text.Json;
using System.Text.Json.Nodes;

namespace Luraph.Core.Pipeline;

public sealed class ArtifactStore
{
    private readonly string root;
    private readonly JsonSerializerOptions json;

    public ArtifactStore(string root, JsonSerializerOptions? json = null)
    {
        this.root = Path.GetFullPath(root);
        this.json = json ?? JsonDefaults.Create();
        Directory.CreateDirectory(this.root);
    }

    public string Root => root;

    public string PathFor(string name)
    {
        string path = Path.GetFullPath(Path.Combine(root, name));
        string prefix = root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar;
        if (!path.StartsWith(prefix, StringComparison.Ordinal) && path != root)
            throw new InvalidOperationException("artifact path escaped the output directory");
        return path;
    }

    public Task WriteTextAsync(string name, string value, CancellationToken cancellationToken = default) =>
        WriteBytesAsync(name, System.Text.Encoding.UTF8.GetBytes(value), cancellationToken);

    public Task WriteJsonAsync<T>(string name, T value, CancellationToken cancellationToken = default) =>
        WriteBytesAsync(name, JsonSerializer.SerializeToUtf8Bytes(value, json), cancellationToken);

    public Task WriteJsonAsync(string name, JsonNode value, CancellationToken cancellationToken = default) =>
        WriteBytesAsync(name, JsonSerializer.SerializeToUtf8Bytes(value, json), cancellationToken);

    private async Task WriteBytesAsync(string name, byte[] value, CancellationToken cancellationToken)
    {
        string path = PathFor(name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllBytesAsync(temporary, value, cancellationToken).ConfigureAwait(false);
            File.Move(temporary, path, true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }
}
