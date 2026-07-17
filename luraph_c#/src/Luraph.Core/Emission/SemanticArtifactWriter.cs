using System.Text.Json;
using Luraph.Core.Ir;
using Luraph.Core.Lifting;

namespace Luraph.Core.Emission;

public sealed record SemanticArtifactPaths(
    string Candidate,
    string? Reconstructed,
    string SemanticIr,
    string Cfg,
    string Mapping,
    string Metrics);

public sealed class SemanticArtifactWriter
{
    public async Task<SemanticArtifactPaths> WriteAsync(
        string outputDirectory,
        LiftResult lift,
        SemanticCandidate candidate,
        CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(outputDirectory);
        string candidatePath = Path.Combine(outputDirectory, "candidate.luau");
        string? reconstructedPath = candidate.FullyRendered
            ? Path.Combine(outputDirectory, "reconstructed.luau")
            : null;
        string semanticIrPath = Path.Combine(outputDirectory, "semantic_ir.json");
        string cfgPath = Path.Combine(outputDirectory, "cfg.json");
        string mappingPath = Path.Combine(outputDirectory, "mapping.json");
        string metricsPath = Path.Combine(outputDirectory, "readability.json");

        JsonSerializerOptions json = JsonDefaults.Create();
        await File.WriteAllTextAsync(candidatePath, candidate.Source, cancellationToken);
        if (reconstructedPath is not null)
            await File.WriteAllTextAsync(reconstructedPath, candidate.Source, cancellationToken);
        await WriteJsonAsync(semanticIrPath, lift.Program, json, cancellationToken);
        await WriteJsonAsync(cfgPath, lift.ControlFlow, json, cancellationToken);
        await WriteJsonAsync(mappingPath, candidate.Mapping, json, cancellationToken);
        await WriteJsonAsync(metricsPath, candidate.Metrics, json, cancellationToken);

        return new SemanticArtifactPaths(
            candidatePath,
            reconstructedPath,
            semanticIrPath,
            cfgPath,
            mappingPath,
            metricsPath);
    }

    private static async Task WriteJsonAsync<T>(
        string path,
        T value,
        JsonSerializerOptions options,
        CancellationToken cancellationToken)
    {
        await using FileStream output = new(path, FileMode.Create, FileAccess.Write, FileShare.None);
        await JsonSerializer.SerializeAsync(output, value, options, cancellationToken);
        await output.FlushAsync(cancellationToken);
    }
}
