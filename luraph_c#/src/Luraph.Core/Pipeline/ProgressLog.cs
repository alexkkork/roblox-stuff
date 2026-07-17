namespace Luraph.Core.Pipeline;

public sealed class ProgressLog(IProgress<ProgressEvent>? target = null)
{
    private readonly List<ProgressEvent> events = [];

    public IReadOnlyList<ProgressEvent> Events => events;

    public void Add(string stage, string status, string message, System.Text.Json.Nodes.JsonObject? metrics = null, int attempt = 1)
    {
        ProgressEvent item = new(stage, status, message, metrics, attempt);
        events.Add(item);
        target?.Report(item);
    }
}
