using Luraph.Core.Runtime;
using Luraph.Core.Tracing;

namespace Luraph.Core.Tests.Runtime;

public sealed class RbxRuntimeRunnerTests
{
    [Fact]
    public async Task CapturesTraceReportAndCleansTempFiles()
    {
        if (OperatingSystem.IsWindows())
            return;
        using var fixture = FakeRuntime.Create("""
            trace=""
            report=""
            while [ "$#" -gt 0 ]; do
              case "$1" in
                --probe-trace) trace="$2"; shift 2 ;;
                --report) report="$2"; shift 2 ;;
                *) shift ;;
              esac
            done
            printf '@@LPH_PROTO_V1@@\t1\t1\tD\n' > "$trace"
            printf '{"termination_reason":"completed"}\n' > "$report"
            printf 'payload output\n'
            printf 'runtime note\n' >&2
            """);

        var result = await new RbxRuntimeRunner().RunAsync(fixture.Request());

        Assert.Equal(RuntimeRunStatus.Completed, result.Status);
        Assert.Equal("payload output\n", result.StandardOutput);
        Assert.Equal("runtime note\n", result.StandardError);
        Assert.Single(result.Trace!.OfType<PrototypeTraceRecord>());
        Assert.Equal("completed", result.Report!["termination_reason"]!.GetValue<string>());
        Assert.True(result.TemporaryFilesRemoved);
        Assert.Empty(Directory.EnumerateFileSystemEntries(fixture.TempRoot));
    }

    [Fact]
    public async Task StopsOnTimeoutAndCancellation()
    {
        if (OperatingSystem.IsWindows())
            return;
        using var fixture = FakeRuntime.Create("sleep 5");
        var timed = await new RbxRuntimeRunner().RunAsync(fixture.Request() with
        {
            Settings = new RuntimeSettings { Timeout = TimeSpan.FromMilliseconds(80) },
        });
        Assert.Equal(RuntimeRunStatus.TimedOut, timed.Status);

        using var cancelled = new CancellationTokenSource(TimeSpan.FromMilliseconds(80));
        var stopped = await new RbxRuntimeRunner().RunAsync(fixture.Request(), cancelled.Token);
        Assert.Equal(RuntimeRunStatus.Cancelled, stopped.Status);
    }

    [Fact]
    public async Task StopsWhenCombinedOutputHitsItsCap()
    {
        if (OperatingSystem.IsWindows())
            return;
        using var fixture = FakeRuntime.Create("""
            i=0
            while [ "$i" -lt 1000 ]; do
              printf '1234567890'
              i=$((i + 1))
            done
            """);
        var request = fixture.Request() with
        {
            Probe = null,
            Source = "return 1",
            ForceLuraph = false,
            TraceEnabled = false,
            MaxOutputBytes = 128,
        };

        var result = await new RbxRuntimeRunner().RunAsync(request);

        Assert.Equal(RuntimeRunStatus.OutputLimit, result.Status);
        Assert.True(result.OutputTruncated);
        Assert.InRange(System.Text.Encoding.UTF8.GetByteCount(result.StandardOutput), 1, 128);
        Assert.True(result.TemporaryFilesRemoved);
    }

    private sealed class FakeRuntime : IDisposable
    {
        private FakeRuntime(string root, string binary, string tempRoot)
        {
            Root = root;
            Binary = binary;
            TempRoot = tempRoot;
        }

        public string Root { get; }
        public string Binary { get; }
        public string TempRoot { get; }

        public static FakeRuntime Create(string body)
        {
            if (OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException();
            var root = Path.Combine(Path.GetTempPath(), $"luraph-test-{Guid.NewGuid():N}");
            var temp = Path.Combine(root, "runs");
            Directory.CreateDirectory(temp);
            var binary = Path.Combine(root, "runtime.sh");
            File.WriteAllText(binary, "#!/bin/sh\nset -u\n" + body + "\n");
            File.SetUnixFileMode(binary,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            return new FakeRuntime(root, binary, temp);
        }

        public RuntimeRunRequest Request() => new()
        {
            BinaryPath = Binary,
            Probe = new LuraphProbe
            {
                Kind = LuraphProbeKind.CallFocused,
                Source = "return 1",
            },
            Settings = new RuntimeSettings
            {
                Timeout = TimeSpan.FromSeconds(2),
                MemoryLimitMb = 768,
                MaxSteps = 1000,
            },
            TraceOptions = new TraceParseOptions { MaxBytes = 4096 },
            TemporaryRoot = TempRoot,
        };

        public void Dispose()
        {
            if (Directory.Exists(Root))
                Directory.Delete(Root, true);
        }
    }
}
