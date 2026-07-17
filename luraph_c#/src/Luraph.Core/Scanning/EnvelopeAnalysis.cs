using Luraph.Core.Containers;

namespace Luraph.Core.Scanning;

public sealed record EnvelopeAnalysis
{
    public bool Complete { get; internal set; }
    public bool Bounded { get; init; } = true;
    public bool FamilyDetected { get; internal set; }
    public bool VersionSupported { get; internal set; }
    public bool SourceRecoveryAttempted { get; init; }
    public BannerInfo Banner { get; internal set; } = new();
    public LuaAuthLauncherInfo LuaAuthLauncher { get; internal set; } = new();
    public WrapperShape Wrapper { get; internal set; } = new();
    public EnvelopeCounts Counts { get; } = new();
    public List<BlobCandidate> Blobs { get; } = [];
    public StaticDecodeMetrics StaticDecode { get; } = new();
    public List<CarrierExtraction> Carriers { get; } = [];
    public ContainerMetrics ContainerMetrics { get; } = new();
    public List<ContainerAnalysis> Containers { get; } = [];
    public List<ReaderMetadata> Readers { get; } = [];
    public List<ScanStage> Stages { get; } = [];
    public ScanConfidence Confidence { get; } = new();
    public List<ScanDiagnostic> Diagnostics { get; } = [];
}
