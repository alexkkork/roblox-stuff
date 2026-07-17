using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Luraph.Core.Containers;
using Luraph.Core.Containers.Legacy;
using Luraph.Core.Emission;
using Luraph.Core.Runtime;
using Luraph.Core.Scanning;
using Luraph.Core.Tracing;
using Luraph.Core.Vm;

namespace Luraph.Core.Pipeline;

public sealed class LuraphDeobfuscator : ILuraphDeobfuscator
{
    private readonly IRbxRuntimeRunner runtime;
    private readonly ILuraphProbeBuilder probes;
    private readonly LuraphTraceParser traceParser;
    private readonly SemanticReconstructionPipeline semanticPipeline;

    public LuraphDeobfuscator(
        IRbxRuntimeRunner? runtime = null,
        ILuraphProbeBuilder? probes = null,
        LuraphTraceParser? traceParser = null,
        SemanticReconstructionPipeline? semanticPipeline = null)
    {
        this.runtime = runtime ?? new RbxRuntimeRunner();
        this.probes = probes ?? new ProbeBuilder();
        this.traceParser = traceParser ?? new LuraphTraceParser();
        this.semanticPipeline = semanticPipeline ?? new SemanticReconstructionPipeline();
    }

    public async Task<DeobfuscationResult> DeobfuscateAsync(
        DeobfuscationRequest request,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var log = new ProgressLog(progress);
        var store = new ArtifactStore(request.OutputDirectory);
        List<Diagnostic> diagnostics = [];
        List<TracePassSummary> tracePasses = [];
        List<string> traceLogs = [];

        if (!File.Exists(request.InputPath))
            return await FinishInvalidAsync(store, log, diagnostics, "input_missing", "input file was not found", cancellationToken).ConfigureAwait(false);
        byte[] input = await File.ReadAllBytesAsync(request.InputPath, cancellationToken).ConfigureAwait(false);
        string hash = FileHash.Sha256(input);
        if (input.Length > request.Limits.MaxSourceBytes)
            return await FinishInvalidAsync(store, log, diagnostics, "source_limit", "source byte limit exceeded", cancellationToken, hash).ConfigureAwait(false);

        string source;
        try
        {
            source = new UTF8Encoding(false, true).GetString(input);
        }
        catch (DecoderFallbackException)
        {
            return await FinishInvalidAsync(store, log, diagnostics, "invalid_utf8", "input is not valid UTF-8", cancellationToken, hash).ConfigureAwait(false);
        }

        log.Add("detect", "running", "checking the luraph wrapper");
        EnvelopeAnalysis envelope = EnvelopeScanner.Analyze(source, request.Limits);
        LegacyContainerResult legacy = LegacyContainerParser.Analyze(source, new LegacyParseOptions { Limits = request.Limits });
        diagnostics.AddRange(envelope.Diagnostics.Select(item => new Diagnostic(
            "detect", item.Code.ToLowerInvariant(), item.Message, item.Severity,
            item.Range is null ? null : new JsonObject { ["begin"] = item.Range.Value.Begin, ["end"] = item.Range.Value.End })));
        diagnostics.AddRange(legacy.Diagnostics.Select(item => new Diagnostic(
            "decode", item.Code.ToLowerInvariant(), item.Message, item.Severity,
            new JsonObject
            {
                ["byte_offset"] = item.ByteOffset,
                ["carrier_marker"] = legacy.Carrier.Marker,
                ["decoded_bytes"] = legacy.Carrier.DecodedBytes,
            })));
        await WriteStaticArtifactsAsync(store, envelope, legacy, cancellationToken).ConfigureAwait(false);
        log.Add("detect", envelope.FamilyDetected ? "done" : "blocked", envelope.FamilyDetected
            ? $"found luraph {envelope.Banner.Version}"
            : "this isnt a supported luraph wrapper");

        if (!envelope.FamilyDetected || !envelope.VersionSupported)
        {
            diagnostics.Add(new("detect", envelope.FamilyDetected ? "unsupported_version" : "unsupported_family",
                envelope.FamilyDetected ? "only Luraph v14.7 is supported" : "input does not match the Luraph envelope"));
            return await FinishAsync(store, log, hash, DeobfuscationStatus.Invalid, Coverage(envelope, legacy),
                new(), diagnostics, tracePasses, new ArtifactManifest(), cancellationToken).ConfigureAwait(false);
        }

        if (request.Mode is DeobfuscationMode.Inspect or DeobfuscationMode.Disassemble)
        {
            DeobfuscationStatus status = request.Mode == DeobfuscationMode.Inspect
                ? DeobfuscationStatus.Inspected
                : DeobfuscationStatus.Disassembled;
            log.Add(request.Mode == DeobfuscationMode.Inspect ? "inspect" : "disassemble", "done", "static files are done");
            return await FinishAsync(store, log, hash, status, Coverage(envelope, legacy), new(), diagnostics,
                tracePasses, new ArtifactManifest(), cancellationToken).ConfigureAwait(false);
        }

        string? traceText = await ReadTraceAsync(request.TracePath, request.Limits.MaxTraceBytes, cancellationToken).ConfigureAwait(false);
        string? opcodeHandlersJson = null;
        if (!string.IsNullOrWhiteSpace(request.TracePath))
        {
            string? traceDirectory = Path.GetDirectoryName(Path.GetFullPath(request.TracePath));
            string handlersPath = Path.Combine(traceDirectory!, "opcode_handlers.json");
            if (File.Exists(handlersPath))
                opcodeHandlersJson = await File.ReadAllTextAsync(handlersPath, cancellationToken).ConfigureAwait(false);
        }
        bool targetedTrace = request.TraceWindowStart.HasValue || request.TraceWindowEnd.HasValue;
        if (targetedTrace && (!request.TraceWindowStart.HasValue || !request.TraceWindowEnd.HasValue ||
            request.TraceWindowStart <= 0 || request.TraceWindowEnd < request.TraceWindowStart))
        {
            diagnostics.Add(new("trace", "invalid_trace_window", "trace window needs START > 0 and END >= START"));
            return await FinishAsync(store, log, hash, DeobfuscationStatus.Invalid, Coverage(envelope, legacy), new(),
                diagnostics, tracePasses, new ArtifactManifest(), cancellationToken).ConfigureAwait(false);
        }
        if ((!HasStructureTrace(traceText) || targetedTrace) && request.Runtime.AutoTrace)
        {
            if (string.IsNullOrWhiteSpace(request.Runtime.BinaryPath))
            {
                diagnostics.Add(new("trace", "runtime_unavailable", "the bundled runtime was not found; use --runtime PATH"));
            }
            else
            {
                ProbePipelineResult probeResult = await RunProbePassesAsync(request, source, traceText, store, log, diagnostics,
                    tracePasses, traceLogs, cancellationToken).ConfigureAwait(false);
                traceText = probeResult.Trace;
                if (!string.IsNullOrWhiteSpace(probeResult.OpcodeHandlersJson))
                    await store.WriteTextAsync("opcode_handlers.json", probeResult.OpcodeHandlersJson, cancellationToken).ConfigureAwait(false);
                opcodeHandlersJson = probeResult.OpcodeHandlersJson;
            }
        }

        ArtifactManifest baseArtifacts = new() { TraceLogs = traceLogs };
        if (string.IsNullOrWhiteSpace(traceText))
        {
            diagnostics.Add(new("trace", "trace_required", "a complete structure trace is required for reconstruction"));
            return await FinishAsync(store, log, hash, DeobfuscationStatus.Blocked, Coverage(envelope, legacy), new(),
                diagnostics, tracePasses, baseArtifacts, cancellationToken).ConfigureAwait(false);
        }

        LuraphTraceDocument trace = traceParser.Parse(traceText, new TraceParseOptions { MaxBytes = request.Limits.MaxTraceBytes });
        SemanticAttemptResult? semanticAttempt = await TryBuildSemanticCandidateAsync(
            request, source, traceText, store, log, diagnostics, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(semanticAttempt?.Analysis.OpcodeHandlersJson))
            opcodeHandlersJson = semanticAttempt.Analysis.OpcodeHandlersJson;
        baseArtifacts = baseArtifacts with
        {
            SemanticCandidate = semanticAttempt?.Reconstruction is null ? null : "semantic_candidate.luau",
            Readability = semanticAttempt?.Reconstruction is null ? null : "readability.json",
            NativeReport = semanticAttempt?.Analysis.NativeReportJson is null ? null : "native_report.json",
            NativeSemanticIr = semanticAttempt?.Analysis.SemanticIrJson is null ? null : "native_semantic_ir.json",
            NativeCandidate = semanticAttempt?.Analysis.NativeCandidateSource is null ? null : "native_semantic_candidate.luau",
        };

        log.Add("lift", "running", "rebuilding the payload from vm events");
        TraceLiftResult traceLift = new TraceLifter().Lift(trace, opcodeHandlersJson);
        bool useSemantic = semanticAttempt?.Ready == true;
        string? candidateSource;
        CoverageSummary coverage;
        if (useSemantic)
        {
            SemanticReconstructionResult semantic = semanticAttempt!.Reconstruction!;
            candidateSource = semantic.Candidate.Source;
            coverage = Coverage(envelope, legacy, traceLift, semantic);
            log.Add("lift", "done", $"lifted {semantic.Candidate.Metrics.Operations} semantic operations");
            diagnostics.Add(new("lift", "luraph_semantic_graph_reconstructed",
                "the candidate was rebuilt from typed semantic IR and a validated CFG; original names, comments, and formatting are not claimed",
                DiagnosticSeverity.Info));
        }
        else
        {
            await WriteTraceArtifactsAsync(store, trace, traceLift, cancellationToken).ConfigureAwait(false);
            coverage = semanticAttempt?.Reconstruction is SemanticReconstructionResult partialSemantic
                ? Coverage(envelope, legacy, traceLift, partialSemantic, semanticPromoted: false)
                : Coverage(envelope, legacy, traceLift);
            candidateSource = traceLift.Source;
        }

        if (!useSemantic && (!traceLift.Complete || candidateSource is null))
        {
            diagnostics.Add(new("lift", "semantic_lift_incomplete", traceLift.Reason ?? "reachable payload operations remain unresolved"));
            log.Add("lift", "blocked", "some payload ops are still unknown");
            return await FinishAsync(store, log, hash, DeobfuscationStatus.Blocked, coverage, new(), diagnostics,
                tracePasses, baseArtifacts, cancellationToken).ConfigureAwait(false);
        }

        await store.WriteTextAsync("candidate.luau", candidateSource!, cancellationToken).ConfigureAwait(false);
        log.Add("trace", "done", "got the whole traced payload", new JsonObject
        {
            ["payload_activation_complete"] = true,
            ["payload_calls"] = traceLift.Statements.Count,
            ["decoder_prototypes"] = Math.Max(0, traceLift.ClosurePrototypes - 1),
            ["reachable_instructions"] = traceLift.ClosureInstructions,
        });
        if (!useSemantic)
        {
            log.Add("lift", "done", $"lifted {traceLift.RootSteps} payload vm steps");
            diagnostics.Add(new("lift", "luraph_trace_payload_reconstructed",
                "the candidate is an observed-trace reconstruction; original names, comments, formatting, and unobserved paths are not claimed",
                DiagnosticSeverity.Info));
        }

        if (string.IsNullOrWhiteSpace(request.Runtime.BinaryPath))
        {
            diagnostics.Add(new("verify", "runtime_unavailable", "candidate was not promoted because no runtime was supplied"));
            return await FinishAsync(store, log, hash, DeobfuscationStatus.Blocked, coverage, new(), diagnostics,
                tracePasses, baseArtifacts with { Candidate = "candidate.luau" }, cancellationToken).ConfigureAwait(false);
        }

        log.Add("verify", "running", "compiling and running both versions");
        RuntimeVerificationResult verified = await new RuntimeVerifier(runtime).VerifyAsync(
            request.Runtime.BinaryPath, source, candidateSource!, request.Runtime, cancellationToken).ConfigureAwait(false);
        if (!verified.Summary.Compiled || !verified.Summary.Equivalent)
        {
            string code = !verified.Summary.Compiled
                ? "candidate_compile_failed"
                : verified.Candidate?.Status != RuntimeRunStatus.Completed
                    ? "candidate_runtime_failed"
                    : "runtime_mismatch";
            diagnostics.Add(new("verify", code,
                verified.Summary.Reason ?? "candidate verification failed"));
            log.Add("verify", "blocked", verified.Summary.Reason ?? "the rebuilt script didnt match");
            return await FinishAsync(store, log, hash, DeobfuscationStatus.Blocked, coverage, verified.Summary,
                diagnostics, tracePasses, baseArtifacts with { Candidate = "candidate.luau" }, cancellationToken).ConfigureAwait(false);
        }

        await store.WriteTextAsync("reconstructed.luau", candidateSource!, cancellationToken).ConfigureAwait(false);
        log.Add("verify", "done", "both versions did the same thing");
        return await FinishAsync(store, log, hash, DeobfuscationStatus.Reconstructed, coverage, verified.Summary,
            diagnostics, tracePasses, baseArtifacts with
            {
                Candidate = "candidate.luau",
                Reconstructed = "reconstructed.luau",
            }, cancellationToken).ConfigureAwait(false);
    }

    private sealed record ProbePipelineResult(string? Trace, string? OpcodeHandlersJson);

    private sealed record SemanticAttemptResult(
        ProbeAnalysisResult Analysis,
        SemanticReconstructionResult? Reconstruction)
    {
        public bool Ready => Reconstruction?.Ready == true;
    }

    private async Task<SemanticAttemptResult?> TryBuildSemanticCandidateAsync(
        DeobfuscationRequest request,
        string source,
        string trace,
        ArtifactStore store,
        ProgressLog log,
        List<Diagnostic> diagnostics,
        CancellationToken cancellationToken)
    {
        log.Add("structure", "running", "building the full semantic graph");
        ProbeAnalysisResult analysis = await probes.AnalyzeAsync(
            request.InputPath,
            source,
            trace,
            request.Runtime.BinaryPath,
            request.Runtime.Timeout,
            request.Limits.MaxTraceBytes,
            cancellationToken).ConfigureAwait(false);

        if (analysis.NativeReportJson is not null)
            await store.WriteTextAsync("native_report.json", analysis.NativeReportJson, cancellationToken).ConfigureAwait(false);
        if (analysis.NativeCandidateSource is not null)
            await store.WriteTextAsync("native_semantic_candidate.luau", analysis.NativeCandidateSource, cancellationToken).ConfigureAwait(false);
        if (analysis.OpcodeHandlersJson is not null)
            await store.WriteTextAsync("opcode_handlers.json", analysis.OpcodeHandlersJson, cancellationToken).ConfigureAwait(false);
        if (analysis.SemanticIrJson is not null)
            await store.WriteTextAsync("native_semantic_ir.json", analysis.SemanticIrJson, cancellationToken).ConfigureAwait(false);
        if (analysis.ControlFlowJson is not null)
            await store.WriteTextAsync("native_cfg.json", analysis.ControlFlowJson, cancellationToken).ConfigureAwait(false);

        if (!analysis.HasSemanticArtifacts)
        {
            diagnostics.Add(new("structure", "semantic_artifacts_unavailable",
                analysis.Reason ?? "the final semantic IR and CFG were not available", DiagnosticSeverity.Info));
            log.Add("structure", "blocked", "full semantic artifacts were not available");
            return new SemanticAttemptResult(analysis, null);
        }

        try
        {
            if (!HasCompatibleSemanticGraph(analysis.SemanticIrJson!, analysis.ControlFlowJson!))
            {
                diagnostics.Add(new("structure", "semantic_graph_unavailable",
                    "the oracle produced an observed-effect graph instead of a full prototype CFG", DiagnosticSeverity.Info));
                log.Add("structure", "blocked", "a full prototype CFG was not available");
                return new SemanticAttemptResult(analysis, null);
            }

            SemanticReconstructionResult reconstruction = semanticPipeline.Reconstruct(
                analysis.SemanticIrJson!, analysis.ControlFlowJson!);
            await store.WriteJsonAsync("semantic_ir.json", reconstruction.Lift.Program, cancellationToken).ConfigureAwait(false);
            await store.WriteJsonAsync("cfg.json", reconstruction.Lift.ControlFlow, cancellationToken).ConfigureAwait(false);
            await store.WriteJsonAsync("mapping.json", reconstruction.Candidate.Mapping, cancellationToken).ConfigureAwait(false);
            await store.WriteJsonAsync("readability.json", new
            {
                ready = reconstruction.Ready,
                graph_valid = reconstruction.Lift.Validation.Valid,
                stats = reconstruction.Readability.Stats,
                metrics = reconstruction.Candidate.Metrics,
                unresolved = reconstruction.Candidate.Unresolved,
            }, cancellationToken).ConfigureAwait(false);
            await store.WriteTextAsync("semantic_candidate.luau", reconstruction.Candidate.Source, cancellationToken).ConfigureAwait(false);

            JsonObject metrics = new()
            {
                ["structured_blocks"] = reconstruction.Readability.Stats.StructuredBlocks,
                ["residual_blocks"] = reconstruction.Readability.Stats.ResidualBlocks,
                ["register_slots"] = reconstruction.Readability.Stats.RegisterSlots,
                ["register_accesses"] = reconstruction.Readability.Stats.RegisterAccesses,
                ["names_improved"] = reconstruction.Readability.Stats.NamesImproved,
                ["unsupported_expressions"] = reconstruction.Candidate.Metrics.UnsupportedExpressions,
                ["unsupported_operations"] = reconstruction.Candidate.Metrics.UnsupportedOperations,
            };
            log.Add("structure", reconstruction.Ready ? "done" : "blocked",
                reconstruction.Ready ? "the semantic graph is fully renderable" : "the semantic graph still has unresolved facts",
                metrics);
            if (!reconstruction.Ready)
            {
                diagnostics.Add(new("structure", "semantic_candidate_incomplete",
                    "a semantic candidate was emitted for inspection but was not promoted because unresolved operations or CFG facts remain",
                    DiagnosticSeverity.Warning,
                    metrics));
            }
            return new SemanticAttemptResult(analysis, reconstruction);
        }
        catch (Exception error) when (error is JsonException or InvalidDataException or InvalidOperationException or ArgumentException or OverflowException)
        {
            diagnostics.Add(new("structure", "semantic_import_failed", error.Message));
            log.Add("structure", "blocked", "the semantic artifacts could not be imported");
            return new SemanticAttemptResult(analysis, null);
        }
    }

    private static bool HasCompatibleSemanticGraph(string semanticIrJson, string cfgJson)
    {
        using JsonDocument semantic = JsonDocument.Parse(semanticIrJson);
        using JsonDocument cfg = JsonDocument.Parse(cfgJson);
        if (!semantic.RootElement.TryGetProperty("prototypes", out JsonElement semanticRows) ||
            semanticRows.ValueKind != JsonValueKind.Array ||
            !cfg.RootElement.TryGetProperty("prototypes", out JsonElement cfgRows) ||
            cfgRows.ValueKind != JsonValueKind.Array)
            return false;

        HashSet<ulong> semanticIds = semanticRows.EnumerateArray()
            .Where(row => row.TryGetProperty("runtime_id", out JsonElement id) && id.TryGetUInt64(out ulong value) && value > 0)
            .Select(row => row.GetProperty("runtime_id").GetUInt64())
            .ToHashSet();
        return semanticIds.Count > 0 && cfgRows.EnumerateArray().Any(row =>
            row.TryGetProperty("runtime_id", out JsonElement id) &&
            id.TryGetUInt64(out ulong value) &&
            semanticIds.Contains(value));
    }

    private async Task<ProbePipelineResult> RunProbePassesAsync(
        DeobfuscationRequest request,
        string source,
        string? startingTrace,
        ArtifactStore store,
        ProgressLog log,
        List<Diagnostic> diagnostics,
        List<TracePassSummary> summaries,
        List<string> logs,
        CancellationToken cancellationToken)
    {
        string? trace = startingTrace;
        string? handlers = null;
        bool targeted = request.TraceWindowStart.HasValue && request.TraceWindowEnd.HasValue;
        int maxPasses = targeted ? 1 : Math.Clamp(request.Runtime.MaxProbePasses, 1, 2);
        for (int pass = 1; pass <= maxPasses && (targeted || !HasStructureTrace(trace)); pass++)
        {
            log.Add("trace", "running", targeted
                ? $"capturing vm steps {request.TraceWindowStart}-{request.TraceWindowEnd}"
                : pass == 1 && string.IsNullOrWhiteSpace(trace)
                ? "making the call probe"
                : "making the payload probe", attempt: pass);
            ProbeBuildResult built = await probes.BuildAsync(request.InputPath, source, trace, request.Runtime.BinaryPath,
                request.Runtime.Timeout, request.TraceWindowStart, request.TraceWindowEnd, cancellationToken).ConfigureAwait(false);
            if (built.Probe is null)
            {
                diagnostics.Add(new("trace", "probe_build_failed", built.Reason ?? "probe generation failed"));
                break;
            }
            handlers = built.OpcodeHandlersJson ?? handlers;
            diagnostics.Add(new("trace", "native_probe_oracle",
                "the temporary probe was generated by the C++ parity oracle during shadow migration", DiagnosticSeverity.Info));

            RuntimeRunResult run = await runtime.RunAsync(RuntimeRunRequest.ForProbe(
                request.Runtime.BinaryPath!, built.Probe, request.Runtime) with
            {
                TraceOptions = new TraceParseOptions { MaxBytes = request.Limits.MaxTraceBytes },
                MaxOutputBytes = request.Limits.MaxTraceBytes,
            }, cancellationToken).ConfigureAwait(false);
            summaries.Add(run.ToPassSummary(built.Probe));
            trace = MergeTrace(targeted ? trace : null, run);
            string name = $"trace_pass_{pass}.log";
            await store.WriteTextAsync(name, trace, cancellationToken).ConfigureAwait(false);
            logs.Add(name);
            bool structureReady = HasStructureTrace(trace);
            bool canRefine = !targeted && run.Reason == "instruction_budget" &&
                !string.IsNullOrWhiteSpace(trace) &&
                trace.Contains(LuraphTraceMarkers.Call, StringComparison.Ordinal) &&
                pass < maxPasses;
            string status = run.Status == RuntimeRunStatus.Completed
                ? "done"
                : structureReady || canRefine ? "partial" : "blocked";
            string message = run.Status == RuntimeRunStatus.Completed
                ? targeted ? "got the requested vm trace window" : $"got trace pass {pass}"
                : structureReady ? "the bounded run produced a complete structure trace"
                : canRefine ? "the bounded call trace is enough to build the payload probe"
                : run.Reason ?? "trace run failed";
            log.Add("trace", status, message, attempt: pass);
            if (canRefine)
            {
                diagnostics.Add(new("trace", "bounded_trace_refinement",
                    "the call-focused run reached its instruction budget, but its bounded trace was retained for the payload probe",
                    DiagnosticSeverity.Info));
                continue;
            }
            if (run.Status != RuntimeRunStatus.Completed && !structureReady)
                break;
        }
        return new(trace, handlers);
    }

    private static string MergeTrace(string? existing, RuntimeRunResult run)
    {
        string captured;
        if (string.IsNullOrEmpty(run.TraceText))
            captured = run.StandardOutput;
        else if (string.IsNullOrEmpty(run.StandardOutput))
            captured = run.TraceText;
        else
            captured = JoinTrace(run.TraceText, run.StandardOutput);
        return string.IsNullOrEmpty(existing) ? captured : JoinTrace(existing, captured);
    }

    private static string JoinTrace(string first, string second) =>
        string.IsNullOrEmpty(second)
            ? first
            : first + (first.EndsWith('\n') ? string.Empty : "\n") + second;

    private static bool HasStructureTrace(string? trace) =>
        !string.IsNullOrWhiteSpace(trace) &&
        trace.Contains(LuraphTraceMarkers.Prototype, StringComparison.Ordinal) &&
        trace.Contains(LuraphTraceMarkers.Step, StringComparison.Ordinal) &&
        trace.Contains(LuraphTraceMarkers.Return, StringComparison.Ordinal);

    private static async Task<string?> ReadTraceAsync(string? path, int maxBytes, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        var info = new FileInfo(path);
        if (info.Length > maxBytes)
            throw new InvalidDataException("trace byte limit exceeded");
        return await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteStaticArtifactsAsync(
        ArtifactStore store,
        EnvelopeAnalysis envelope,
        LegacyContainerResult legacy,
        CancellationToken cancellationToken)
    {
        await store.WriteJsonAsync("envelope.json", envelope, cancellationToken).ConfigureAwait(false);
        await store.WriteJsonAsync("legacy_container.json", legacy, cancellationToken).ConfigureAwait(false);
        await store.WriteJsonAsync("constants.json", new
        {
            containers = envelope.Containers.Select(container => new { container.CarrierIndex, container.Constants }),
        }, cancellationToken).ConfigureAwait(false);
        var normalized = envelope.Containers
            .Where(container => container.ParseStatus == ContainerParseStatus.Parsed)
            .Select(VmNormalizer.NormalizeContainer)
            .ToArray();
        await store.WriteJsonAsync("vm.json", new { containers = normalized }, cancellationToken).ConfigureAwait(false);
        await store.WriteJsonAsync("cfg.json", new { prototypes = Array.Empty<object>(), unresolved = Array.Empty<object>() }, cancellationToken).ConfigureAwait(false);
        await store.WriteJsonAsync("semantic_ir.json", new { prototypes = Array.Empty<object>(), unresolved = Array.Empty<object>() }, cancellationToken).ConfigureAwait(false);
        await store.WriteJsonAsync("opcode_handlers.json", new { handlers = Array.Empty<object>(), status = "trace_pending" }, cancellationToken).ConfigureAwait(false);
        await store.WriteJsonAsync("mapping.json", new { statements = Array.Empty<object>() }, cancellationToken).ConfigureAwait(false);
        await store.WriteTextAsync("disassembly.txt", Disassemble(normalized), cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteTraceArtifactsAsync(
        ArtifactStore store,
        LuraphTraceDocument trace,
        TraceLiftResult lift,
        CancellationToken cancellationToken)
    {
        await store.WriteJsonAsync("semantic_ir.json", new
        {
            kind = "trace_backed_terminal_payload",
            root_activation = lift.RootActivation,
            root_prototype = lift.RootPrototype,
            statements = lift.Statements,
            trace_summary = trace.Summary,
            complete = lift.Complete,
        }, cancellationToken).ConfigureAwait(false);
        await store.WriteJsonAsync("cfg.json", new
        {
            prototypes = lift.RootPrototype is null ? Array.Empty<object>() : new object[]
            {
                new
                {
                    runtime_id = lift.RootPrototype,
                    entry_pc = lift.Statements.FirstOrDefault()?.Pc ?? 1,
                    blocks = new[] { new { id = "entry", reachable = true, terminator = "return" } },
                },
            },
        }, cancellationToken).ConfigureAwait(false);
        await store.WriteJsonAsync("mapping.json", new
        {
            statements = lift.Statements.Select((item, index) => new
            {
                line = index + 1,
                item.Activation,
                item.VmCount,
                item.Pc,
                item.Opcode,
                item.CoveredPcs,
            }),
            instruction_coverage = lift.InstructionCoverage,
            covered_instructions = lift.InstructionCoverage.Count,
            statement_coverage_complete = lift.Complete,
        }, cancellationToken).ConfigureAwait(false);
    }

    private static string Disassemble(IEnumerable<NormalizedContainer> containers)
    {
        var output = new StringBuilder();
        foreach (NormalizedContainer container in containers)
        {
            output.AppendLine($"root={container.RootWrapperIndex} valid={container.RootValid}");
            foreach (NormalizedPrototype prototype in container.Prototypes)
            {
                output.AppendLine($"proto {prototype.WrapperIndex} regs={prototype.RegisterCapacity} insns={prototype.Instructions.Count}");
                foreach (NormalizedInstruction instruction in prototype.Instructions)
                    output.AppendLine($"  {instruction.Pc,5} op={instruction.Opcode,-4} D={instruction.D.BaseValue,-8} G={instruction.G.BaseValue,-8} p={instruction.P.BaseValue,-8}");
            }
        }
        return output.ToString();
    }

    private static CoverageSummary Coverage(
        EnvelopeAnalysis envelope,
        LegacyContainerResult legacy,
        TraceLiftResult? lift = null,
        SemanticReconstructionResult? semantic = null,
        bool semanticPromoted = true)
    {
        int semanticInstructions = semantic?.Lift.Program.Prototypes.Sum(item => item.Instructions.Count) ?? 0;
        int semanticUnresolved = semantic is null
            ? 0
            : semantic.Candidate.Unresolved.Count +
                semantic.Candidate.Metrics.UnsupportedExpressions +
                semantic.Candidate.Metrics.UnsupportedOperations +
                semantic.Candidate.Metrics.SymbolicTransitions +
                semantic.Candidate.Metrics.UnresolvedCaptureKeys;
        return new()
        {
            Containers = envelope.ContainerMetrics.ParsedCount + (legacy.Status == LegacyParseStatus.Parsed ? 1 : 0),
            Prototypes = semantic?.Lift.Program.Prototypes.Count ?? lift?.PrototypeCount ?? Math.Max(envelope.ContainerMetrics.PrototypeCount, legacy.PrototypeCount),
            Instructions = semantic is null ? lift?.InstructionCount ?? Math.Max(envelope.ContainerMetrics.InstructionCount, legacy.InstructionCount) : semanticInstructions,
            ReachableInstructions = semantic is null ? lift?.ClosureInstructions ?? 0 : semanticInstructions,
            ClassifiedInstructions = semantic is null ? lift?.ClassifiedInstructions ?? 0 : semanticInstructions,
            DecoderPrototypes = lift is null ? 0 : Math.Max(0, lift.ClosurePrototypes - 1),
            Constants = Math.Max(envelope.ContainerMetrics.ConstantCount, legacy.ConstantCount),
            Blocks = semantic?.Candidate.Metrics.Blocks ?? (lift?.Complete == true ? Math.Max(1, lift.ClosurePrototypes) : 0),
            LiftedOperations = semantic?.Candidate.Metrics.Operations ?? lift?.ClosureInstructions ?? 0,
            UnresolvedOperations = semantic is null ? lift?.UnresolvedOperations ?? 0 : semanticUnresolved,
            StatementCoverageComplete = semantic is not null
                ? semanticPromoted && semantic.Ready
                : lift?.Complete == true,
            LiftBackend = semantic is not null
                ? semanticPromoted ? "semantic-ir" : "observed-trace+semantic-ir-partial"
                : lift is not null ? "observed-trace" : "static-container",
            StructuredBlocks = semantic?.Readability.Stats.StructuredBlocks ?? 0,
            ResidualBlocks = semantic?.Readability.Stats.ResidualBlocks ?? 0,
            RegistersScalarized = semantic?.Readability.Stats.RegisterSlots ?? 0,
            RegisterAccessesScalarized = semantic?.Readability.Stats.RegisterAccesses ?? 0,
            NamesImproved = semantic?.Readability.Stats.NamesImproved ?? 0,
        };
    }

    private static async Task<DeobfuscationResult> FinishInvalidAsync(
        ArtifactStore store,
        ProgressLog log,
        List<Diagnostic> diagnostics,
        string code,
        string message,
        CancellationToken cancellationToken,
        string hash = "")
    {
        diagnostics.Add(new("input", code, message));
        log.Add("input", "blocked", message);
        await WriteEmptyArtifactsAsync(store, cancellationToken).ConfigureAwait(false);
        return await FinishAsync(store, log, hash, DeobfuscationStatus.Invalid, new(), new(), diagnostics,
            [], new ArtifactManifest(), cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteEmptyArtifactsAsync(ArtifactStore store, CancellationToken cancellationToken)
    {
        foreach (string name in new[] { "envelope.json", "legacy_container.json", "constants.json", "vm.json", "cfg.json", "semantic_ir.json", "opcode_handlers.json", "mapping.json" })
            await store.WriteJsonAsync(name, new { status = "unavailable" }, cancellationToken).ConfigureAwait(false);
        await store.WriteTextAsync("disassembly.txt", string.Empty, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<DeobfuscationResult> FinishAsync(
        ArtifactStore store,
        ProgressLog log,
        string hash,
        DeobfuscationStatus status,
        CoverageSummary coverage,
        VerificationSummary verification,
        IReadOnlyList<Diagnostic> diagnostics,
        IReadOnlyList<TracePassSummary> tracePasses,
        ArtifactManifest artifacts,
        CancellationToken cancellationToken)
    {
        DeobfuscationResult result = new()
        {
            Status = status,
            ExactSource = false,
            InputSha256 = hash,
            Coverage = coverage,
            Verification = verification,
            Diagnostics = diagnostics,
            TracePasses = tracePasses,
            Stages = log.Events,
            Artifacts = artifacts,
        };
        await store.WriteJsonAsync(artifacts.Report, result, cancellationToken).ConfigureAwait(false);
        return result;
    }
}
