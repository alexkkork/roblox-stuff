using System.Text;

namespace Luraph.Core.Containers.Legacy;

public static class LegacyContainerParser
{
    private static readonly byte[][] KnownStrings =
    [
        "loadstring"u8.ToArray(),
        "rawset"u8.ToArray(),
        "pcall"u8.ToArray(),
        "xpcall"u8.ToArray(),
        "currentline"u8.ToArray(),
        "game"u8.ToArray(),
        "Luraph"u8.ToArray(),
        "function"u8.ToArray(),
        "string"u8.ToArray(),
        "table"u8.ToArray(),
    ];

    public static LegacyContainerResult Analyze(string source, LegacyParseOptions? options = null)
    {
        options ??= new();
        var evidence = LegacySourceScanner.Scan(source, options);
        var diagnostics = evidence.Diagnostics.ToList();
        var inference = new LegacyInferenceMetrics();
        if (evidence.Carrier.Length == 0)
            return Result(LegacyParseStatus.CarrierNotFound);

        var decoded = LegacyAscii85.Decode(evidence.Carrier, options.Limits.MaxContainerBytes);
        if (decoded.Metadata.Status != LegacyDecodeStatus.Decoded)
        {
            Add(DiagnosticSeverity.Error, "LEGACY_ASCII85_FAILED", $"ASCII85 decoding stopped with {decoded.Metadata.Status}.", decoded.Metadata.ErrorOffset);
            return Result(LegacyParseStatus.MetadataOnly, decoded.Metadata);
        }

        Add(DiagnosticSeverity.Info, "LEGACY_ASCII85_DECODED",
            $"Decoded {decoded.Metadata.GroupCount} little-endian ASCII85 groups, including {decoded.Metadata.ZeroGroupCount} zero groups.");
        if (evidence.Offsets.Count > 0)
            Add(DiagnosticSeverity.Info, "LEGACY_OFFSETS_EXTRACTED", $"Extracted {evidence.Offsets.Count} bounded subtraction offsets from source.");

        var alignments = FindConstantAlignments(decoded.Bytes, evidence.Offsets, options, diagnostics, out inference);
        if (alignments.Count == 0)
        {
            Add(DiagnosticSeverity.Warning, "LEGACY_CONSTANT_SCHEMA_MISMATCH",
                "The four-tag legacy constant schema did not align with the decoded pool and source-proven offsets.");
            return Result(LegacyParseStatus.ConstantTagInferenceFailed, decoded.Metadata);
        }

        var layouts = new List<LayoutCandidate>();
        var attempts = 0;
        foreach (var alignment in alignments)
        {
            var instructionOffsets = options.CountOffsets is not null
                ? [options.CountOffsets.Instruction]
                : CandidateOffsets(evidence.Offsets, options.MaxOffsetCandidates)
                    .Where(value => value != alignment.Offsets.Constant && value != alignment.Offsets.Prototype)
                    .ToArray();
            var extraFields = options.HasExtraPrototypeField.HasValue
                ? [options.HasExtraPrototypeField.Value]
                : new[] { false, true };

            foreach (var instructionOffset in instructionOffsets)
                foreach (var extraField in extraFields)
                {
                    if (attempts >= Math.Max(0, options.MaxLayoutAttempts))
                        break;
                    attempts++;
                    if (TryReadLayout(decoded.Bytes, alignment, instructionOffset, extraField, options.Limits, out var layout))
                        layouts.Add(layout);
                }
        }

        if (layouts.Count == 0)
        {
            Add(DiagnosticSeverity.Warning, "LEGACY_PROTOTYPE_LAYOUT_MISMATCH",
                $"No prototype layout passed bounded validation after {attempts} attempts.");
            var first = alignments[0];
            return Result(LegacyParseStatus.PrototypeLayoutInvalid, decoded.Metadata) with
            {
                EffectiveOffsets = first.Offsets,
                ConstantTags = first.Tags,
                ConstantCacheEnabled = first.CacheEnabled,
                ConstantCount = first.Constants.Count,
                Constants = first.Constants,
                LayoutAttempts = attempts,
            };
        }

        var selected = layouts
            .OrderByDescending(item => item.Alignment.Confidence)
            .ThenByDescending(item => item.Prototypes.Sum(proto => proto.Instructions.Count))
            .ThenBy(item => item.TrailerBytes)
            .First();
        var modes = LegacyModeInference.Infer(selected.Prototypes, selected.Alignment.Constants.Count);
        var reachable = Reachable(selected.RootPrototype, selected.Prototypes, modes.References);
        var totalInstructions = selected.Prototypes.Sum(proto => proto.Instructions.Count);
        var reachableInstructions = selected.Prototypes
            .Where(proto => reachable.Contains(proto.Index))
            .Sum(proto => proto.Instructions.Count);
        var payloadClass = selected.Alignment.Constants.Count <= 3 && totalInstructions <= 4
            ? LegacyPayloadClass.Tiny
            : modes.Metadata.UniqueBest && reachableInstructions >= 32
                ? LegacyPayloadClass.Substantial
                : LegacyPayloadClass.Unknown;

        if (!modes.Metadata.UniqueBest)
            Add(DiagnosticSeverity.Warning, "LEGACY_MODE_AMBIGUOUS", "Operand modes have multiple equally scored assignments.");
        Add(DiagnosticSeverity.Info, "LEGACY_CONTAINER_PARSED",
            $"Parsed {selected.Prototypes.Count} prototypes and {totalInstructions} instructions with a valid root.");

        return Result(LegacyParseStatus.Parsed, decoded.Metadata) with
        {
            EffectiveOffsets = selected.Alignment.Offsets with { Instruction = selected.InstructionOffset },
            ConstantTags = selected.Alignment.Tags,
            ConstantCacheEnabled = selected.Alignment.CacheEnabled,
            HasExtraPrototypeField = selected.HasExtraField,
            ConstantCount = selected.Alignment.Constants.Count,
            PrototypeCount = selected.Prototypes.Count,
            InstructionCount = totalInstructions,
            DescriptorCount = selected.Prototypes.Sum(proto => proto.Descriptors.Count),
            LineEntryCount = selected.Prototypes.Sum(proto => proto.Lines.Count),
            UpvalueCount = selected.Prototypes.Sum(proto => proto.UpvalueCount),
            RootPrototype = selected.RootPrototype,
            ReachablePrototypeCount = reachable.Count,
            ReachableInstructionCount = reachableInstructions,
            PayloadClass = payloadClass,
            LayoutAttempts = attempts,
            Constants = selected.Alignment.Constants,
            Prototypes = selected.Prototypes,
            Modes = modes.Metadata,
            PrototypeReferences = modes.References,
        };

        LegacyContainerResult Result(LegacyParseStatus status, LegacyCarrierMetadata? carrier = null) => new()
        {
            Status = status,
            Carrier = carrier ?? new(),
            OffsetEvidence = evidence.Offsets,
            Inference = inference,
            Diagnostics = diagnostics.Take(Math.Max(0, options.Limits.MaxDiagnostics)).ToArray(),
        };

        void Add(DiagnosticSeverity severity, string code, string message, int? byteOffset = null)
        {
            if (diagnostics.Count < Math.Max(0, options.Limits.MaxDiagnostics))
                diagnostics.Add(new(severity, code, message, byteOffset));
        }
    }

    private static List<ConstantAlignment> FindConstantAlignments(
        byte[] bytes,
        IReadOnlyList<LegacyOffsetEvidence> evidence,
        LegacyParseOptions options,
        List<LegacyDiagnostic> diagnostics,
        out LegacyInferenceMetrics inference)
    {
        inference = new();
        var alignments = new List<ConstantAlignment>();
        var root = new LegacyCursor(bytes);
        if (!root.ReadUleb(out var rawCount, out _) || !root.ReadByte(out var cacheFlag))
            return alignments;

        var offsets = options.CountOffsets is not null
            ? [options.CountOffsets.Constant]
            : CandidateOffsets(evidence, options.MaxOffsetCandidates);
        var protoOffsets = options.CountOffsets is not null
            ? [options.CountOffsets.Prototype]
            : CandidateOffsets(evidence, options.MaxOffsetCandidates);
        var countCandidates = offsets
            .Select(offset => Count(rawCount, offset, options.Limits.MaxConstants, out var count)
                ? new LegacyCountCandidate(offset, count)
                : null)
            .Where(item => item is not null)
            .Cast<LegacyCountCandidate>()
            .ToArray();

        if (options.ConstantTags is not null)
        {
            if (!options.ConstantTags.IsDistinct)
                return alignments;
            foreach (var constantOffset in offsets)
            {
                if (!Count(rawCount, constantOffset, options.Limits.MaxConstants, out var count))
                    continue;
                if (!ReadConstants(bytes, root.Position, count, options.ConstantTags, out var constants, out var end))
                    continue;
                if (!TryUleb(bytes, end, out var rawProto, out var afterProto))
                    continue;
                foreach (var prototypeOffset in protoOffsets)
                {
                    if (prototypeOffset == constantOffset || !Count(rawProto, prototypeOffset, options.Limits.MaxPrototypes, out var prototypeCount))
                        continue;
                    alignments.Add(new(new(constantOffset, prototypeOffset, 0), options.ConstantTags, cacheFlag != 0,
                        constants, prototypeCount, afterProto, int.MaxValue));
                }
            }
            inference = new()
            {
                RawConstantCount = rawCount,
                ConstantCountCandidates = countCandidates,
            };
            return alignments.Take(Math.Max(0, options.MaxConstantAlignments)).ToList();
        }

        var stringTag = FindStringTag(bytes);
        if (!stringTag.Tag.HasValue)
        {
            inference = new()
            {
                RawConstantCount = rawCount,
                StringAnchorMatches = stringTag.Matches,
                ConstantCountCandidates = countCandidates,
            };
            diagnostics.Add(new(DiagnosticSeverity.Warning, "LEGACY_STRING_TAG_UNRESOLVED", "Known string anchors did not prove a unique string tag."));
            return alignments;
        }

        var tagTrials = 0;
        foreach (var constantOffset in offsets)
        {
            if (!Count(rawCount, constantOffset, options.Limits.MaxConstants, out var count) || count == 0)
                continue;
            for (var booleanTag = 0; booleanTag <= byte.MaxValue; booleanTag++)
            {
                tagTrials++;
                if (!TryLegacyFourTagPool(bytes, root.Position, count, stringTag.Tag.Value, (byte)booleanTag,
                        out var tags, out var end, out var confidence))
                    continue;
                if (!TryUleb(bytes, end, out var rawProto, out var afterProto))
                    continue;
                foreach (var prototypeOffset in protoOffsets)
                {
                    if (prototypeOffset == constantOffset || !Count(rawProto, prototypeOffset, options.Limits.MaxPrototypes, out var prototypeCount))
                        continue;
                    if (!ReadConstants(bytes, root.Position, count, tags, out var constants, out var verifiedEnd) || verifiedEnd != end)
                        continue;
                    alignments.Add(new(new(constantOffset, prototypeOffset, 0), tags, cacheFlag != 0,
                        constants, prototypeCount, afterProto, confidence));
                    if (alignments.Count >= Math.Max(0, options.MaxConstantAlignments))
                    {
                        inference = Metrics();
                        return alignments;
                    }
                }
            }
        }
        inference = Metrics();
        diagnostics.Add(new(DiagnosticSeverity.Info, "LEGACY_TAG_TRIALS", $"Checked {tagTrials} finite constant-tag alignments."));
        return alignments;

        LegacyInferenceMetrics Metrics() => new()
        {
            RawConstantCount = rawCount,
            InferredStringTag = stringTag.Tag,
            StringAnchorMatches = stringTag.Matches,
            ConstantTagTrials = tagTrials,
            ConstantCountCandidates = countCandidates,
        };
    }

    private static bool TryLegacyFourTagPool(
        byte[] bytes,
        int start,
        int count,
        byte stringTag,
        byte booleanTag,
        out LegacyConstantTagMap tags,
        out int end,
        out int confidence)
    {
        tags = new(0, 0, 0, 0);
        end = start;
        confidence = 0;
        if (stringTag == booleanTag)
            return false;
        var cur = new LegacyCursor(bytes, start);
        var seen = new HashSet<byte>();
        var numeric = new Dictionary<byte, List<long>>();
        var booleanSeen = false;
        for (var i = 0; i < count; i++)
        {
            if (!cur.ReadByte(out var tag))
                return false;
            seen.Add(tag);
            if (tag == stringTag)
            {
                if (!cur.ReadUleb(out var length, out _) || !cur.ReadBytes(length, out _))
                    return false;
            }
            else if (tag == booleanTag)
            {
                if (!cur.ReadByte(out var value) || value > 1)
                    return false;
                booleanSeen = true;
            }
            else
            {
                if (!cur.ReadInt64(out var value))
                    return false;
                if (!numeric.TryGetValue(tag, out var values))
                    numeric[tag] = values = [];
                values.Add(value);
            }
        }

        if (!booleanSeen || !seen.Contains(stringTag) || seen.Count != 4 || numeric.Count != 2)
            return false;
        var pair = numeric.Keys.Order().ToArray();
        var direct = NumericScore(pair[0], LegacyConstantKind.Double, numeric) + NumericScore(pair[1], LegacyConstantKind.Int64, numeric);
        var swapped = NumericScore(pair[0], LegacyConstantKind.Int64, numeric) + NumericScore(pair[1], LegacyConstantKind.Double, numeric);
        var doubleTag = direct >= swapped ? pair[0] : pair[1];
        var intTag = direct >= swapped ? pair[1] : pair[0];
        tags = new(booleanTag, doubleTag, stringTag, intTag);
        end = cur.Position;
        confidence = Math.Max(direct, swapped);
        return true;
    }

    private static int NumericScore(byte tag, LegacyConstantKind kind, IReadOnlyDictionary<byte, List<long>> values)
    {
        var score = 0;
        foreach (var raw in values[tag])
        {
            if (kind == LegacyConstantKind.Double)
            {
                var value = BitConverter.Int64BitsToDouble(raw);
                if (double.IsFinite(value))
                    score += 2;
                if (value == 0 || Math.Abs(value) is >= 1e-6 and <= 1e12)
                    score++;
            }
            else
            {
                if (raw is >= -1_000_000 and <= 1_000_000_000_000)
                    score += 2;
                if ((ulong)raw >> 32 is 0 or uint.MaxValue)
                    score++;
            }
        }
        return score;
    }

    private static bool ReadConstants(
        byte[] bytes,
        int start,
        int count,
        LegacyConstantTagMap tags,
        out List<LegacyConstant> constants,
        out int end)
    {
        constants = new(count);
        end = start;
        var cur = new LegacyCursor(bytes, start);
        for (var i = 0; i < count; i++)
        {
            var begin = cur.Position;
            if (!cur.ReadByte(out var tag) || tags.Resolve(tag) is not { } kind)
                return false;
            var value = new LegacyConstant { Index = i + 1, Tag = tag, Kind = kind };
            switch (kind)
            {
                case LegacyConstantKind.Boolean:
                    if (!cur.ReadByte(out var boolean) || boolean > 1)
                        return false;
                    value = value with { BooleanValue = boolean == 1 };
                    break;
                case LegacyConstantKind.Double:
                    if (!cur.ReadDouble(out var number))
                        return false;
                    value = value with { DoubleValue = number };
                    break;
                case LegacyConstantKind.Int64:
                    if (!cur.ReadInt64(out var integer))
                        return false;
                    value = value with { Int64Value = integer };
                    break;
                case LegacyConstantKind.String:
                    if (!cur.ReadUleb(out var length, out _) || !cur.ReadBytes(length, out var text))
                        return false;
                    value = value with { StringBytes = text };
                    break;
            }
            constants.Add(value with { Span = new(begin, cur.Position) });
        }
        end = cur.Position;
        return true;
    }

    private static bool TryReadLayout(
        byte[] bytes,
        ConstantAlignment alignment,
        long instructionOffset,
        bool extraField,
        AnalysisLimits limits,
        out LayoutCandidate layout)
    {
        layout = default!;
        var cur = new LegacyCursor(bytes, alignment.PrototypeDataOffset);
        var prototypes = new List<LegacyPrototype>(alignment.PrototypeCount);
        var totalInstructions = 0;
        var totalDescriptors = 0;
        var totalLines = 0;
        for (var prototypeIndex = 1; prototypeIndex <= alignment.PrototypeCount; prototypeIndex++)
        {
            var begin = cur.Position;
            if (!cur.ReadUleb(out var descriptorCountRaw, out _) || descriptorCountRaw > (ulong)Math.Max(0, limits.MaxDescriptors - totalDescriptors))
                return false;
            var descriptorCount = (int)descriptorCountRaw;
            var descriptors = new List<LegacyResolvedDescriptor>(descriptorCount);
            for (var i = 1; i <= descriptorCount; i++)
            {
                if (!cur.ReadUleb(out var raw, out var span))
                    return false;
                descriptors.Add(new(i, raw, raw / 4, (uint)(raw % 4), span));
            }
            totalDescriptors += descriptorCount;

            if (extraField && !cur.ReadUleb(out _, out _))
                return false;
            if (!cur.ReadUleb(out var rawInstructionCount, out _) ||
                !Count(rawInstructionCount, instructionOffset, Math.Max(0, limits.MaxInstructions - totalInstructions), out var instructionCount))
                return false;
            var instructions = new List<LegacyInstruction>(instructionCount);
            for (var pc = 1; pc <= instructionCount; pc++)
            {
                var instructionBegin = cur.Position;
                if (!cur.ReadUleb(out var rawC, out _) || !cur.ReadUleb(out var rawA, out _) ||
                    !cur.ReadUleb(out var rawB, out _) || !cur.ReadUleb(out var opcode, out _))
                    return false;
                instructions.Add(new()
                {
                    Index = pc,
                    RawC = rawC,
                    RawA = rawA,
                    RawB = rawB,
                    Opcode = opcode,
                    Span = new(instructionBegin, cur.Position),
                });
            }
            totalInstructions += instructionCount;

            if (!cur.ReadUleb(out var maxStackRaw, out _) || maxStackRaw > int.MaxValue || !cur.ReadInt32(out var lineRecordCount) ||
                lineRecordCount < 0 || lineRecordCount > Math.Max(0, limits.MaxInstructions - totalLines))
                return false;
            var lineMap = new Dictionary<int, int>();
            var lineIndex = 1;
            for (var line = 0; line < lineRecordCount; line++)
            {
                if (!cur.ReadInt32(out var encoded) || encoded < 0)
                    return false;
                var baseValue = encoded / 2;
                if ((encoded & 1) == 0)
                    lineMap[lineIndex] = baseValue;
                else
                {
                    if (!cur.ReadInt32(out lineIndex) || !cur.ReadInt32(out var lineNumber) ||
                        baseValue < 0 || lineIndex < baseValue || lineIndex > instructionCount ||
                        lineIndex - baseValue + lineMap.Count > Math.Max(0, limits.MaxInstructions))
                        return false;
                    for (var pc = baseValue; pc <= lineIndex; pc++)
                        lineMap[pc] = lineNumber;
                }
                lineIndex++;
            }
            totalLines += lineMap.Count;

            if (!cur.ReadUleb(out var upvalues, out _) || upvalues > (ulong)Math.Max(0, limits.MaxDescriptors))
                return false;
            prototypes.Add(new()
            {
                Index = prototypeIndex,
                MaxStack = (int)maxStackRaw,
                UpvalueCount = (int)upvalues,
                Descriptors = descriptors,
                Instructions = instructions,
                Lines = lineMap.OrderBy(item => item.Key).Select(item => new LegacyLineEntry(item.Key, item.Value)).ToArray(),
                Span = new(begin, cur.Position),
            });
        }

        if (!cur.ReadUleb(out var rootRaw, out _) || rootRaw < 1 || rootRaw > (ulong)prototypes.Count ||
            cur.Remaining > Math.Max(0, limits.MaxTrailerBytes))
            return false;
        layout = new(alignment, instructionOffset, extraField, prototypes, (int)rootRaw, cur.Remaining);
        return true;
    }

    private static StringTagEvidence FindStringTag(byte[] bytes)
    {
        var hits = new Dictionary<byte, int>();
        foreach (var needle in KnownStrings)
        {
            var search = 0;
            while (search <= bytes.Length - needle.Length)
            {
                var index = bytes.AsSpan(search).IndexOf(needle);
                if (index < 0)
                    break;
                index += search;
                for (var width = 1; width <= 5 && index - width - 1 >= 0; width++)
                {
                    var start = index - width;
                    if (TryUleb(bytes, start, out var length, out var end) && end == index && length == (ulong)needle.Length)
                    {
                        var tag = bytes[start - 1];
                        hits[tag] = hits.GetValueOrDefault(tag) + 1;
                    }
                }
                search = index + 1;
            }
        }
        if (hits.Count == 0)
            return new(null, 0);
        var ordered = hits.OrderByDescending(item => item.Value).ThenBy(item => item.Key).ToArray();
        return ordered.Length == 1 || ordered[0].Value > ordered[1].Value
            ? new(ordered[0].Key, ordered[0].Value)
            : new(null, ordered[0].Value);
    }

    private static long[] CandidateOffsets(IReadOnlyList<LegacyOffsetEvidence> evidence, int max)
    {
        var values = evidence.Select(item => item.Value).Where(value => value >= 0).Distinct().Take(Math.Max(0, max)).ToList();
        if (!values.Contains(0))
            values.Add(0);
        return values.ToArray();
    }

    private static bool Count(ulong raw, long offset, int max, out int value)
    {
        value = 0;
        if (offset < 0 || (ulong)offset > raw)
            return false;
        var adjusted = raw - (ulong)offset;
        if (adjusted > (ulong)Math.Max(0, max))
            return false;
        value = (int)adjusted;
        return true;
    }

    private static bool TryUleb(byte[] bytes, int start, out ulong value, out int end)
    {
        var cur = new LegacyCursor(bytes, start);
        var ok = cur.ReadUleb(out value, out _);
        end = cur.Position;
        return ok;
    }

    private static HashSet<int> Reachable(
        int root,
        IReadOnlyList<LegacyPrototype> prototypes,
        IReadOnlyList<LegacyPrototypeReference> references)
    {
        var edges = references.Where(item => item.Valid).GroupBy(item => item.SourcePrototype)
            .ToDictionary(group => group.Key, group => group.Select(item => item.TargetPrototype).Distinct().ToArray());
        var reached = new HashSet<int>();
        var queue = new Queue<int>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            if (!reached.Add(current) || !edges.TryGetValue(current, out var targets))
                continue;
            foreach (var target in targets)
                if (target >= 1 && target <= prototypes.Count)
                    queue.Enqueue(target);
        }
        return reached;
    }

    private sealed record ConstantAlignment(
        LegacyCountOffsets Offsets,
        LegacyConstantTagMap Tags,
        bool CacheEnabled,
        List<LegacyConstant> Constants,
        int PrototypeCount,
        int PrototypeDataOffset,
        int Confidence);

    private sealed record LayoutCandidate(
        ConstantAlignment Alignment,
        long InstructionOffset,
        bool HasExtraField,
        List<LegacyPrototype> Prototypes,
        int RootPrototype,
        int TrailerBytes);

    private sealed record StringTagEvidence(byte? Tag, int Matches);
}
