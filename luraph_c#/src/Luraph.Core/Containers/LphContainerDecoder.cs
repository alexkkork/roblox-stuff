using System.Security.Cryptography;

namespace Luraph.Core.Containers;

public static class LphContainerDecoder
{
    private const ulong ConstantBias = 12_618;
    private const ulong PrototypeBias = 87_799;
    private const ulong InstructionBias = 7_379;

    public static ContainerAnalysis Decode(
        ReadOnlySpan<byte> carrier,
        int carrierIndex,
        AnalysisLimits? limits = null,
        int decodedBudget = -1)
    {
        limits ??= new();
        var maxBytes = decodedBudget < 0 ? limits.MaxContainerBytes : Math.Min(decodedBudget, limits.MaxContainerBytes);
        var radix = DecodeRadix85(carrier, Math.Max(0, maxBytes));
        if (radix.Status != ContainerDecodeStatus.Decoded)
        {
            return new()
            {
                CarrierIndex = carrierIndex,
                DecodeStatus = radix.Status,
                EncodedCarrierBytes = carrier.Length,
                EncodedBodyBytes = radix.BodyBytes,
                Radix85GroupCount = radix.GroupCount,
                EncodedErrorOffset = radix.ErrorOffset,
            };
        }

        var parsed = Parse(radix.Bytes, limits);
        return parsed with
        {
            CarrierIndex = carrierIndex,
            DecodeStatus = ContainerDecodeStatus.Decoded,
            EncodedCarrierBytes = carrier.Length,
            EncodedBodyBytes = radix.BodyBytes,
            Radix85GroupCount = radix.GroupCount,
            DecodedBytes = radix.Bytes.Length,
            DecodedSha256 = Convert.ToHexStringLower(SHA256.HashData(radix.Bytes)),
        };
    }

    private static ContainerAnalysis Parse(byte[] bytes, AnalysisLimits limits)
    {
        var cur = new Cursor(bytes);
        var constants = new List<ConstantMetadata>();
        var prototypes = new List<PrototypeMetadata>();

        if (!cur.ReadUleb(out var rawConstantCount))
            return Failed(cur);
        if (!DecodeCount(rawConstantCount, ConstantBias, limits.MaxConstants, out var constantCount, out var countStatus))
            return Failed(countStatus, rawConstantCount.Span.Begin);
        if (!cur.ReadByte(out var poolMode, out var poolModeSpan))
            return Failed(cur);

        var constantsBegin = cur.Offset;
        for (var i = 0; i < constantCount; i++)
        {
            if (!ReadConstant(cur, i, out var constant))
                return Failed(cur, constantCount, rawConstantCount.Span, poolMode, poolModeSpan, constants, new(constantsBegin, cur.Offset));
            constants.Add(constant);
        }
        var constantsSpan = new ByteSpan(constantsBegin, cur.Offset);

        if (!cur.ReadUleb(out var rawPrototypeCount))
            return Failed(cur, constantCount, rawConstantCount.Span, poolMode, poolModeSpan, constants, constantsSpan);
        if (!DecodeCount(rawPrototypeCount, PrototypeBias, limits.MaxPrototypes, out var prototypeCount, out countStatus))
            return Failed(countStatus, rawPrototypeCount.Span.Begin, constantCount, rawConstantCount.Span, poolMode, poolModeSpan, constants, constantsSpan);

        var prototypesBegin = cur.Offset;
        var totalInstructions = 0;
        var totalDescriptors = 0;
        for (var i = 0; i < prototypeCount; i++)
        {
            var recordBegin = cur.Offset;
            if (!cur.ReadUleb(out var meta) || !cur.ReadUleb(out var rawInstructionCount))
                return Failed(cur, constantCount, rawConstantCount.Span, poolMode, poolModeSpan, constants, constantsSpan, prototypeCount, rawPrototypeCount.Span, prototypes, new(prototypesBegin, cur.Offset), totalInstructions, totalDescriptors);

            var instructionRoom = Math.Max(0, limits.MaxInstructions - totalInstructions);
            if (!DecodeCount(rawInstructionCount, InstructionBias, instructionRoom, out var instructionCount, out countStatus))
                return Failed(countStatus, rawInstructionCount.Span.Begin, constantCount, rawConstantCount.Span, poolMode, poolModeSpan, constants, constantsSpan, prototypeCount, rawPrototypeCount.Span, prototypes, new(prototypesBegin, cur.Offset), totalInstructions, totalDescriptors);

            var instructionsBegin = cur.Offset;
            var instructions = new List<InstructionMetadata>(instructionCount);
            for (var instructionIndex = 0; instructionIndex < instructionCount; instructionIndex++)
            {
                var instructionBegin = cur.Offset;
                var words = new InstructionWordMetadata[4];
                for (var word = 0; word < words.Length; word++)
                {
                    if (!cur.ReadSignedFold(out var value, out var span))
                        return Failed(cur, constantCount, rawConstantCount.Span, poolMode, poolModeSpan, constants, constantsSpan, prototypeCount, rawPrototypeCount.Span, prototypes, new(prototypesBegin, cur.Offset), totalInstructions, totalDescriptors);
                    words[word] = new(value, span);
                }
                instructions.Add(new()
                {
                    Index = instructionIndex,
                    Span = new(instructionBegin, cur.Offset),
                    Words = words,
                });
            }
            var instructionSpan = new ByteSpan(instructionsBegin, cur.Offset);
            totalInstructions += instructionCount;

            if (!cur.ReadUleb(out var rawDescriptorCount))
                return Failed(cur, constantCount, rawConstantCount.Span, poolMode, poolModeSpan, constants, constantsSpan, prototypeCount, rawPrototypeCount.Span, prototypes, new(prototypesBegin, cur.Offset), totalInstructions, totalDescriptors);
            if (rawDescriptorCount.Value > (ulong)Math.Max(0, limits.MaxDescriptors - totalDescriptors))
                return Failed(ContainerParseStatus.CountLimitExceeded, rawDescriptorCount.Span.Begin, constantCount, rawConstantCount.Span, poolMode, poolModeSpan, constants, constantsSpan, prototypeCount, rawPrototypeCount.Span, prototypes, new(prototypesBegin, cur.Offset), totalInstructions, totalDescriptors);

            var descriptorCount = checked((int)rawDescriptorCount.Value);
            var descriptorsBegin = cur.Offset;
            var descriptors = new List<DescriptorMetadata>(descriptorCount);
            for (var descriptorIndex = 0; descriptorIndex < descriptorCount; descriptorIndex++)
            {
                if (!cur.ReadUleb(out var raw))
                    return Failed(cur, constantCount, rawConstantCount.Span, poolMode, poolModeSpan, constants, constantsSpan, prototypeCount, rawPrototypeCount.Span, prototypes, new(prototypesBegin, cur.Offset), totalInstructions, totalDescriptors);
                descriptors.Add(new(descriptorIndex, raw.Value, (uint)(raw.Value % 4), raw.Value / 4, raw.Span));
            }
            var descriptorSpan = new ByteSpan(descriptorsBegin, cur.Offset);
            totalDescriptors += descriptorCount;

            if (!cur.ReadUleb(out var finalValue))
                return Failed(cur, constantCount, rawConstantCount.Span, poolMode, poolModeSpan, constants, constantsSpan, prototypeCount, rawPrototypeCount.Span, prototypes, new(prototypesBegin, cur.Offset), totalInstructions, totalDescriptors);

            prototypes.Add(new()
            {
                Index = i,
                Span = new(recordBegin, cur.Offset),
                Meta = meta.Value,
                MetaSpan = meta.Span,
                InstructionCount = instructionCount,
                InstructionCountSpan = rawInstructionCount.Span,
                InstructionWordsSpan = instructionSpan,
                DescriptorCount = descriptorCount,
                DescriptorCountSpan = rawDescriptorCount.Span,
                DescriptorsSpan = descriptorSpan,
                FinalValue = finalValue.Value,
                FinalSpan = finalValue.Span,
                Instructions = instructions,
                Descriptors = descriptors,
            });
        }
        var prototypesSpan = new ByteSpan(prototypesBegin, cur.Offset);

        if (!cur.ReadUleb(out var root))
            return Failed(cur, constantCount, rawConstantCount.Span, poolMode, poolModeSpan, constants, constantsSpan, prototypeCount, rawPrototypeCount.Span, prototypes, prototypesSpan, totalInstructions, totalDescriptors);
        var trailerSpan = new ByteSpan(cur.Offset, bytes.Length);
        if (cur.Remaining > Math.Max(0, limits.MaxTrailerBytes))
            return Failed(ContainerParseStatus.TrailerLimitExceeded, cur.Offset, constantCount, rawConstantCount.Span, poolMode, poolModeSpan, constants, constantsSpan, prototypeCount, rawPrototypeCount.Span, prototypes, prototypesSpan, totalInstructions, totalDescriptors, root.Value, root.Span, trailerSpan);

        return new()
        {
            ParseStatus = ContainerParseStatus.Parsed,
            ConstantCount = constantCount,
            ConstantCountSpan = rawConstantCount.Span,
            ConstantPoolMode = poolMode,
            ConstantPoolModeSpan = poolModeSpan,
            ConstantsSpan = constantsSpan,
            PrototypeCount = prototypeCount,
            PrototypeCountSpan = rawPrototypeCount.Span,
            PrototypesSpan = prototypesSpan,
            InstructionCount = totalInstructions,
            DescriptorCount = totalDescriptors,
            RootSelector = root.Value,
            RootSelectorSpan = root.Span,
            TrailerSpan = trailerSpan,
            Constants = constants,
            Prototypes = prototypes,
            TrailerBytes = bytes[cur.Offset..],
        };
    }

    private static bool ReadConstant(Cursor cur, int index, out ConstantMetadata result)
    {
        result = new();
        var begin = cur.Offset;
        if (!cur.ReadByte(out var tag, out var tagSpan))
            return false;

        ConstantKind kind;
        ByteSpan dataSpan;
        ByteSpan? lengthSpan = null;
        long? signed = null;
        ulong? unsigned = null;
        bool? boolean = null;
        float? f32 = null;
        double? f64 = null;
        uint? f32Bits = null;
        ulong? f64Bits = null;
        byte[] stringBytes = [];

        if (tag <= 39)
        {
            kind = ConstantKind.Integer;
            if (!ReadSigned(cur, 2, out signed, out dataSpan))
                return false;
        }
        else if (tag <= 46)
        {
            kind = ConstantKind.Float;
            if (!cur.ReadLittle(8, out var bits, out dataSpan))
                return false;
            f64Bits = bits;
            f64 = BitConverter.Int64BitsToDouble(unchecked((long)bits));
        }
        else if (tag <= 67)
        {
            kind = ConstantKind.Boolean;
            boolean = false;
            cur.SkipZero(out dataSpan);
        }
        else if (tag <= 75)
        {
            kind = ConstantKind.Float;
            if (!cur.ReadLittle(4, out var bits, out dataSpan))
                return false;
            f32Bits = (uint)bits;
            f32 = BitConverter.Int32BitsToSingle(unchecked((int)bits));
        }
        else if (tag <= 89 || tag is >= 91 and <= 109)
        {
            kind = ConstantKind.Integer;
            if (!cur.ReadLittle(1, out var value, out dataSpan))
                return false;
            signed = -(long)value;
        }
        else if (tag == 90)
        {
            kind = ConstantKind.Integer;
            if (!ReadSigned(cur, 4, out signed, out dataSpan))
                return false;
        }
        else if (tag <= 116)
        {
            kind = ConstantKind.Boolean;
            boolean = true;
            cur.SkipZero(out dataSpan);
        }
        else if (tag <= 155 || tag is >= 157 and <= 181)
        {
            kind = ConstantKind.String;
            if (!cur.ReadUleb(out var length) || !cur.ReadBytes(length.Value, out stringBytes, out dataSpan))
                return false;
            lengthSpan = length.Span;
        }
        else if (tag == 156)
        {
            kind = ConstantKind.Integer;
            if (!cur.ReadLittle(8, out var value, out dataSpan))
                return false;
            unsigned = value;
        }
        else if (tag <= 198)
        {
            kind = ConstantKind.Integer;
            if (!cur.ReadLittle(1, out var value, out dataSpan))
                return false;
            unsigned = value;
        }
        else if (tag <= 232)
        {
            kind = ConstantKind.Integer;
            if (!cur.ReadLittle(2, out var value, out dataSpan))
                return false;
            unsigned = value;
        }
        else
        {
            kind = ConstantKind.Integer;
            if (!cur.ReadLittle(4, out var value, out dataSpan))
                return false;
            unsigned = value;
        }

        result = new()
        {
            Index = index,
            Tag = tag,
            Kind = kind,
            Span = new(begin, cur.Offset),
            TagSpan = tagSpan,
            LengthSpan = lengthSpan,
            DataSpan = dataSpan,
            DataBytes = dataSpan.Length,
            SignedIntegerValue = signed,
            UnsignedIntegerValue = unsigned,
            BooleanValue = boolean,
            Float32Value = f32,
            Float64Value = f64,
            Float32Bits = f32Bits,
            Float64Bits = f64Bits,
            StringBytes = stringBytes,
        };
        return true;
    }

    private static bool ReadSigned(Cursor cur, int width, out long? value, out ByteSpan span)
    {
        value = null;
        if (!cur.ReadLittle(width, out var raw, out span))
            return false;
        var bits = width * 8;
        var sign = 1UL << (bits - 1);
        value = (raw & sign) == 0 ? (long)raw : unchecked((long)(raw | (ulong.MaxValue << bits)));
        return true;
    }

    private static bool DecodeCount(UlebValue raw, ulong bias, int limit, out int value, out ContainerParseStatus status)
    {
        value = 0;
        status = ContainerParseStatus.NotAttempted;
        if (raw.Value < bias)
        {
            status = ContainerParseStatus.CountUnderflow;
            return false;
        }
        var adjusted = raw.Value - bias;
        if (adjusted > (ulong)Math.Max(0, limit))
        {
            status = ContainerParseStatus.CountLimitExceeded;
            return false;
        }
        value = (int)adjusted;
        return true;
    }

    private static RadixResult DecodeRadix85(ReadOnlySpan<byte> carrier, int maxBytes)
    {
        if (carrier.Length < 4 || carrier[0] != 'L' || carrier[1] != 'P' || carrier[2] != 'H' || carrier[3] is < 33 or > 126)
            return new(ContainerDecodeStatus.InvalidPrefix, [], 0, 0, 0);
        var bodyBytes = carrier.Length - 4;
        if (bodyBytes % 5 != 0)
            return new(ContainerDecodeStatus.MisalignedBody, [], bodyBytes, 0, carrier.Length);
        var groups = bodyBytes / 5;
        if (groups > maxBytes / 4)
            return new(ContainerDecodeStatus.OutputLimitExceeded, [], bodyBytes, groups, 4);

        var bytes = new byte[groups * 4];
        for (var group = 0; group < groups; group++)
        {
            ulong value = 0;
            var begin = 4 + group * 5;
            for (var i = 0; i < 5; i++)
            {
                var ch = carrier[begin + i];
                if (ch is < 33 or > 117)
                    return new(ContainerDecodeStatus.InvalidCharacter, [], bodyBytes, groups, begin + i);
                var digit = (ulong)(ch - 33);
                if (value > (uint.MaxValue - digit) / 85)
                    return new(ContainerDecodeStatus.Radix85Overflow, [], bodyBytes, groups, begin);
                value = value * 85 + digit;
            }
            for (var i = 0; i < 4; i++)
                bytes[group * 4 + i] = (byte)(value >> (i * 8));
        }
        return new(ContainerDecodeStatus.Decoded, bytes, bodyBytes, groups, null);
    }

    private static ContainerAnalysis Failed(Cursor cur, int constantCount = 0, ByteSpan constantCountSpan = default, byte poolMode = 0,
        ByteSpan poolModeSpan = default, IReadOnlyList<ConstantMetadata>? constants = null, ByteSpan constantsSpan = default,
        int prototypeCount = 0, ByteSpan prototypeCountSpan = default, IReadOnlyList<PrototypeMetadata>? prototypes = null,
        ByteSpan prototypesSpan = default, int instructions = 0, int descriptors = 0) =>
        Failed(cur.Status, cur.ErrorOffset, constantCount, constantCountSpan, poolMode, poolModeSpan, constants, constantsSpan,
            prototypeCount, prototypeCountSpan, prototypes, prototypesSpan, instructions, descriptors);

    private static ContainerAnalysis Failed(ContainerParseStatus status, int errorOffset, int constantCount = 0,
        ByteSpan constantCountSpan = default, byte poolMode = 0, ByteSpan poolModeSpan = default,
        IReadOnlyList<ConstantMetadata>? constants = null, ByteSpan constantsSpan = default, int prototypeCount = 0,
        ByteSpan prototypeCountSpan = default, IReadOnlyList<PrototypeMetadata>? prototypes = null, ByteSpan prototypesSpan = default,
        int instructions = 0, int descriptors = 0, ulong root = 0, ByteSpan rootSpan = default, ByteSpan trailerSpan = default) => new()
        {
            ParseStatus = status,
            ParseErrorOffset = errorOffset,
            ConstantCount = constantCount,
            ConstantCountSpan = constantCountSpan,
            ConstantPoolMode = poolMode,
            ConstantPoolModeSpan = poolModeSpan,
            Constants = constants ?? [],
            ConstantsSpan = constantsSpan,
            PrototypeCount = prototypeCount,
            PrototypeCountSpan = prototypeCountSpan,
            Prototypes = prototypes ?? [],
            PrototypesSpan = prototypesSpan,
            InstructionCount = instructions,
            DescriptorCount = descriptors,
            RootSelector = root,
            RootSelectorSpan = rootSpan,
            TrailerSpan = trailerSpan,
        };

    private sealed record RadixResult(ContainerDecodeStatus Status, byte[] Bytes, int BodyBytes, int GroupCount, int? ErrorOffset);

    private readonly record struct UlebValue(ulong Value, ByteSpan Span);

    private sealed class Cursor(byte[] data)
    {
        public int Offset { get; private set; }
        public int Remaining => data.Length - Offset;
        public ContainerParseStatus Status { get; private set; }
        public int ErrorOffset { get; private set; }

        public bool ReadByte(out byte value, out ByteSpan span)
        {
            var begin = Offset;
            if (!Need(1))
            {
                value = 0;
                span = default;
                return false;
            }
            value = data[Offset++];
            span = new(begin, Offset);
            return true;
        }

        public bool ReadLittle(int width, out ulong value, out ByteSpan span)
        {
            var begin = Offset;
            value = 0;
            if (width > 8 || !Need(width))
            {
                span = default;
                return false;
            }
            for (var i = 0; i < width; i++)
                value |= (ulong)data[Offset + i] << (i * 8);
            Offset += width;
            span = new(begin, Offset);
            return true;
        }

        public bool ReadBytes(ulong count, out byte[] value, out ByteSpan span)
        {
            var begin = Offset;
            if (count > (ulong)Remaining)
            {
                Fail(ContainerParseStatus.Truncated, Offset);
                value = [];
                span = default;
                return false;
            }
            value = data.AsSpan(Offset, (int)count).ToArray();
            Offset += (int)count;
            span = new(begin, Offset);
            return true;
        }

        public bool ReadUleb(out UlebValue output)
        {
            var begin = Offset;
            ulong value = 0;
            for (var i = 0; i < 10; i++)
            {
                if (!Need(1))
                {
                    output = default;
                    return false;
                }
                var ch = data[Offset++];
                var payload = (ulong)(ch & 0x7f);
                if (i == 9 && (payload > 1 || (ch & 0x80) != 0))
                {
                    Fail(ContainerParseStatus.UlebOverflow, begin);
                    output = default;
                    return false;
                }
                value |= payload << (i * 7);
                if ((ch & 0x80) != 0)
                    continue;
                if (i > 0 && payload == 0)
                {
                    Fail(ContainerParseStatus.NonCanonicalUleb, begin);
                    output = default;
                    return false;
                }
                output = new(value, new(begin, Offset));
                return true;
            }
            Fail(ContainerParseStatus.UlebOverflow, begin);
            output = default;
            return false;
        }

        public bool ReadSignedFold(out long value, out ByteSpan span)
        {
            const ulong threshold = 1UL << 52;
            const ulong modulus = 1UL << 53;
            if (!ReadUleb(out var raw))
            {
                value = 0;
                span = default;
                return false;
            }
            if (raw.Value >= modulus)
            {
                Fail(ContainerParseStatus.SignedFoldOverflow, raw.Span.Begin);
                value = 0;
                span = default;
                return false;
            }
            value = raw.Value >= threshold ? -(long)(modulus - raw.Value) : (long)raw.Value;
            span = raw.Span;
            return true;
        }

        public void SkipZero(out ByteSpan span) => span = new(Offset, Offset);

        private bool Need(int count)
        {
            if (count <= Remaining)
                return true;
            Fail(ContainerParseStatus.Truncated, Offset);
            return false;
        }

        private void Fail(ContainerParseStatus status, int offset)
        {
            if (Status != ContainerParseStatus.NotAttempted)
                return;
            Status = status;
            ErrorOffset = offset;
        }
    }
}
