using System.Text;
using Luraph.Core.Containers.Legacy;

namespace Luraph.Core.Tests.Scanning;

public sealed class LegacyContainerParserTests
{
    private static readonly LegacyConstantTagMap Tags = new(11, 22, 33, 44);
    private static readonly LegacyCountOffsets Offsets = new(100, 200, 300);

    [Fact]
    public void DecodesPrimaryFixtureButRejectsItsDifferentConstantSchema()
    {
        var source = File.ReadAllText(Fixture("subject_1b642e9523c1.luau"));

        var result = LegacyContainerParser.Analyze(source);

        Assert.Equal(LegacyParseStatus.ConstantTagInferenceFailed, result.Status);
        Assert.Equal(LegacyDecodeStatus.Decoded, result.Carrier.Status);
        Assert.Equal("LPH@", result.Carrier.Marker);
        Assert.Equal(75_929, result.Carrier.EncodedBytes);
        Assert.Equal(15_185, result.Carrier.GroupCount);
        Assert.Equal(0, result.Carrier.ZeroGroupCount);
        Assert.Equal(60_740, result.Carrier.DecodedBytes);
        Assert.Equal([30_479L, 98_427L, 18_205L], result.OffsetEvidence.Select(item => item.Value).ToArray());
        Assert.Equal((ulong)31_599, result.Inference.RawConstantCount);
        Assert.Equal((byte)137, result.Inference.InferredStringTag);
        Assert.Equal(10, result.Inference.StringAnchorMatches);
        Assert.Equal(768, result.Inference.ConstantTagTrials);
        Assert.Equal([(30_479L, 1_120), (18_205L, 13_394), (0L, 31_599)],
            result.Inference.ConstantCountCandidates.Select(item => (item.Offset, item.Count)).ToArray());
        Assert.Contains(result.Diagnostics, item => item.Code == "LEGACY_CONSTANT_SCHEMA_MISMATCH");
    }

    [Fact]
    public void DecodesDollarFixtureWithAscii85ZeroGroups()
    {
        var source = File.ReadAllText(Fixture("subject_ea93959c47e6.luau"));

        var result = LegacyContainerParser.Analyze(source);

        Assert.Equal(LegacyParseStatus.ConstantTagInferenceFailed, result.Status);
        Assert.Equal(LegacyDecodeStatus.Decoded, result.Carrier.Status);
        Assert.Equal("LPH$", result.Carrier.Marker);
        Assert.Equal(288_411, result.Carrier.EncodedBytes);
        Assert.Equal(57_855, result.Carrier.GroupCount);
        Assert.Equal(217, result.Carrier.ZeroGroupCount);
        Assert.Equal(231_420, result.Carrier.DecodedBytes);
        Assert.Equal([16_927L, 45_233L, 27_336L], result.OffsetEvidence.Select(item => item.Value).ToArray());
        Assert.Equal((ulong)19_282, result.Inference.RawConstantCount);
        Assert.Equal((byte)68, result.Inference.InferredStringTag);
        Assert.Equal(10, result.Inference.StringAnchorMatches);
        Assert.Equal(512, result.Inference.ConstantTagTrials);
        Assert.Equal([(16_927L, 2_355), (0L, 19_282)],
            result.Inference.ConstantCountCandidates.Select(item => (item.Offset, item.Count)).ToArray());
    }

    [Fact]
    public void DecodesStandaloneZeroGroupAsFourZeroBytes()
    {
        var source = Source("LPH$z");

        var result = LegacyContainerParser.Analyze(source);

        Assert.Equal(LegacyDecodeStatus.Decoded, result.Carrier.Status);
        Assert.Equal(1, result.Carrier.GroupCount);
        Assert.Equal(1, result.Carrier.ZeroGroupCount);
        Assert.Equal(4, result.Carrier.DecodedBytes);
    }

    [Fact]
    public void ParsesExplicitThreeConstantTinyContainer()
    {
        var bytes = BuildContainer(
            [
                Constant.String(Tags.String, "loadstring"),
                Constant.Boolean(Tags.Boolean, true),
                Constant.Integer(Tags.Int64, 42),
            ],
            [Prototype(2, 1)]);
        var result = LegacyContainerParser.Analyze(Source(Encode(bytes)), new()
        {
            CountOffsets = Offsets,
            ConstantTags = Tags,
            HasExtraPrototypeField = false,
        });

        Assert.Equal(LegacyParseStatus.Parsed, result.Status);
        Assert.Equal(LegacyPayloadClass.Tiny, result.PayloadClass);
        Assert.Equal(3, result.ConstantCount);
        Assert.Equal(1, result.PrototypeCount);
        Assert.Equal(2, result.InstructionCount);
        Assert.Equal(1, result.LineEntryCount);
        Assert.Equal(1, result.UpvalueCount);
        Assert.Equal(1, result.RootPrototype);
        Assert.Equal("loadstring", Encoding.UTF8.GetString(result.Constants[0].StringBytes));
        Assert.True(result.Constants[1].BooleanValue);
        Assert.Equal(42, result.Constants[2].Int64Value);
        Assert.NotNull(result.Modes);
        Assert.Equal(5_040, result.Modes.CandidatesEvaluated);
        Assert.False(result.Modes.ArrayPermutationResolved);
        Assert.Equal(6, result.Modes.ArrayPermutationCandidates);
    }

    [Fact]
    public void InfersFourRandomizedConstantTags()
    {
        var bytes = BuildContainer(
            [
                Constant.String(Tags.String, "loadstring"),
                Constant.Boolean(Tags.Boolean, false),
                Constant.Double(Tags.Double, 3.5),
                Constant.Integer(Tags.Int64, 42),
            ],
            [Prototype(1, 0)]);
        var result = LegacyContainerParser.Analyze(Source(Encode(bytes)), new()
        {
            CountOffsets = Offsets,
            HasExtraPrototypeField = false,
        });

        Assert.Equal(LegacyParseStatus.Parsed, result.Status);
        Assert.Equal(Tags, result.ConstantTags);
        Assert.Equal(3.5, result.Constants.Single(item => item.Kind == LegacyConstantKind.Double).DoubleValue);
        Assert.Equal(42, result.Constants.Single(item => item.Kind == LegacyConstantKind.Int64).Int64Value);
    }

    [Fact]
    public void ResolvesAValidatedPrototypeReference()
    {
        var instructions = new List<InstructionData>();
        for (var pc = 1; pc <= 12; pc++)
        {
            var c = pc == 1 ? Lane(2, 4) : Lane(1, 1);
            var a = Lane(pc == 12 ? 0 : 1, 2);
            var b = Lane(pc == 1 ? 0 : 1, 3);
            instructions.Add(new(c, a, b, (ulong)(50 + pc)));
        }
        var bytes = BuildContainer(
            [
                Constant.String(Tags.String, "loadstring"),
                Constant.Boolean(Tags.Boolean, true),
                Constant.Double(Tags.Double, 1.25),
                Constant.Integer(Tags.Int64, 7),
            ],
            [Prototype(instructions), Prototype(0, 0)]);
        var result = LegacyContainerParser.Analyze(Source(Encode(bytes)), new()
        {
            CountOffsets = Offsets,
            ConstantTags = Tags,
            HasExtraPrototypeField = false,
        });

        Assert.Equal(LegacyParseStatus.Parsed, result.Status);
        Assert.Contains(result.PrototypeReferences, item => item.Valid && item.SourcePrototype == 1 && item.TargetPrototype == 2);
    }

    private static string Fixture(string name)
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "tests", "fixtures", "luraph", name)))
            root = root.Parent;
        Assert.NotNull(root);
        return Path.Combine(root.FullName, "tests", "fixtures", "luraph", name);
    }

    private static string Source(string carrier) =>
        $"local a=x[1]()-{Offsets.Constant}\n" +
        $"local b=x[2]()-{Offsets.Prototype}\n" +
        $"local c=x[3]()-{Offsets.Instruction}\n" +
        $"local payload=[==[{carrier}]==]";

    private static byte[] BuildContainer(IReadOnlyList<Constant> constants, IReadOnlyList<PrototypeData> prototypes)
    {
        var bytes = new List<byte>();
        Uleb(bytes, (ulong)(Offsets.Constant + constants.Count));
        bytes.Add(1);
        foreach (var constant in constants)
        {
            bytes.Add(constant.Tag);
            bytes.AddRange(constant.Bytes);
        }
        Uleb(bytes, (ulong)(Offsets.Prototype + prototypes.Count));
        foreach (var prototype in prototypes)
        {
            Uleb(bytes, (ulong)prototype.Descriptors.Length);
            foreach (var descriptor in prototype.Descriptors)
                Uleb(bytes, descriptor);
            Uleb(bytes, (ulong)(Offsets.Instruction + prototype.Instructions.Length));
            foreach (var instruction in prototype.Instructions)
            {
                Uleb(bytes, instruction.C);
                Uleb(bytes, instruction.A);
                Uleb(bytes, instruction.B);
                Uleb(bytes, instruction.Opcode);
            }
            Uleb(bytes, 8);
            Little32(bytes, prototype.Instructions.Length == 0 ? 0 : 1);
            if (prototype.Instructions.Length > 0)
                Little32(bytes, 20);
            Uleb(bytes, (ulong)prototype.Upvalues);
        }
        Uleb(bytes, 1);
        while (bytes.Count % 4 != 0)
            bytes.Add(0xee);
        return bytes.ToArray();
    }

    private static PrototypeData Prototype(int instructionCount, int upvalues)
    {
        var instructions = Enumerable.Range(1, instructionCount)
            .Select(pc => new InstructionData(Lane(1, 1), Lane(0, 2), Lane(0, 3), (ulong)(70 + pc)))
            .ToArray();
        return new([5], instructions, upvalues);
    }

    private static PrototypeData Prototype(IReadOnlyList<InstructionData> instructions) => new([5], instructions.ToArray(), 1);

    private static ulong Lane(int value, int residue) => (ulong)(value * 8 + residue);

    private static string Encode(byte[] bytes)
    {
        Assert.Equal(0, bytes.Length % 4);
        var output = new StringBuilder("LPH@");
        for (var offset = 0; offset < bytes.Length; offset += 4)
        {
            uint value = 0;
            for (var i = 0; i < 4; i++)
                value |= (uint)bytes[offset + i] << (i * 8);
            if (value == 0)
            {
                output.Append('z');
                continue;
            }
            var chars = new char[5];
            for (var i = 4; i >= 0; i--)
            {
                chars[i] = (char)(value % 85 + 33);
                value /= 85;
            }
            output.Append(chars);
        }
        return output.ToString();
    }

    private static void Uleb(List<byte> bytes, ulong value)
    {
        do
        {
            var next = (byte)(value & 0x7f);
            value >>= 7;
            if (value != 0)
                next |= 0x80;
            bytes.Add(next);
        }
        while (value != 0);
    }

    private static void Little32(List<byte> bytes, int value)
    {
        for (var i = 0; i < 4; i++)
            bytes.Add((byte)((uint)value >> (i * 8)));
    }

    private sealed record Constant(byte Tag, byte[] Bytes)
    {
        public static Constant Boolean(byte tag, bool value) => new(tag, [(byte)(value ? 1 : 0)]);

        public static Constant Double(byte tag, double value) => new(tag, BitConverter.GetBytes(value));

        public static Constant Integer(byte tag, long value) => new(tag, BitConverter.GetBytes(value));

        public static Constant String(byte tag, string value)
        {
            var text = Encoding.UTF8.GetBytes(value);
            var bytes = new List<byte>();
            Uleb(bytes, (ulong)text.Length);
            bytes.AddRange(text);
            return new(tag, bytes.ToArray());
        }
    }

    private sealed record InstructionData(ulong C, ulong A, ulong B, ulong Opcode);

    private sealed record PrototypeData(ulong[] Descriptors, InstructionData[] Instructions, int Upvalues);
}
