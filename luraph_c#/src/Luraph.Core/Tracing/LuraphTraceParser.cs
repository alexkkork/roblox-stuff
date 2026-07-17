using System.Buffers;
using System.Globalization;
using System.Text;

namespace Luraph.Core.Tracing;

public sealed class LuraphTraceParser
{
    public LuraphTraceDocument Parse(string text, TraceParseOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        options ??= new TraceParseOptions();
        Validate(options);

        var bytes = Encoding.UTF8.GetBytes(text);
        var hit = bytes.Length > options.MaxBytes;
        return ParseBytes(bytes.AsMemory(0, Math.Min(bytes.Length, options.MaxBytes)), hit, options);
    }

    public async Task<LuraphTraceDocument> ParseAsync(
        Stream stream,
        TraceParseOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        options ??= new TraceParseOptions();
        Validate(options);

        using var data = new MemoryStream(Math.Min(options.MaxBytes, 1024 * 1024));
        var buffer = ArrayPool<byte>.Shared.Rent(16 * 1024);
        var limitHit = false;
        try
        {
            while (data.Length <= options.MaxBytes)
            {
                var left = options.MaxBytes + 1L - data.Length;
                var read = await stream.ReadAsync(
                    buffer.AsMemory(0, (int)Math.Min(buffer.Length, left)),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    break;
                await data.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
            limitHit = data.Length > options.MaxBytes;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        var bytes = data.GetBuffer().AsMemory(0, (int)Math.Min(data.Length, options.MaxBytes));
        return ParseBytes(bytes, limitHit, options);
    }

    private static LuraphTraceDocument ParseBytes(
        ReadOnlyMemory<byte> bytes,
        bool byteLimitHit,
        TraceParseOptions options)
    {
        var text = Encoding.UTF8.GetString(bytes.Span);
        if (byteLimitHit && text.Length > 0 && text[^1] != '\n')
        {
            var lastLine = text.LastIndexOf('\n');
            text = lastLine < 0 ? string.Empty : text[..(lastLine + 1)];
        }

        var state = new ParseState(options, bytes.Length, byteLimitHit);
        using var reader = new StringReader(text);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (state.RowsRead >= options.MaxRows)
            {
                state.RowLimitHit = true;
                break;
            }
            state.RowsRead++;
            state.ParseLine(line.TrimEnd('\r'));
        }
        return state.Build();
    }

    private static void Validate(TraceParseOptions options)
    {
        if (options.MaxBytes is < 1 or > 1024 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(options), "trace bytes must be between 1 and 1 GiB");
        if (options.MaxRows < 1)
            throw new ArgumentOutOfRangeException(nameof(options), "trace rows must be positive");
    }

    private sealed class ParseState(TraceParseOptions options, long bytesRead, bool byteLimitHit)
    {
        private readonly List<LuraphTraceRecord> records = [];
        private readonly List<string> output = [];
        private readonly List<TraceParseDiagnostic> diagnostics = [];
        private int markerRows;
        private int malformedRows;

        public int RowsRead { get; set; }
        public bool RowLimitHit { get; set; }

        public void ParseLine(string line)
        {
            if (!line.StartsWith(LuraphTraceMarkers.Prefix, StringComparison.Ordinal))
            {
                if (line.Length > 0)
                    output.Add(line);
                return;
            }

            markerRows++;
            var fields = line.Split('\t');
            var parsed = fields[0] switch
            {
                LuraphTraceMarkers.Call => ParseCall(fields),
                LuraphTraceMarkers.Vm => ParseVm(fields),
                LuraphTraceMarkers.Activation => ParseActivation(fields),
                LuraphTraceMarkers.Prototype => ParsePrototype(fields),
                LuraphTraceMarkers.PrototypeObject => ParsePrototypeObject(fields),
                LuraphTraceMarkers.Instruction => ParseInstruction(fields),
                LuraphTraceMarkers.LaneTop => ParseLaneTop(fields),
                LuraphTraceMarkers.LaneTable => ParseLaneTable(fields),
                LuraphTraceMarkers.ActivationPrototype => ParseActivationPrototype(fields),
                LuraphTraceMarkers.ActivationArgumentTable => ParseActivationArgumentTable(fields),
                LuraphTraceMarkers.CaptureDomain => ParseCaptureDomain(fields),
                LuraphTraceMarkers.Step => ParseStep(fields),
                LuraphTraceMarkers.Return => ParseReturn(fields),
                _ => Bad("unknown_marker", $"unknown marker {fields[0]}"),
            };
            if (parsed is not null)
                records.Add(parsed);
        }

        public LuraphTraceDocument Build()
        {
            var calls = records.OfType<CallTraceRecord>().Count();
            var vm = records.OfType<VmTraceRecord>().Count();
            var activations = records.OfType<ActivationTraceRecord>().Count()
                + records.OfType<ActivationPrototypeTraceRecord>().Count();
            var prototypes = records.OfType<PrototypeTraceRecord>().Count();
            var instructions = records.OfType<InstructionTraceRecord>().Count();
            var laneRows = records.OfType<LaneTopTraceRecord>().Count()
                + records.OfType<LaneTableTraceRecord>().Count();
            var steps = records.OfType<StepTraceRecord>().Count();
            var returns = records.OfType<ReturnTraceRecord>().Count();
            return new LuraphTraceDocument
            {
                Records = records,
                OutputLines = output,
                Diagnostics = diagnostics,
                Summary = new TraceSummary
                {
                    BytesRead = bytesRead,
                    RowsRead = RowsRead,
                    MarkerRows = markerRows,
                    MalformedRows = malformedRows,
                    OutputRows = output.Count,
                    Calls = calls,
                    VmEvents = vm,
                    Activations = activations,
                    Prototypes = prototypes,
                    Instructions = instructions,
                    LaneRows = laneRows,
                    Steps = steps,
                    Returns = returns,
                    ByteLimitHit = byteLimitHit,
                    RowLimitHit = RowLimitHit,
                },
            };
        }

        private LuraphTraceRecord? ParseCall(string[] f)
        {
            if (f.Length < 12 || !TryU64(f[1], out var vm) || !TryU64(f[2], out var activation)
                || !TryI64(f[6], out var pc) || !TryI64(f[7], out var opcode)
                || !TryInt(f[10], out var count) || count is < 0 or > 8
                || f[9] is not ("print" or "warn" or "error")
                || !TryValues(f[11], count, out var arguments))
                return Bad("bad_call", "invalid call row");

            return new CallTraceRecord(RowsRead, vm, activation, OptionalU64(f[3]), OptionalI64(f[4]),
                OptionalI64(f[5]), pc, opcode, OptionalI64(f[8]), f[9], arguments);
        }

        private LuraphTraceRecord? ParseVm(string[] f)
        {
            if (f.Length < 8 || !TryU64(f[1], out var vm) || !TryU64(f[2], out var activation)
                || !TryI64(f[6], out var pc) || !TryI64(f[7], out var opcode))
                return Bad("bad_vm", "invalid VM row");

            VmOperandSnapshot? primary = null;
            VmOperandSnapshot? next = null;
            VmOperandSnapshot? t = null;
            VmOperandSnapshot? u = null;
            if (f.Length >= 23)
            {
                var primaryRegister = OptionalI64(f[8]);
                primary = Snapshot(primaryRegister, f[9], f[10], f[11]);
                next = Snapshot(primaryRegister is null ? null : primaryRegister + 1, f[12], f[13], f[14]);
                t = Snapshot(OptionalI64(f[15]), f[16], f[17], f[18]);
                u = Snapshot(OptionalI64(f[19]), f[20], f[21], f[22]);
            }
            return new VmTraceRecord(RowsRead, vm, activation, OptionalU64(f[3]), OptionalI64(f[4]),
                OptionalI64(f[5]), pc, opcode, primary, next, t, u,
                Field(f, 23), Field(f, 24), Field(f, 25));
        }

        private LuraphTraceRecord? ParseActivation(string[] f)
        {
            if (f.Length < 7 || !TryU64(f[1], out var vm) || !TryU64(f[2], out var activation)
                || !TryInt(f[6], out var count) || count < 0)
                return Bad("bad_activation", "invalid activation row");
            return new ActivationTraceRecord(RowsRead, vm, activation, OptionalU64(f[3]),
                OptionalI64(f[4]), OptionalI64(f[5]), count, Field(f, 7));
        }

        private LuraphTraceRecord? ParsePrototype(string[] f)
        {
            if (f.Length < 4 || !TryU64(f[1], out var id) || id == 0
                || !TryInt(f[2], out var count) || count < 0 || count > options.MaxInstructionsPerPrototype)
                return Bad("bad_prototype", "invalid prototype row");
            var lanes = f[3].Split(',', StringSplitOptions.RemoveEmptyEntries);
            if (lanes.Any(lane => !Identifier(lane)))
                return Bad("bad_prototype_lanes", "prototype lane name is invalid");
            return new PrototypeTraceRecord(RowsRead, id, count, lanes);
        }

        private LuraphTraceRecord? ParsePrototypeObject(string[] f)
        {
            if (f.Length < 3 || !TryU64(f[1], out var prototype) || prototype == 0
                || !TryU64(f[2], out var objectId) || objectId == 0)
                return Bad("bad_prototype_object", "invalid prototype object row");
            return new PrototypeObjectTraceRecord(RowsRead, prototype, objectId);
        }

        private LuraphTraceRecord? ParseInstruction(string[] f)
        {
            if (f.Length < 5 || !TryU64(f[1], out var prototype) || prototype == 0
                || !TryInt(f[2], out var pc) || pc <= 0 || !TryI64(f[3], out var opcode)
                || !TryValueMap(f[4], out var lanes))
                return Bad("bad_instruction", "invalid instruction row");
            return new InstructionTraceRecord(RowsRead, prototype, pc, opcode, lanes);
        }

        private LuraphTraceRecord? ParseLaneTop(string[] f)
        {
            if (f.Length < 6 || !TryU64(f[1], out var prototype) || prototype == 0
                || !TryInt(f[2], out var pc) || pc <= 0 || !Identifier(f[3])
                || !RuntimeValue.TryDecode(f[4], out var key) || !RuntimeValue.TryDecode(f[5], out var value))
                return Bad("bad_lane_top", "invalid top lane row");
            return new LaneTopTraceRecord(RowsRead, prototype, pc, f[3], key!, value!);
        }

        private LuraphTraceRecord? ParseLaneTable(string[] f)
        {
            if (f.Length < 8 || !TryU64(f[1], out var prototype) || prototype == 0
                || !TryInt(f[2], out var pc) || pc <= 0 || !Identifier(f[3])
                || !TryInt(f[4], out var depth) || depth is < 0 or > 4
                || !RuntimeValue.TryDecode(f[6], out var key) || !RuntimeValue.TryDecode(f[7], out var value))
                return Bad("bad_lane_table", "invalid nested lane row");
            return new LaneTableTraceRecord(RowsRead, prototype, pc, f[3], depth, f[5], key!, value!);
        }

        private LuraphTraceRecord? ParseActivationPrototype(string[] f)
        {
            if (f.Length < 8 || !TryU64(f[1], out var activation) || activation == 0
                || !TryU64(f[2], out var prototype) || prototype == 0
                || !TryInt(f[6], out var count) || count < 0
                || !TryCapturedValues(Field(f, 8) ?? string.Empty, out var args))
                return Bad("bad_activation_prototype", "invalid activation prototype row");
            return new ActivationPrototypeTraceRecord(RowsRead, activation, prototype, OptionalU64(f[3]),
                OptionalI64(f[4]), OptionalI64(f[5]), count, OptionalI64(f[7]), args, OptionalU64(Field(f, 9)));
        }

        private LuraphTraceRecord? ParseActivationArgumentTable(string[] f)
        {
            if (f.Length < 6 || !TryU64(f[1], out var activation) || activation == 0
                || !TryU64(f[2], out var prototype) || prototype == 0
                || !TryInt(f[3], out var argumentIndex) || argumentIndex <= 0
                || !RuntimeValue.TryDecode(f[4], out var key) || !RuntimeValue.TryDecode(f[5], out var value))
                return Bad("bad_activation_arg_table", "invalid activation argument table row");
            return new ActivationArgumentTableTraceRecord(RowsRead, activation, prototype, argumentIndex, key!, value!);
        }

        private LuraphTraceRecord? ParseCaptureDomain(string[] f)
        {
            if (f.Length < 6 || !TryU64(f[1], out var activation) || activation == 0
                || !TryU64(f[2], out var prototype) || prototype == 0
                || !TryInt(f[3], out var complete) || complete is < 0 or > 1
                || !TryInt(f[4], out var count) || count is < 0 or > 256
                || !TryIntegers(f[5], count, 0, 200_000, ',', out var indices))
                return Bad("bad_capture_domain", "invalid capture domain row");
            return new CaptureDomainTraceRecord(RowsRead, activation, prototype, complete == 1, indices);
        }

        private LuraphTraceRecord? ParseStep(string[] f)
        {
            if (f.Length < 8 || !TryU64(f[1], out var vm) || !TryU64(f[2], out var activation)
                || !TryI64(f[3], out var pc) || !TryI64(f[4], out var opcode)
                || !TryI64(f[5], out var nextPc) || !TryInt(f[6], out var count)
                || count < 0 || count > options.MaxWritesPerStep
                || !TryWrites(f[7], count, out var writes)
                || !TryValueMap(Field(f, 8) ?? string.Empty, out var lanes))
                return Bad("bad_step", "invalid step row");
            return new StepTraceRecord(RowsRead, vm, activation, pc, opcode, nextPc, writes, lanes);
        }

        private LuraphTraceRecord? ParseReturn(string[] f)
        {
            if (f.Length < 8 || !TryU64(f[1], out var vm) || !TryU64(f[2], out var activation) || activation == 0
                || !TryI64(f[3], out var pc) || pc <= 0 || !TryI64(f[4], out var opcode)
                || !TryInt(f[5], out var arity) || arity < 0 || !TryInt(f[6], out var captured)
                || captured < 0 || captured > options.MaxCapturedReturns || captured > arity
                || !TryValues(f[7], captured, out var values))
                return Bad("bad_return", "invalid return row");
            return new ReturnTraceRecord(RowsRead, vm, activation, pc, opcode, arity, values);
        }

        private LuraphTraceRecord? Bad(string code, string message)
        {
            malformedRows++;
            if (diagnostics.Count < 64)
                diagnostics.Add(new TraceParseDiagnostic(RowsRead, code, message));
            return null;
        }

        private static VmOperandSnapshot Snapshot(long? register, string type, string value, string name) =>
            new(register, type, EmptyNull(value), EmptyNull(name));

        private static bool TryValues(string packed, int expected, out IReadOnlyList<RuntimeValue> values)
        {
            var result = new List<RuntimeValue>(expected);
            if (expected == 0)
            {
                values = result;
                return packed.Length == 0;
            }
            foreach (var item in packed.Split('|'))
            {
                if (!RuntimeValue.TryDecode(item, out var value))
                {
                    values = [];
                    return false;
                }
                result.Add(value!);
            }
            values = result;
            return result.Count == expected;
        }

        private static bool TryCapturedValues(string packed, out IReadOnlyList<RuntimeValue> values)
        {
            if (packed.Length == 0)
            {
                values = [];
                return true;
            }
            var items = packed.Split('|');
            if (items.Length > 8)
            {
                values = [];
                return false;
            }
            var result = new List<RuntimeValue>(items.Length);
            foreach (var item in items)
            {
                if (!RuntimeValue.TryDecode(item, out var value))
                {
                    values = [];
                    return false;
                }
                result.Add(value!);
            }
            values = result;
            return true;
        }

        private static bool TryValueMap(string packed, out IReadOnlyDictionary<string, RuntimeValue> values)
        {
            var result = new Dictionary<string, RuntimeValue>(StringComparer.Ordinal);
            if (packed.Length == 0)
            {
                values = result;
                return true;
            }
            foreach (var item in packed.Split('|'))
            {
                var equal = item.IndexOf('=');
                if (equal <= 0 || !Identifier(item[..equal])
                    || !RuntimeValue.TryDecode(item[(equal + 1)..], out var value))
                {
                    values = result;
                    return false;
                }
                result[item[..equal]] = value!;
            }
            values = result;
            return true;
        }

        private static bool TryWrites(string packed, int expected, out IReadOnlyList<RegisterWrite> writes)
        {
            var result = new List<RegisterWrite>(expected);
            if (expected == 0)
            {
                writes = result;
                return packed.Length == 0;
            }
            foreach (var item in packed.Split('|'))
            {
                var equal = item.IndexOf('=');
                if (equal <= 0 || !TryInt(item[..equal], out var register) || register is < -200_000 or > 200_000
                    || !RuntimeValue.TryDecode(item[(equal + 1)..], out var value))
                {
                    writes = [];
                    return false;
                }
                result.Add(new RegisterWrite(register, value!));
            }
            writes = result;
            return result.Count == expected;
        }

        private static bool TryIntegers(
            string packed,
            int expected,
            int min,
            int max,
            char separator,
            out IReadOnlyList<int> values)
        {
            var result = new List<int>(expected);
            if (expected == 0)
            {
                values = result;
                return packed.Length == 0;
            }
            foreach (var item in packed.Split(separator))
            {
                if (!TryInt(item, out var value) || value < min || value > max)
                {
                    values = [];
                    return false;
                }
                result.Add(value);
            }
            values = result;
            return result.Count == expected;
        }

        private static string? Field(string[] fields, int index) =>
            index < fields.Length ? fields[index] : null;

        private static string? EmptyNull(string value) => value.Length == 0 ? null : value;

        private static bool TryU64(string? text, out ulong value) =>
            ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);

        private static bool TryI64(string? text, out long value) =>
            long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);

        private static bool TryInt(string? text, out int value) =>
            int.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);

        private static ulong? OptionalU64(string? text) =>
            text is null or "" or "nil" ? null : TryU64(text, out var value) ? value : null;

        private static long? OptionalI64(string? text) =>
            text is null or "" or "nil" ? null : TryI64(text, out var value) ? value : null;

        private static bool Identifier(string value)
        {
            if (value.Length == 0 || !(value[0] == '_' || char.IsAsciiLetter(value[0])))
                return false;
            for (var index = 1; index < value.Length; index++)
                if (value[index] != '_' && !char.IsAsciiLetterOrDigit(value[index]))
                    return false;
            return true;
        }
    }
}
