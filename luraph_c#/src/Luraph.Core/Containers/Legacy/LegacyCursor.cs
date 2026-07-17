namespace Luraph.Core.Containers.Legacy;

internal sealed class LegacyCursor(byte[] data, int position = 0)
{
    public int Position { get; private set; } = position;
    public int Remaining => data.Length - Position;
    public string? ErrorCode { get; private set; }
    public int ErrorOffset { get; private set; }

    public bool ReadByte(out byte value)
    {
        if (!Need(1))
        {
            value = 0;
            return false;
        }
        value = data[Position++];
        return true;
    }

    public bool ReadUleb(out ulong value, out ByteSpan span)
    {
        var begin = Position;
        value = 0;
        for (var i = 0; i < 10; i++)
        {
            if (!ReadByte(out var ch))
            {
                span = default;
                return false;
            }
            var payload = (ulong)(ch & 0x7f);
            if (i == 9 && (payload > 1 || (ch & 0x80) != 0))
            {
                Fail("LEGACY_ULEB_OVERFLOW", begin);
                span = default;
                return false;
            }
            value |= payload << (i * 7);
            if ((ch & 0x80) != 0)
                continue;
            if (i > 0 && payload == 0)
            {
                Fail("LEGACY_ULEB_NONCANONICAL", begin);
                span = default;
                return false;
            }
            span = new(begin, Position);
            return true;
        }
        Fail("LEGACY_ULEB_OVERFLOW", begin);
        span = default;
        return false;
    }

    public bool ReadInt32(out int value)
    {
        if (!ReadUInt64(4, out var raw))
        {
            value = 0;
            return false;
        }
        value = unchecked((int)raw);
        return true;
    }

    public bool ReadInt64(out long value)
    {
        if (!ReadUInt64(8, out var raw))
        {
            value = 0;
            return false;
        }
        value = unchecked((long)raw);
        return true;
    }

    public bool ReadDouble(out double value)
    {
        if (!ReadInt64(out var bits))
        {
            value = 0;
            return false;
        }
        value = BitConverter.Int64BitsToDouble(bits);
        return true;
    }

    public bool ReadBytes(ulong count, out byte[] bytes)
    {
        if (count > (ulong)Remaining)
        {
            Fail("LEGACY_TRUNCATED", Position);
            bytes = [];
            return false;
        }
        bytes = data.AsSpan(Position, (int)count).ToArray();
        Position += (int)count;
        return true;
    }

    private bool ReadUInt64(int width, out ulong value)
    {
        value = 0;
        if (!Need(width))
            return false;
        for (var i = 0; i < width; i++)
            value |= (ulong)data[Position + i] << (i * 8);
        Position += width;
        return true;
    }

    private bool Need(int count)
    {
        if (count <= Remaining)
            return true;
        Fail("LEGACY_TRUNCATED", Position);
        return false;
    }

    private void Fail(string code, int offset)
    {
        if (ErrorCode is not null)
            return;
        ErrorCode = code;
        ErrorOffset = offset;
    }
}

