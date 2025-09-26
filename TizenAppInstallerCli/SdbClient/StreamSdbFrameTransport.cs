using System.Buffers.Binary;
using System.Net;

namespace TizenAppInstallerCli.SdbClient;

// Stream-based transport implementation (NetworkStream or any Stream)
internal sealed class StreamSdbFrameTransport : ISdbFrameTransport
{
    private readonly Stream _stream;
    private readonly bool _leaveOpen;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public EndPoint RemoteEndPoint { get; }

    public StreamSdbFrameTransport(Stream stream, EndPoint? remoteEndPoint = null, bool leaveOpen = false)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _leaveOpen = leaveOpen;
        RemoteEndPoint = remoteEndPoint ?? new IPEndPoint(IPAddress.Any, 0);
    }

    public async Task WriteFrameAsync(SdbFrame frame, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(frame);

        // Ensure atomicity of a logical frame write
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // header: 6 uint32 little-endian
            // compute derived values
            frame.DataLength = (uint)(frame.Payload?.Length ?? 0);
            frame.DataChecksum = SdbChecksum.Sum32(frame.Payload ?? []);
            frame.Magic = ((uint)frame.Command) ^ 0xffffffffu;

            // write header
            byte[] message = new byte[24 + (int)frame.DataLength];
            BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(0, 4), (uint)frame.Command);
            BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(4, 4), frame.Arg0);
            BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(8, 4), frame.Arg1);
            BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(12, 4), frame.DataLength);
            BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(16, 4), frame.DataChecksum);
            BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(20, 4), frame.Magic);
            frame.Payload?.CopyTo(message.AsSpan(24));

            await _stream.WriteAsync(message, ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<SdbFrame> ReadFrameAsync(CancellationToken ct = default)
    {
        // read 24-byte header
        byte[] header = new byte[24];
        await ReadExactlyAsync(_stream, header, 0, 24, ct).ConfigureAwait(false);

        SdbFrame frame = new()
        {
            Command = (SdbCommand)BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0, 4)),
            Arg0 = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4, 4)),
            Arg1 = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(8, 4)),
            DataLength = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12, 4)),
            DataChecksum = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(16, 4)),
            Magic = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(20, 4))
        };

        if (frame.DataLength > 0)
        {
            frame.Payload = new byte[frame.DataLength];
            await ReadExactlyAsync(_stream, frame.Payload, 0, (int)frame.DataLength, ct).ConfigureAwait(false);
        }
        else
        {
            frame.Payload = [];
        }

        // header validation (magic)
        if (!frame.ValidateHeader())
            throw new InvalidDataException($"Invalid magic in frame. Cmd={(uint)frame.Command:X8} magic=0x{frame.Magic:X8}");

        // checksum validation (sum32)
        if (!frame.ValidateChecksum())
            throw new InvalidDataException($"Invalid checksum for command {frame.Command}. Expected {frame.DataChecksum:X8}, computed {SdbChecksum.Sum32(frame.Payload):X8}");

        return frame;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            _writeLock?.Dispose();
            if (!_leaveOpen) _stream?.Dispose();
        }
        catch { }
        await Task.CompletedTask;
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
    {
        int read = 0;
        while (read < count)
        {
            int r = await stream.ReadAsync(buffer.AsMemory(offset + read, count - read), ct).ConfigureAwait(false);
            if (r == 0) throw new EndOfStreamException("Remote closed stream while reading");
            read += r;
        }
    }
}
