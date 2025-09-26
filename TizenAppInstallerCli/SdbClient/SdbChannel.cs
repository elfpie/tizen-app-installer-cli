using System.Threading.Channels;

namespace TizenAppInstallerCli.SdbClient;

public sealed class SdbChannel : IAsyncDisposable
{
    private readonly SdbTcpDevice _device;
    private readonly Channel<byte[]> _incoming = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    private readonly SemaphoreSlim _writeSem = new(1, 1);
    private bool _closed;
    private int _readCursor;
    private byte[]? _currentChunk;

    private uint LocalId { get; }
    public uint RemoteId { get; internal set; }
    public string Service { get; }

    internal SdbChannel(SdbTcpDevice device, uint localId, string service)
    {
        _device = device;
        LocalId = localId;
        Service = service;
    }

    internal void EnqueueIncoming(byte[] bytes)
    {
        if (!_incoming.Writer.TryWrite(bytes)) { /* drop? */ }
    }

    public async Task WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_closed, nameof(SdbChannel));
        
        // respect device.maxData
        int offset = 0;
        while (offset < buffer.Length)
        {
            int chunkSize = (int)Math.Min(_device.MaxData, buffer.Length - offset);
            byte[] chunk = buffer.Slice(offset, chunkSize).ToArray();
            await _writeSem.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var frame = new SdbFrame
                {
                    Command = SdbCommand.Wrte,
                    Arg0 = LocalId,
                    Arg1 = RemoteId,
                    Payload = chunk
                };
                await _device.WriteFrameAsync(frame, ct).ConfigureAwait(false);
            }
            finally
            {
                _writeSem.Release();
            }
            offset += chunkSize;
        }
    }

    /// <summary>
    /// Read into buffer; returns number of bytes read or 0 when the channel is closed and no more data.
    /// </summary>
    public async Task<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_closed && _incoming.Reader.Count == 0 && _currentChunk == null) return 0;

        while (true)
        {
            if (_currentChunk != null)
            {
                int available = _currentChunk.Length - _readCursor;
                if (available > 0)
                {
                    int toCopy = Math.Min(available, buffer.Length);
                    new ReadOnlySpan<byte>(_currentChunk, _readCursor, toCopy).CopyTo(buffer.Span);
                    _readCursor += toCopy;
                    if (_readCursor >= _currentChunk.Length)
                    {
                        _currentChunk = null;
                        _readCursor = 0;
                    }
                    return toCopy;
                }

                _currentChunk = null;
                _readCursor = 0;
            }

            if (_incoming.Reader.TryRead(out var chunk))
            {
                if (chunk.Length == 0)
                {
                    // empty chunk as signal of closed channel
                    _closed = true;
                    return 0;
                }
                _currentChunk = chunk;
                _readCursor = 0;
                continue;
            }

            if (_closed)
            {
                return 0;
            }

            // wait for next incoming
            if (!await _incoming.Reader.WaitToReadAsync(ct).ConfigureAwait(false))
            {
                return 0;
            }
        }
    }

    private async Task CloseAsync(CancellationToken ct = default)
    {
        if (_closed) return;
        _closed = true;
        var frame = new SdbFrame
        {
            Command = SdbCommand.Clse,
            Arg0 = LocalId,
            Arg1 = RemoteId,
            Payload = []
        };
        await _device.WriteFrameAsync(frame, ct).ConfigureAwait(false);
        // signal readers
        _incoming.Writer.TryWrite([]);
        _incoming.Writer.Complete();
    }

    public async ValueTask DisposeAsync()
    {
        await CloseAsync().ConfigureAwait(false);
        _writeSem.Dispose();
    }
}
