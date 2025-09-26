using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TizenAppInstallerCli.SdbClient;

public class SdbTcpDevice : ISdbDevice
{
    private const uint CLIENT_VERSION = 0x01000000;
    private const int SYNC_MAX_DATA = 64 * 1024;
    private readonly int _port;
    private TcpClient? _tcp;
    private ISdbFrameTransport? _transport;
    private CancellationTokenSource? _pumpCts;
    private Task? _pumpTask;
    private uint _nextLocalId = 'a';
    private readonly ConcurrentDictionary<uint, SdbChannel> _channelsByLocalId = new();
    private readonly ConcurrentDictionary<uint, SdbChannel> _channelsByRemoteId = new();
    private readonly ConcurrentDictionary<uint, TaskCompletionSource<SdbChannel>> _pendingOpens = new();

    public string DeviceId { get; private set; }

    public IPAddress IpAddress { get; }

    public uint MaxData { get; private set; } = 4096; // negotiation fallback

    public SdbTcpDevice(IPAddress address, int port = 26101)
    {
        IpAddress = address ?? throw new ArgumentNullException(nameof(address));
        _port = port;
        DeviceId = $"{IpAddress}:{_port}";
    }

    public async Task ConnectAsync(CancellationToken ct = default)
    {
        if (_transport != null) return; // already connected

        _tcp = new TcpClient();
        using var linkCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkCts.CancelAfter(TimeSpan.FromSeconds(10));
        await _tcp.ConnectAsync(IpAddress, _port).WaitAsync(linkCts.Token).ConfigureAwait(false);
        NetworkStream ns = _tcp.GetStream();
        _transport = new StreamSdbFrameTransport(ns, _tcp.Client.RemoteEndPoint, leaveOpen: false);

        // send CNXN
        byte[] banner = Encoding.UTF8.GetBytes("host::sdb-net-client");
        var cnxn = new SdbFrame
        {
            Command = SdbCommand.Cnxn,
            Arg0 = CLIENT_VERSION,
            Arg1 = MaxData,
            Payload = banner
        };
        await WriteFrameAsync(cnxn, ct).ConfigureAwait(false);

        SdbFrame resp = await _transport.ReadFrameAsync(ct).ConfigureAwait(false);

        if (resp.Command == SdbCommand.Auth)
        {
            throw new InvalidOperationException(
                "Remote requested AUTH but client is configured to not perform authentication.");
        }

        if (resp.Command != SdbCommand.Cnxn)
        {
            throw new InvalidDataException($"Expected CNXN; got {resp.Command}");
        }

        // read negotiated maxData from response Arg1
        MaxData = Math.Min(MaxData, resp.Arg1 == 0 ? MaxData : resp.Arg1);

        // set device id string from banner payload (if present)
        DeviceId = resp.Payload.Length > 0 ? Encoding.UTF8.GetString(resp.Payload) : DeviceId;

        // start the background pump to read frames and dispatch to channels
        _pumpCts = new CancellationTokenSource();
        _pumpTask = Task.Run(() => PumpLoopAsync(_pumpCts.Token), ct);
    }

    public async Task DisconnectAsync()
    {
        try
        {
            _pumpCts?.Cancel();
            if (_pumpTask != null) await _pumpTask.ConfigureAwait(false);
        }
        catch
        {
        }

        try
        {
            if (_transport != null) await _transport.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
        }

        _transport = null;
        _tcp?.Dispose();
        _tcp = null;
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync().ConfigureAwait(false);
        foreach (SdbChannel ch in _channelsByLocalId.Values) await ch.DisposeAsync().ConfigureAwait(false);
    }


    public async Task<SdbChannel> OpenAsync(string service, CancellationToken ct = default)
    {
        if (_transport == null) throw new InvalidOperationException("Not connected");
        uint localId = GetNextLocalId();
        var channel = new SdbChannel(this, localId, service);

        // Prepare a TCS that will be completed when pump processes OKAY or failed on CLSE
        TaskCompletionSource<SdbChannel> tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pendingOpens.TryAdd(localId, tcs))
            throw new InvalidOperationException("Local id pending open conflict");

        // Register channel in the local map so pump can route WRTE frames even before OKAY.
        if (!_channelsByLocalId.TryAdd(localId, channel))
        {
            _pendingOpens.TryRemove(localId, out _);
            throw new InvalidOperationException("Local id conflict");
        }

        // Send OPEN
        var openFrame = new SdbFrame
        {
            Command = SdbCommand.Open,
            Arg0 = localId,
            Arg1 = 0,
            Payload = SdbFrame.StringToAsciiPayload(service)
        };

        try
        {
            await WriteFrameAsync(openFrame, ct).ConfigureAwait(false);

            // Wait for the pump to signal OKAY (complete the TCS)
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            // apply an overall timeout (was 10s previously)
            linkedCts.CancelAfter(TimeSpan.FromSeconds(10));
            await using (linkedCts.Token.Register(() => tcs.TrySetCanceled()))
            {
                SdbChannel openedChannel = await tcs.Task.ConfigureAwait(false);

                // If openedChannel.RemoteId set to 0 for some reason, treat as failure:
                if (openedChannel.RemoteId == 0)
                {
                    // Remove state and throw
                    _channelsByLocalId.TryRemove(localId, out _);
                    _pendingOpens.TryRemove(localId, out _);
                    throw new InvalidOperationException("Remote opened channel but did not supply remote id.");
                }

                return openedChannel;
            }
        }
        catch (Exception)
        {
            // cleanup pending state if anything goes wrong (including timeout/cancel)
            _channelsByLocalId.TryRemove(localId, out _);
            _pendingOpens.TryRemove(localId, out _);
            // propagate
            throw;
        }
    }

    public async Task<int> ShellCommandAsync(string command, Stream output, CancellationToken ct = default)
    {
        await using SdbChannel ch = await OpenAsync($"shell:{command}\0", ct).ConfigureAwait(false);

        byte[] buffer = new byte[MaxData];
        int total = 0;
        while (true)
        {
            int read = await ch.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (read == 0) break;
            await output.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            total += read;
        }

        return total;
    }

    public async Task<string> ShellCommandAsync(string command, CancellationToken ct = default)
    {
        await using SdbChannel ch = await OpenAsync($"shell:{command}\0", ct).ConfigureAwait(false);

        byte[] buffer = new byte[MaxData];
        var sb = new StringBuilder();
        while (true)
        {
            int read = await ch.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (read == 0) break;
            sb.Append(Encoding.UTF8.GetString(buffer, 0, read));
        }

        return sb.ToString();
    }

    public async IAsyncEnumerable<string> ShellCommandLinesAsync(
        string command,
        [System.Runtime.CompilerServices.EnumeratorCancellation]
        CancellationToken ct = default)
    {
        await using SdbChannel ch = await OpenAsync($"shell:{command}\0", ct).ConfigureAwait(false);

        const int MaxData = 8192;
        byte[] buffer = new byte[MaxData];
        var decoder = Encoding.UTF8.GetDecoder();
        var charBuf = new char[MaxData];
        var sb = new StringBuilder();

        while (true)
        {
            int read = await ch.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (read == 0) break;

            int chars = decoder.GetChars(buffer, 0, read, charBuf, 0, false);
            if (chars > 0) sb.Append(charBuf, 0, chars);

            // extract complete lines (up to last '\n'), leave partial line in sb
            int lastNewline = -1;
            for (int i = sb.Length - 1; i >= 0; i--)
            {
                if (sb[i] == '\n')
                {
                    lastNewline = i;
                    break;
                }
            }

            if (lastNewline >= 0)
            {
                string toProcess = sb.ToString(0, lastNewline + 1);
                string[] lines = toProcess.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
                foreach (string line in lines)
                {
                    yield return line;
                }

                sb.Remove(0, lastNewline + 1);
            }
        }

        // flush decoder and emit any remaining text as lines
        int finalChars = decoder.GetChars([], 0, 0, charBuf, 0, true);
        if (finalChars > 0) sb.Append(charBuf, 0, finalChars);

        if (sb.Length > 0)
        {
            string[] remaining = sb.ToString().Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in remaining) yield return line;
        }
    }

    public async Task<Dictionary<string, string>> CapabilityAsync(CancellationToken ct = default)
    {
        await using SdbChannel ch = await OpenAsync("capability:\0", ct).ConfigureAwait(false);
        byte[] buffer = new byte[MaxData];
        List<byte> allBytes = [];

        while (true)
        {
            int read = await ch.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (read == 0) break;

            allBytes.AddRange(buffer[..read]);
        }

        if (allBytes.Count < 2) return [];

        // skip two first bytes from payload as they represent the length in hex
        string response = Encoding.UTF8.GetString(allBytes.ToArray()[2..]);

        string[] lines = response.Split('\n');
        Dictionary<string, string> result = [];
        foreach (string line in lines)
        {
            string[] parts = line.Split(':', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 2)
            {
                result.Add(parts[0], parts[1]);
            }
        }

        return result;
    }

    public async Task PushAsync(
        Stream localStream,
        string remotePath,
        IProgress<double>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(localStream);
        if (string.IsNullOrEmpty(remotePath)) throw new ArgumentNullException(nameof(remotePath));

        await using SdbChannel ch = await OpenAsync("sync:\0", ct).ConfigureAwait(false);

        // Build SEND request
        byte[] pathBytes = Encoding.UTF8.GetBytes(remotePath);
        await SendSyncPacketAsync(ch, Encoding.ASCII.GetBytes("SEND"), pathBytes, ct).ConfigureAwait(false);

        // Track progress
        long totalSent = 0;
        long? totalLength = localStream.CanSeek ? localStream.Length : null;

        byte[] buffer = new byte[SYNC_MAX_DATA];

        while (true)
        {
            ct.ThrowIfCancellationRequested();
            int read = await localStream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
            if (read == 0) break;

            await SendSyncPacketAsync(ch, Encoding.ASCII.GetBytes("DATA"), buffer.AsMemory(0, read), ct)
                .ConfigureAwait(false);

            totalSent += read;

            if (progress != null && totalLength.HasValue && totalLength.Value > 0)
            {
                double percent = totalSent / (double)totalLength.Value * 100.0;
                progress.Report(percent);
            }
        }

        // send DONE with mtime
        uint mtime = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        byte[] mtimeBuf = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(mtimeBuf, mtime);
        await SendSyncPacketAsync(ch, Encoding.ASCII.GetBytes("DONE"), mtimeBuf, ct).ConfigureAwait(false);

        // read responses until OKAY or FAIL
        while (true)
        {
            (string respId, byte[] respPayload) = await ReadSyncResponseAsync(ch, ct).ConfigureAwait(false);
            if (respId == "OKAY")
            {
                progress?.Report(100.0); // force 100% on success
                return;
            }

            if (respId == "FAIL")
            {
                string msg = respPayload.Length > 0 ? Encoding.UTF8.GetString(respPayload) : "unknown";
                throw new InvalidOperationException($"sdb sync: FAIL: {msg}");
            }
        }
    }

    private static async Task SendSyncPacketAsync(SdbChannel ch, byte[] id4, ReadOnlyMemory<byte> payload,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(id4);
        ArgumentNullException.ThrowIfNull(ch);
        if (id4.Length != 4) throw new ArgumentException("id4 must be 4 bytes", nameof(id4));

        // build: 4 bytes id (ASCII), 4 bytes uint32 length (little-endian), then payload bytes (if any)
        byte[] header = new byte[8];
        Buffer.BlockCopy(id4, 0, header, 0, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4, 4), (uint)payload.Length);

        if (payload.Length == 0)
        {
            await ch.WriteAsync(header, ct).ConfigureAwait(false);
            return;
        }

        // allocate contiguous buffer of header + payload
        byte[] buf = new byte[8 + payload.Length];
        header.CopyTo(buf, 0);
        // copy payload
        payload.CopyTo(buf.AsMemory(8));
        await ch.WriteAsync(buf, ct).ConfigureAwait(false);
    }

    private static async Task<(string id, byte[] payload)> ReadSyncResponseAsync(SdbChannel ch, CancellationToken ct)
    {
        byte[] header = await ReadExactlyFromChannelAsync(ch, 8, ct).ConfigureAwait(false);
        if (header.Length < 8) throw new EndOfStreamException("Unexpected EOF reading sync header");
        string id = Encoding.ASCII.GetString(header, 0, 4);
        uint len = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4, 4));
        byte[] payload = [];
        if (len > 0)
        {
            payload = await ReadExactlyFromChannelAsync(ch, (int)len, ct).ConfigureAwait(false);
        }

        return (id, payload);
    }

    private static async Task<byte[]> ReadExactlyFromChannelAsync(SdbChannel ch, int size, CancellationToken ct)
    {
        if (size == 0) return [];
        byte[] result = new byte[size];
        int pos = 0;
        while (pos < size)
        {
            int wanted = size - pos;
            Memory<byte> slice = new(result, pos, wanted);
            int read = await ch.ReadAsync(slice, ct).ConfigureAwait(false);
            if (read == 0)
            {
                // channel closed/EOF early
                throw new EndOfStreamException("Unexpected EOF from channel while reading sync payload");
            }

            pos += read;
        }

        return result;
    }

    internal async Task WriteFrameAsync(SdbFrame frame, CancellationToken ct = default)
    {
        if (_transport == null) throw new InvalidOperationException("Not connected");
        await _transport.WriteFrameAsync(frame, ct).ConfigureAwait(false);
    }

    private async Task PumpLoopAsync(CancellationToken ct)
    {
        ISdbFrameTransport? transport = _transport;
        if (transport == null) return;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                SdbFrame frame;
                try
                {
                    frame = await transport.ReadFrameAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    // stop pump on remote close or invalid data
                    break;
                }

                switch (frame.Command)
                {
                    case SdbCommand.Okay:
                        // OKAY: arg0 = remoteId, arg1 = localId
                    {
                        uint remoteId = frame.Arg0;
                        uint localId = frame.Arg1;

                        if (_channelsByLocalId.TryGetValue(localId, out SdbChannel? ch))
                        {
                            // set RemoteId and add remote map
                            ch.RemoteId = remoteId;
                            _channelsByRemoteId.TryAdd(remoteId, ch);

                            // If there's a pending Open, complete it now (prefer TryRemove to avoid races)
                            if (_pendingOpens.TryRemove(localId, out TaskCompletionSource<SdbChannel>? tcs))
                            {
                                // complete the TCS with the channel
                                tcs.TrySetResult(ch);
                            }
                        }
                        // No local channel present; ignore or optionally send CLSE
                    }
                        break;

                    case SdbCommand.Wrte:
                        // incoming: arg0 = remoteId, arg1 = localId
                    {
                        uint remoteId = frame.Arg0;
                        uint localId = frame.Arg1;
                        if (_channelsByLocalId.TryGetValue(localId, out SdbChannel? ch))
                        {
                            // dispatch payload even if RemoteId == 0 (device writes early)
                            ch.EnqueueIncoming(frame.Payload);

                            // send OKAY back to acknowledge
                            var okay = new SdbFrame
                            {
                                Command = SdbCommand.Okay,
                                Arg0 = localId,
                                Arg1 = remoteId,
                                Payload = []
                            };

                            try
                            {
                                await WriteFrameAsync(okay, ct).ConfigureAwait(false);
                            }
                            catch
                            {
                            }
                        }
                        else
                        {
                            // If the device wrote to a channel we don't have, reply CLSE to tell it to close
                            var clse = new SdbFrame
                            {
                                Command = SdbCommand.Clse,
                                Arg0 = localId,
                                Arg1 = remoteId,
                                Payload = []
                            };
                            try
                            {
                                await WriteFrameAsync(clse, ct).ConfigureAwait(false);
                            }
                            catch
                            {
                            }
                        }
                    }
                        break;

                    case SdbCommand.Clse:
                        // incoming: arg0 = remoteId, arg1 = localId
                    {
                        uint remoteId = frame.Arg0;
                        uint localId = frame.Arg1;

                        // If there's a pending open for this localId that hasn't seen OKAY yet,
                        // we should fail that pending open with an exception.
                        if (_pendingOpens.TryRemove(localId, out TaskCompletionSource<SdbChannel>? pendingTcs))
                        {
                            // We got closed before OKAY -> indicate failure
                            pendingTcs.TrySetException(
                                new InvalidOperationException("Remote closed channel before sending OKAY"));
                        }

                        if (_channelsByLocalId.TryRemove(localId, out SdbChannel? ch))
                        {
                            // signal close to channel readers
                            ch.EnqueueIncoming([]);
                            _channelsByRemoteId.TryRemove(remoteId, out _);
                        }

                        // send CLSE back to acknowledge (if we still have transport)
                        var clse = new SdbFrame
                        {
                            Command = SdbCommand.Clse,
                            Arg0 = localId,
                            Arg1 = remoteId,
                            Payload = []
                        };

                        try
                        {
                            await WriteFrameAsync(clse, ct).ConfigureAwait(false);
                        }
                        catch
                        {
                        }
                    }
                        break;

                    case SdbCommand.Open:
                        // device initiated open -> not implemented in this client; send CLSE to indicate we don't accept
                    {
                        uint localId = frame.Arg1; // from device: arg1 is client-local-id?
                        // safe action: send CLSE with local/remote swapped so device knows
                        var clse = new SdbFrame
                        {
                            Command = SdbCommand.Clse,
                            Arg0 = frame.Arg1,
                            Arg1 = frame.Arg0,
                            Payload = []
                        };
                        try
                        {
                            await WriteFrameAsync(clse, ct).ConfigureAwait(false);
                        }
                        catch
                        {
                        }
                    }
                        break;

                    case SdbCommand.Cnxn:
                        // ignore additional CNXN frames
                        break;
                }
            }
        }
        finally
        {
            // on pump exit, close all channels
            foreach (KeyValuePair<uint, SdbChannel> kv in _channelsByLocalId)
            {
                SdbChannel c = kv.Value;
                c.EnqueueIncoming([]); // signal EOF
            }
        }
    }

    private uint GetNextLocalId() => Interlocked.Increment(ref _nextLocalId);
}