using System.Net;

namespace TizenAppInstallerCli.SdbClient;

public interface ISdbFrameTransport : IAsyncDisposable
{
    Task WriteFrameAsync(SdbFrame frame, CancellationToken ct = default);
    Task<SdbFrame> ReadFrameAsync(CancellationToken ct = default);
    EndPoint RemoteEndPoint { get; }
}
