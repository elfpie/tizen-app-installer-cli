namespace TizenAppInstallerCli.SdbClient;

public interface ISdbDevice : IAsyncDisposable
{
    string DeviceId { get; }
    Task ConnectAsync(CancellationToken ct = default);
    Task DisconnectAsync();
    Task<SdbChannel> OpenAsync(string service, CancellationToken ct = default);
    Task<int> ShellCommandAsync(string command, Stream output, CancellationToken ct = default);
    Task<string> ShellCommandAsync(string command, CancellationToken ct = default);
    Task<Dictionary<string, string>> CapabilityAsync(CancellationToken ct = default);
    Task PushAsync(Stream localStream, string remotePath, IProgress<double>? progress = null, CancellationToken ct = default);
}