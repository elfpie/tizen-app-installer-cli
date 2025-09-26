using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using TizenAppInstallerCli.SdbClient;

namespace TizenAppInstallerCli.Services;

public class NetworkService
{
    private static int scanTimeoutMs = 1000;

    public static async Task<SdbTcpDevice?> ValidateManualTizenAddress(string ip,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var cts = new CancellationTokenSource(scanTimeoutMs);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                cts.Token, cancellationToken);

            SdbTcpDevice sdbDevice = new(IPAddress.Parse(ip));
            await sdbDevice.ConnectAsync(linkedCts.Token);
            return sdbDevice;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static async Task<List<SdbTcpDevice>> FindTizenTvsAsync(CancellationToken cancellationToken = default,
        bool virtualScan = false)
    {
        ConcurrentBag<SdbTcpDevice> foundDevices = [];
        IEnumerable<IPAddress> localIps = GetRelevantLocalIPs(virtualScan);

        // Group by network prefix to avoid scanning the same network multiple times
        List<string> uniqueNetworks = localIps
            .Select(GetNetworkPrefix)
            .Distinct()
            .ToList();

        await Task.WhenAll(uniqueNetworks.SelectMany(networkPrefix =>
            Enumerable.Range(1, 254)
                .Select(i => $"{networkPrefix}.{i}")
                .Select(async ip =>
                {
                    try
                    {
                        using var cts = new CancellationTokenSource(scanTimeoutMs);
                        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                            cts.Token, cancellationToken);

                        SdbTcpDevice sdbClient = new(IPAddress.Parse(ip));

                        await sdbClient.ConnectAsync(linkedCts.Token);

                        foundDevices.Add(sdbClient);
                    }
                    catch
                    {
                        /* Ignore scan failures */
                    }
                })));

        return foundDevices.ToList();
    }

    public static string GetLocalIpAddress()
    {
        string hostName = Dns.GetHostName();

        IPHostEntry ipEntry = Dns.GetHostEntry(hostName);

        foreach (IPAddress ip in ipEntry.AddressList)
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
            {
                return ip.ToString();
            }
        }

        return string.Empty;
    }

    private static IEnumerable<IPAddress> GetRelevantLocalIPs(bool virtualScan = false)
    {
        List<string> baseIps = NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.OperationalStatus == OperationalStatus.Up)
            .Where(ni =>
                virtualScan || (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
                                ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211))
            .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
            .Where(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork)
            .Where(ip => !IPAddress.IsLoopback(ip.Address))
            .Select(ip => ip.Address.ToString())
            .ToList();


        return baseIps
            .Distinct()
            .Select(IPAddress.Parse);
    }

    private static string GetNetworkPrefix(IPAddress ip)
    {
        byte[] bytes = ip.GetAddressBytes();
        return $"{bytes[0]}.{bytes[1]}.{bytes[2]}";
    }
}