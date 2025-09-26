using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using TizenAppInstallerCli.SdbClient;
using TizenAppInstallerCli.SigningManager;

namespace TizenAppInstallerCli;

public class TizenInstaller
{
    private readonly string _packagePath;
    private readonly SdbTcpDevice _sdbClient;
    private readonly Stream _packageStream;
    private Stream? _installStream = null;
    
    public string? PackageId { get; private set; }

    public TizenInstaller(string packagePath, SdbTcpDevice sdbClient)
    {
        _packagePath = packagePath;
        _sdbClient = sdbClient;
        _packageStream = File.OpenRead(_packagePath);
    }

    public async Task InstallApp(
        IProgress<double>? uploadProgress = null,
        IProgress<double>? installProgress = null
    )
    {
        if (_installStream == null) throw new InvalidOperationException("Install stream not prepared. Call SignPackageIfNecessary first.");
        
        string remotePath = $"/home/owner/share/tmp/sdk_tools/tmp/{Path.GetFileName(_packagePath)}";
        string appId = await FindPackageId();
        await _sdbClient.PushAsync(_installStream, remotePath, uploadProgress);

        await foreach (string line in _sdbClient.ShellCommandLinesAsync($"0 vd_appinstall {appId} {remotePath}"))
        {
            if (installProgress == null) continue;

            var pctRx = new Regex(@"\[(\d{1,3})\]", RegexOptions.Compiled);
            Match m = pctRx.Match(line);
            if (m.Success && int.TryParse(m.Groups[1].Value, out int pct))
            {
                installProgress.Report(Math.Clamp(pct, 0, 100));
            }
        }
    }

    public async Task SignPackageIfNecessary()
    {
        Version tizenVersion = await GetTizenVersion();

        Stream installStream;
        if (tizenVersion >= new Version("7.0"))
        {
            installStream = await SignApp();
        }
        else
        {
            installStream = _packageStream;
        }

        _installStream = installStream;
    }

    private async Task<Version> GetTizenVersion()
    {
        Dictionary<string, string> capability = await _sdbClient.CapabilityAsync();
        string version = capability.GetValueOrDefault("platform_version", "9.0");

        return new Version(version);
    }

    private async Task<Stream> SignApp()
    {
        SamsungAuth? samsungAuth = await SamsungLoginService.PerformSamsungLoginAsync();
        if (samsungAuth is null)
            throw new Exception("Could not authenticate with Samsung servers");

        SamsungCertificateCreator certCreator = new();

        string deviceUid = await GetTvDeviceUid();

        string email = samsungAuth.InputEmailID ?? "";
        AuthorInfo authorInfo = new(
            Name: email,
            Email: email,
            Password: email,
            PrivilegeLevel: "Public"
        );

        (X509Certificate2Collection authorPfx, X509Certificate2Collection distributorPfx, _) =
            await certCreator.CreateCertificateAsync(authorInfo, samsungAuth, [deviceUid]);
        Stream signedStream = await TizenResigner.ResignPackageAsync(_packageStream, authorPfx, distributorPfx);

        return signedStream;
    }

    private async Task<string> GetTvDeviceUid()
    {
        string deviceInfo = await _sdbClient.ShellCommandAsync("0 getduid");
        return deviceInfo.Trim();
    }

    public async Task<bool> IsAppAlreadyInstalled()
    {
        string packageId = await FindPackageId();
        string appList = await _sdbClient.ShellCommandAsync("0 vd_applist");

        return appList.Contains(packageId);
    }


    public async Task UninstallApp(IProgress<double>? progress = null)
    {
        string packageId = await FindPackageId();
        using MemoryStream memoryStream = new();

        var pctRx = new Regex(@"\[(\d{1,3})\]", RegexOptions.Compiled);

        await foreach (string line in _sdbClient.ShellCommandLinesAsync($"0 vd_appuninstall {packageId}"))
        {
            if (progress == null) continue;

            Match m = pctRx.Match(line);
            if (m.Success && int.TryParse(m.Groups[1].Value, out int pct))
            {
                progress.Report(Math.Clamp(pct, 0, 100));
            }
        }
    }

    private async Task<string> FindPackageId()
    {
        if (PackageId != null) return PackageId;

        using var archive = new ZipArchive(_packageStream, ZipArchiveMode.Read, leaveOpen: true);

        ZipArchiveEntry? configEntry = archive.GetEntry("config.xml");
        ZipArchiveEntry? manifestEntry = archive.GetEntry("tizen-manifest.xml");
        bool isWgt = configEntry is not null;

        ZipArchiveEntry? targetEntry = isWgt ? configEntry : manifestEntry;

        if (targetEntry is null)
        {
            throw new Exception("Invalid App. No target entry found");
        }

        string xmlText;
        await using (Stream stream = targetEntry.Open())
        using (var sr = new StreamReader(stream))
        {
            xmlText = await sr.ReadToEndAsync().ConfigureAwait(false);
        }

        if (string.IsNullOrWhiteSpace(xmlText))
            throw new Exception("Invalid App. Could not read xml entry");

        XDocument doc;
        try
        {
            doc = XDocument.Parse(xmlText);
        }
        catch
        {
            throw new Exception("Invalid App. Could not read xml entry");
        }

        string? packageId = null;

        if (!isWgt)
        {
            XElement? root = doc.Root;
            packageId = root?.Attribute("package")?.Value;
            if (string.IsNullOrWhiteSpace(packageId))
            {
                XElement? manifestElem = doc.Descendants().FirstOrDefault(e =>
                    string.Equals(e.Name.LocalName, "manifest", StringComparison.OrdinalIgnoreCase));
                packageId = manifestElem?.Attribute("package")?.Value;
            }
        }
        else
        {
            XElement? applicationElem = doc
                .Descendants()
                .FirstOrDefault(e =>
                    string.Equals(e.Name.LocalName, "application", StringComparison.OrdinalIgnoreCase));

            if (applicationElem is not null)
            {
                packageId = applicationElem.Attribute("id")?.Value;
            }

            if (string.IsNullOrWhiteSpace(packageId))
            {
                XElement? widgetElem = doc.Root;
                if (widgetElem is not null)
                {
                    string? idAttr = widgetElem.Attribute("id")?.Value;
                    if (!string.IsNullOrWhiteSpace(idAttr))
                        packageId = idAttr;
                }
            }
        }

        if (string.IsNullOrWhiteSpace(packageId))
            throw new Exception("Invalid App. Could not find package ID");

        PackageId = packageId.Trim();
        _packageStream.Seek(0, SeekOrigin.Begin);
        return PackageId;
    }
}