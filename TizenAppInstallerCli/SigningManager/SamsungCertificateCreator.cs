// https://github.com/reisxd/tizen.js/blob/main/src/samsungCertificateCreator.js

using System.IO.Compression;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace TizenAppInstallerCli.SigningManager;

public record AuthorInfo(
    string Name,
    string Email,
    string Password,
    string Country = "",
    string State = "",
    string City = "",
    string Organization = "",
    string? Department = "",
    string PrivilegeLevel = "Public"
);

public sealed class SamsungCertificateCreator : IDisposable
{
    private readonly HttpClient _http = new();
    private readonly Dictionary<string, byte[]> _vdFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _localSamsungCertsPath;
    private bool _disposed;

    private const string ExtensionsIndexUrl = "https://download.tizen.org/sdk/extensions/";
    private static string AuthorEndpoint => "https://svdca.samsungqbe.com/apis/v3/authors";
    private static string DistributorEndpoint => "https://svdca.samsungqbe.com/apis/v3/distributors";

    public SamsungCertificateCreator()
    {
        _localSamsungCertsPath = Path.Combine(AppContext.BaseDirectory, "SamsungCerts");
    }

    /// <summary>
    /// Returns full certificate collections (leaf with private key first, then intermediates) and the distributor XML text.
    /// </summary>
    public async Task<(X509Certificate2Collection authorCerts, X509Certificate2Collection distributorCerts, string distributorXml)>
        CreateCertificateAsync(
            AuthorInfo authorInfo,
            SamsungAuth accessInfo,
            string[] duidList)
    {
        ArgumentNullException.ThrowIfNull(authorInfo);
        ArgumentNullException.ThrowIfNull(accessInfo);

        await EnsureVdCertificatesInMemoryAsync().ConfigureAwait(false);

        // generate CSRs and keys (keep RSA instances until after CopyWithPrivateKey)
        (string authorCsrPem, RSA authorRsa) = CreateAuthorCsr(authorInfo);
        (string distributorCsrPem, RSA distributorRsa) = CreateDistributorCsr(authorInfo, duidList);

        // post CSRs
        string authorResponse =
            await PostCsrAsync(AuthorEndpoint, accessInfo, authorCsrPem, "author.csr").ConfigureAwait(false);
        string distributorResponse = await PostCsrAsync(DistributorEndpoint, accessInfo, distributorCsrPem,
            "distributor.csr", extraForm: form =>
            {
                form.Add(new StringContent(authorInfo.PrivilegeLevel), "privilege_level");
                form.Add(new StringContent("Individual"), "developer_type");
            }).ConfigureAwait(false);

        try
        {
            // Build certificate collections with proper intermediate chains
            X509Certificate2Collection authorColl = BuildAuthorCertificateChain(authorResponse, authorRsa, authorInfo);
            X509Certificate2Collection distributorColl =
                BuildDistributorCertificateChain(distributorResponse, distributorRsa, authorInfo);

            return (authorColl, distributorColl, distributorResponse);
        }
        finally
        {
            // Always dispose RSA objects
            authorRsa.Dispose();
            distributorRsa.Dispose();
        }
    }

    private X509Certificate2Collection BuildAuthorCertificateChain(string response, RSA privateKey,
        AuthorInfo authorInfo)
    {
        // Extract the leaf certificate from response
        X509Certificate2? leafCert = ExtractLeafCertificateFromResponse(response, privateKey);
        if (leafCert == null)
            throw new InvalidOperationException("Could not extract author certificate from server response.");

        // Build the full chain: leaf + intermediate
        var collection = new X509Certificate2Collection
        {
            leafCert
        };

        // Add intermediate certificate (author CA)
        byte[]? intermediateCertData = GetVdCertificate("vd_tizen_dev_author_ca.cer");
        if (intermediateCertData != null)
        {
            X509Certificate2 intermediateCert = X509CertificateLoader.LoadCertificate(intermediateCertData);
            collection.Add(intermediateCert);
        }

        return collection;
    }

    private X509Certificate2Collection BuildDistributorCertificateChain(string response, RSA privateKey,
        AuthorInfo authorInfo)
    {
        // Extract the leaf certificate from response
        X509Certificate2? leafCert = ExtractLeafCertificateFromResponse(response, privateKey);
        if (leafCert == null)
            throw new InvalidOperationException("Could not extract distributor certificate from server response.");

        // Build the full chain: leaf + intermediate
        var collection = new X509Certificate2Collection
        {
            leafCert
        };

        // Add appropriate intermediate certificate based on privilege level
        string intermediateCertFileName = authorInfo.PrivilegeLevel == "Public"
            ? "vd_tizen_dev_public2.crt"
            : "vd_tizen_dev_partner2.crt";

        byte[]? intermediateCertData = GetVdCertificate(intermediateCertFileName);
        if (intermediateCertData != null)
        {
            X509Certificate2 intermediateCert = X509CertificateLoader.LoadCertificate(intermediateCertData);
            collection.Add(intermediateCert);
        }

        return collection;
    }

    private X509Certificate2? ExtractLeafCertificateFromResponse(string response, RSA privateKey)
    {
        // Try to extract PEM blocks first
        List<string> pemBlocks = ExtractAllPemBlocks(response);

        if (pemBlocks.Count == 0)
        {
            // Try to extract from XML
            pemBlocks = TryExtractAllCertsFromXmlText(response) ?? [];
        }

        if (pemBlocks.Count == 0)
            return null;

        // Find the certificate that matches our private key
        foreach (string pem in pemBlocks)
        {
            try
            {
                X509Certificate2 cert = X509CertificateLoader.LoadCertificate(PemToDer(pem));

                // Check if this certificate matches our private key
                if (CertificateMatchesPrivateKey(cert, privateKey))
                {
                    return cert.CopyWithPrivateKey(privateKey);
                }
            }
            catch
            {
                // Skip invalid certificates
                continue;
            }
        }

        // If no matching certificate found, use the first one (fallback)
        if (pemBlocks.Count > 0)
        {
            try
            {
                X509Certificate2 cert = X509CertificateLoader.LoadCertificate(PemToDer(pemBlocks[0]));
                return cert.CopyWithPrivateKey(privateKey);
            }
            catch
            {
                // If this fails too, return null
            }
        }

        return null;
    }

    private bool CertificateMatchesPrivateKey(X509Certificate2 cert, RSA privateKey)
    {
        try
        {
            using RSA? publicKey = cert.GetRSAPublicKey();
            if (publicKey == null) return false;

            RSAParameters publicParams = publicKey.ExportParameters(false);
            RSAParameters privateParams = privateKey.ExportParameters(true);

            return publicParams.Modulus != null &&
                   privateParams.Modulus != null &&
                   ByteArraysEqual(publicParams.Modulus, privateParams.Modulus);
        }
        catch
        {
            return false;
        }
    }

    private byte[]? GetVdCertificate(string fileName)
    {
        return _vdFiles.GetValueOrDefault(fileName);
    }

    private async Task EnsureVdCertificatesInMemoryAsync()
    {
        if (_vdFiles.Count > 0) return;

        // 1) Try loading local certificates from likely locations
        try
        {
            LoadVdCertificatesFromLocal(_localSamsungCertsPath);
            if (_vdFiles.Count > 0) return;
        }
        catch
        {
            // ignore and try next
        }

        // 2) No local certs found -> find latest tizen-certificate-extension zip on the server
        string bundleUrl = await GetLatestBundleUrlAsync().ConfigureAwait(false) ?? throw new InvalidOperationException("Could not find the latest tizen-certificate-extension bundle URL.");

        using HttpResponseMessage resp = await _http.GetAsync(bundleUrl).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();

        await using Stream topStream = await resp.Content.ReadAsStreamAsync().ConfigureAwait(false);
        using var topArchive = new ZipArchive(topStream, ZipArchiveMode.Read);

        await ExtractCertsFromArchiveAsync(topArchive).ConfigureAwait(false);
    }

    private void LoadVdCertificatesFromLocal(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory)) return;
        if (!Directory.Exists(directory)) return;

        foreach (var file in Directory.EnumerateFiles(directory, "*.*", SearchOption.TopDirectoryOnly)
                     .Where(f => f.EndsWith(".crt", StringComparison.OrdinalIgnoreCase) ||
                                 f.EndsWith(".cer", StringComparison.OrdinalIgnoreCase)))
        {
            string name = Path.GetFileName(file);
            if (_vdFiles.ContainsKey(name)) continue;
            byte[] bytes = File.ReadAllBytes(file);
            _vdFiles[name] = bytes;
        }
    }

    private async Task<string?> GetLatestBundleUrlAsync()
    {
        using var resp = await _http.GetAsync(ExtensionsIndexUrl).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) return null;

        string text = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);

        var matches = Regex.Matches(text, @"tizen-certificate-extension_(\d+(?:\.\d+)*)\.zip", RegexOptions.IgnoreCase);
        if (matches.Count == 0) return null;

        var map = new Dictionary<Version, string>();
        foreach (Match m in matches)
        {
            string verStr = m.Groups[1].Value;
            if (Version.TryParse(verStr, out var ver))
            {
                string fileName = m.Value;
                // keep one filename per version
                if (!map.ContainsKey(ver)) map[ver] = fileName;
            }
        }

        if (map.Count == 0) return null;

        var latestVersion = map.Keys.OrderByDescending(v => v).First();
        return ExtensionsIndexUrl + map[latestVersion];
    }

    private async Task ExtractCertsFromArchiveAsync(ZipArchive archive)
    {
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            string name = entry.Name;
            if (string.IsNullOrEmpty(name)) continue;

            if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
            {
                using var ms = new MemoryStream();
                await using (Stream es = entry.Open())
                {
                    await es.CopyToAsync(ms).ConfigureAwait(false);
                }

                ms.Position = 0;
                using var nested = new ZipArchive(ms, ZipArchiveMode.Read);
                await ExtractCertsFromArchiveAsync(nested).ConfigureAwait(false);
            }
            else if (name.EndsWith(".crt", StringComparison.OrdinalIgnoreCase) ||
                     name.EndsWith(".cer", StringComparison.OrdinalIgnoreCase))
            {
                await using Stream es = entry.Open();
                using var outMs = new MemoryStream();
                await es.CopyToAsync(outMs).ConfigureAwait(false);
                _vdFiles[name] = outMs.ToArray();
            }
        }
    }

    private (string CsrPem, RSA Rsa) CreateAuthorCsr(AuthorInfo authorInfo, int keySize = 2048)
    {
        var rsa = RSA.Create(keySize);
        string dn =
            $"CN={authorInfo.Name}, OU={authorInfo.Department}, O={authorInfo.Organization}, L={authorInfo.City}, ST={authorInfo.State}, C={authorInfo.Country}";
        var req = new CertificateRequest(new X500DistinguishedName(dn), rsa, HashAlgorithmName.SHA512,
            RSASignaturePadding.Pkcs1);
        byte[] csr = req.CreateSigningRequest();
        string pem = PemEncode("CERTIFICATE REQUEST", csr);
        return (pem, rsa);
    }

    private (string CsrPem, RSA Rsa) CreateDistributorCsr(AuthorInfo authorInfo, IEnumerable<string> duidList,
        int keySize = 2048)
    {
        var rsa = RSA.Create(keySize);
        string subject = $"CN=TizenSDK, E={authorInfo.Email}";
        var req = new CertificateRequest(new X500DistinguishedName(subject), rsa, HashAlgorithmName.SHA512,
            RSASignaturePadding.Pkcs1);

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri("URN:tizen:packageid="));
        if (duidList != null)
        {
            foreach (string duid in duidList)
                sanBuilder.AddUri(new Uri($"URN:tizen:deviceid={duid}"));
        }

        req.CertificateExtensions.Add(sanBuilder.Build());

        byte[] csr = req.CreateSigningRequest();
        string pem = PemEncode("CERTIFICATE REQUEST", csr);
        return (pem, rsa);
    }

    private async Task<string> PostCsrAsync(string url, SamsungAuth accessInfo, string csrPem, string filename,
        Action<MultipartFormDataContent>? extraForm = null)
    {
        using var form = new MultipartFormDataContent();
        form.Add(new StringContent(accessInfo.AccessToken), "access_token");
        form.Add(new StringContent(accessInfo.UserId), "user_id");
        form.Add(new StringContent("VD"), "platform");

        byte[] bytes = Encoding.ASCII.GetBytes(csrPem);
        var byteContent = new ByteArrayContent(bytes);
        byteContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
        form.Add(byteContent, "csr", filename);

        extraForm?.Invoke(form);

        using HttpResponseMessage resp = await _http.PostAsync(url, form).ConfigureAwait(false);
        string text = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);

        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"Failed POST to {url}: {resp.StatusCode}\n{text}");

        return text;
    }

    private static List<string> ExtractAllPemBlocks(string text)
    {
        List<string> result = [];
        if (string.IsNullOrEmpty(text)) return result;

        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";

        int idx = 0;
        while (true)
        {
            int b = text.IndexOf(begin, idx, StringComparison.Ordinal);
            if (b < 0) break;
            int e = text.IndexOf(end, b, StringComparison.Ordinal);
            if (e < 0) break;
            e += end.Length;

            string block = text.Substring(b, e - b);
            result.Add(block);
            idx = e;
        }

        return result;
    }

    private static List<string>? TryExtractAllCertsFromXmlText(string xmlOrText)
    {
        List<string> results = [];
        if (string.IsNullOrEmpty(xmlOrText)) return results;

        try
        {
            var doc = new XmlDocument();
            doc.LoadXml(xmlOrText);

            string[] candidateNames = ["X509Certificate", "Certificate", "X509Data", "Cert"];
            foreach (string name in candidateNames)
            {
                XmlNodeList? nodes = doc.GetElementsByTagName(name);
                if (nodes != null && nodes.Count > 0)
                {
                    foreach (XmlNode node in nodes)
                    {
                        string? t = node.InnerText?.Trim();
                        if (string.IsNullOrEmpty(t)) continue;

                        if (t.Contains("-----BEGIN CERTIFICATE-----"))
                        {
                            string? pem = ExtractPemBlock(t);
                            if (!string.IsNullOrEmpty(pem)) results.Add(pem);
                            continue;
                        }

                        string s = new string(t.Where(c => !char.IsWhiteSpace(c)).ToArray());
                        if (s.Length >= 100 && IsBase64(s))
                        {
                            results.Add(WrapPemCertificate(s));
                        }
                    }
                }
            }
        }
        catch
        {
            // not XML — ignore
        }

        return results.Count > 0 ? results : null;
    }

    private static string? ExtractPemBlock(string text)
    {
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        int b = text.IndexOf(begin, StringComparison.Ordinal);
        if (b < 0) return null;
        int e = text.IndexOf(end, b, StringComparison.Ordinal);
        if (e < 0) return null;
        e += end.Length;
        return text.Substring(b, e - b);
    }

    private static bool IsBase64(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        string t = new string(s.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (t.Length < 100) return false;
        Span<byte> buffer = stackalloc byte[1];
        return Convert.TryFromBase64String(t, buffer, out _);
    }

    private static string WrapPemCertificate(string base64Data)
    {
        string norm = new string(base64Data.Where(c => !char.IsWhiteSpace(c)).ToArray());
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN CERTIFICATE-----");
        for (int i = 0; i < norm.Length; i += 64)
        {
            sb.AppendLine(norm.Substring(i, Math.Min(64, norm.Length - i)));
        }

        sb.AppendLine("-----END CERTIFICATE-----");
        return sb.ToString();
    }

    private static byte[] PemToDer(string pem)
    {
        string[] lines = pem.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        var sb = new StringBuilder();
        foreach (string l in lines)
        {
            if (l.StartsWith("-----")) continue;
            sb.Append(l.Trim());
        }

        return Convert.FromBase64String(sb.ToString());
    }

    private static string PemEncode(string label, byte[] data)
    {
        string b64 = Convert.ToBase64String(data);
        var sb = new StringBuilder();
        sb.AppendLine($"-----BEGIN {label}-----");
        for (int i = 0; i < b64.Length; i += 64)
            sb.AppendLine(b64.Substring(i, Math.Min(64, b64.Length - i)));
        sb.AppendLine($"-----END {label}-----");
        return sb.ToString();
    }

    private static bool ByteArraysEqual(byte[] a, byte[] b)
    {
        if (ReferenceEquals(a, b)) return true;
        if (a == null || b == null) return false;
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i])
                return false;
        return true;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _http.Dispose();
        _vdFiles.Clear();
        _disposed = true;
    }
}