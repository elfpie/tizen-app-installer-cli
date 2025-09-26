// https://github.com/reisxd/tizen.js/blob/main/src/packageSigner.js

using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace TizenAppInstallerCli.SigningManager;

public static class TizenResigner
{
    // These constants come from the JS code you provided
    private const string AuthorPropDigest = "aXbSAVgmAz0GsBUeZ1UmNDRrxkWhDUVGb45dZcNRq429wX3X+x6kaXT3NdNDTSNVTU+ypkysPMGvQY10fG1EWQ==";
    private const string DistributorPropDigest = "/r5npk2VVA46QFJnejgONBEh4BWtjrtu9x/IFeLksjWyGmB/cMWKSJWQl7aU3YRQRZ3AesG8gF7qGyvKX9Snig==";

    private const string XmlDsigNs = "http://www.w3.org/2000/09/xmldsig#";
    private const string XmlDsigMoreRsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    private const string XmlEncSha512 = "http://www.w3.org/2001/04/xmlenc#sha512";
    private const string ExcC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private const string C14n11 = "http://www.w3.org/2006/12/xml-c14n11";

    private record FileEntry(string UriEscaped, byte[] Data);

    /// <summary>
    /// Resigns a Tizen package (widget / TPK).
    /// Now accepts full certificate collections for author & distributor (leaf with private key must be present).
    /// </summary>
    /// <param name="packageStream">Stream containing the original package (zip)</param>
    /// <param name="authorCerts">Author certificate collection (leaf with private key + intermediates)</param>
    /// <param name="distributorCerts">Distributor certificate collection (leaf with private key + intermediates)</param>
    /// <returns>A Stream (MemoryStream) with the resigned ZIP. Position is set to 0.</returns>
    public static async Task<Stream> ResignPackageAsync(
        Stream packageStream,
        X509Certificate2Collection authorCerts,
        X509Certificate2Collection distributorCerts)
    {
        ArgumentNullException.ThrowIfNull(packageStream);
        ArgumentNullException.ThrowIfNull(authorCerts);
        ArgumentNullException.ThrowIfNull(distributorCerts);

        // 1) Read all files from original zip (skip existing signature xmls)
        var files = new List<FileEntry>();
        using (var archive = new ZipArchive(packageStream, ZipArchiveMode.Read, leaveOpen: true))
        {
            foreach (var entry in archive.Entries)
            {
                if (entry.FullName.EndsWith("/")) continue; // directory
                var nameLower = entry.Name.ToLowerInvariant();
                if (nameLower.Contains("signature") && nameLower.EndsWith(".xml")) continue;

                using var ms = new MemoryStream();
                await using var entryStream = entry.Open();
                await entryStream.CopyToAsync(ms);
                files.Add(new FileEntry(Uri.EscapeDataString(entry.FullName), ms.ToArray()));
            }
        }

        // Build AuthorSignature (now passing the full collection)
        files = await BuildSignatureAsync("AuthorSignature", files, authorCerts);

        // Build DistributorSignature (signs files including the author signature)
        files = await BuildSignatureAsync("DistributorSignature", files, distributorCerts);

        // Create new zip with the resulting files
        var outMs = new MemoryStream();
        using (var newZip = new ZipArchive(outMs, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var file in files)
            {
                var entryName = Uri.UnescapeDataString(file.UriEscaped);
                var entry = newZip.CreateEntry(entryName, CompressionLevel.Optimal);
                using var entryStream = entry.Open();
                await entryStream.WriteAsync(file.Data, 0, file.Data.Length);
            }
        }

        outMs.Seek(0, SeekOrigin.Begin);
        return outMs;
    }

    /// <summary>
    /// Builds the signature XML and returns the new files list (signature file inserted first).
    /// Accepts full X509Certificate2Collection for KeyInfo output. The leaf certificate inside the collection must have the private key.
    /// </summary>
    private static async Task<List<FileEntry>> BuildSignatureAsync(
        string id,
        List<FileEntry> inputFiles,
        X509Certificate2Collection certChain)
    {
        if (certChain == null || certChain.Count == 0)
            throw new ArgumentException("Certificate chain must be provided and contain at least one certificate.", nameof(certChain));

        // 0) Fix certChain order, leaf with private key must be first
        var certsOrdered = new X509Certificate2Collection();
        var leafCert = certChain.OfType<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey);
        if (leafCert == null)
            throw new InvalidOperationException("No certificate with a private key was found in the provided certificate collection.");

        certsOrdered.Add(leafCert);
        certChain.Remove(leafCert);
        certsOrdered.AddRange(certChain);
        certChain = certsOrdered;

        // 1) create references: for every file compute SHA512 and add a Reference entry
        var sbReferences = new StringBuilder();
        foreach (var file in inputFiles)
        {
            var digest = ComputeSha512Base64(file.Data);
            sbReferences.Append(CreateReferenceXml(digest, file.UriEscaped, includeTransform: false));
        }

        // add #prop reference using the fixed digest
        var propDigest = id == "AuthorSignature" ? AuthorPropDigest : DistributorPropDigest;
        // In the original JS they included a Transform Algorithm xml-c14n11 specifically for '#prop'
        sbReferences.Append(CreateReferenceXml(propDigest, "#prop", includeTransform: true));

        // 2) build SignedInfo XML string
        var signedInfoXml = new StringBuilder();
        // signedInfoXml.AppendLine("<SignedInfo>");
        signedInfoXml.AppendLine($"<SignedInfo xmlns=\"{XmlDsigNs}\">");  // Add this xmlns to match JS inheritance
        signedInfoXml.AppendLine($"<CanonicalizationMethod Algorithm=\"{ExcC14n}\"></CanonicalizationMethod>");
        signedInfoXml.AppendLine($"<SignatureMethod Algorithm=\"{XmlDsigMoreRsaSha512}\"></SignatureMethod>");
        signedInfoXml.AppendLine(sbReferences.ToString().TrimEnd());
        signedInfoXml.AppendLine("</SignedInfo>");

        // Wrap into a Signature element (so we can canonicalize SignedInfo properly)
        var signatureDoc = new XmlDocument { PreserveWhitespace = true };
        var signatureWrapper = signatureDoc.CreateElement("Signature", XmlDsigNs);
        signatureDoc.AppendChild(signatureWrapper);

        // import SignedInfo into signatureDoc
        var signedInfoNode = CreateXmlFragment(signatureDoc, signedInfoXml.ToString());
        signatureWrapper.AppendChild(signedInfoNode);

        // 3) canonicalize SignedInfo using exclusive c14n (same as JS's ExclusiveCanonicalization)
        var canonicalSignedInfoBytes = CanonicalizeXmlNodeToBytes(signedInfoNode);

        // 4) find the signing certificate (leaf with private key) inside the certChain
        X509Certificate2? signingCert = certChain
            .OfType<X509Certificate2>()
            .FirstOrDefault(c => c.HasPrivateKey);

        if (signingCert == null)
            throw new InvalidOperationException("No certificate with a private key was found in the provided certificate collection.");

        // 5) sign canonicalized bytes with RSA-SHA512 from signingCert private key
        using var rsa = signingCert.GetRSAPrivateKey();
        if (rsa == null) throw new InvalidOperationException("Certificate does not contain an RSA private key.");

        var signatureBytes = rsa.SignData(canonicalSignedInfoBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        var signatureBase64 = Convert.ToBase64String(signatureBytes);
        var signatureBase64Split = SplitBase64Lines(signatureBase64);

        // 6) Build KeyInfo (one <X509Certificate> element per cert in provided collection, in collection order)
        var keyInfoSb = new StringBuilder();
        keyInfoSb.AppendLine("<KeyInfo>");
        keyInfoSb.AppendLine("<X509Data>");
        foreach (X509Certificate2 cert in certChain)
        {
            var certBase64 = Convert.ToBase64String(cert.RawData); // DER -> base64
            keyInfoSb.AppendLine("<X509Certificate>");
            keyInfoSb.AppendLine(SplitBase64Lines(certBase64)); // lines with '\n'
            keyInfoSb.AppendLine("</X509Certificate>");
        }
        keyInfoSb.AppendLine("</X509Data>");
        keyInfoSb.AppendLine("</KeyInfo>");

        // 7) Build Object Id="prop" with SignatureProperties (same as original)
        var role = id == "AuthorSignature" ? "author" : "distributor";
        var objectSb = new StringBuilder();
        objectSb.Append("<Object Id=\"prop\">");
        objectSb.Append("<SignatureProperties xmlns:dsp=\"http://www.w3.org/2009/xmldsig-properties\">");
        objectSb.Append($"<SignatureProperty Id=\"profile\" Target=\"#{id}\">");
        objectSb.Append("<dsp:Profile URI=\"http://www.w3.org/ns/widgets-digsig#profile\"></dsp:Profile>");
        objectSb.Append("</SignatureProperty>");
        objectSb.Append($"<SignatureProperty Id=\"role\" Target=\"#{id}\">");
        objectSb.Append($"<dsp:Role URI=\"http://www.w3.org/ns/widgets-digsig#role-{role}\"></dsp:Role>");
        objectSb.Append("</SignatureProperty>");
        objectSb.Append($"<SignatureProperty Id=\"identifier\" Target=\"#{id}\">");
        objectSb.Append("<dsp:Identifier></dsp:Identifier>");
        objectSb.Append("</SignatureProperty>");
        objectSb.Append("</SignatureProperties>");
        objectSb.Append("</Object>");

        // 8) Compose final Signature XML (SignedInfo + SignatureValue + KeyInfo + Object)
        var signatureXmlSb = new StringBuilder();
        signatureXmlSb.AppendLine($"<Signature xmlns=\"{XmlDsigNs}\" Id=\"{id}\">");
        signatureXmlSb.AppendLine(signedInfoXml.ToString().TrimEnd());
        signatureXmlSb.AppendLine($"<SignatureValue>");
        signatureXmlSb.AppendLine(signatureBase64Split);
        signatureXmlSb.AppendLine($"</SignatureValue>");
        signatureXmlSb.AppendLine(keyInfoSb.ToString().TrimEnd());
        signatureXmlSb.AppendLine(objectSb.ToString().TrimEnd());
        signatureXmlSb.Append($"</Signature>");

        // 9) Insert signature file at the beginning of files list
        var signatureFileName = id == "AuthorSignature" ? "author-signature.xml" : "signature1.xml";
        var signatureBytesUtf8 = Encoding.UTF8.GetBytes(signatureXmlSb.ToString());
        var newFiles = new List<FileEntry>
        {
            new FileEntry(Uri.EscapeDataString(signatureFileName), signatureBytesUtf8)
        };
        // Append original files (they stay in same relative order)
        newFiles.AddRange(inputFiles);

        await Task.CompletedTask;
        return newFiles;
    }

    private static string CreateReferenceXml(string digestBase64, string uri, bool includeTransform)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"<Reference URI=\"{EscapeXmlAttribute(uri)}\">");
        if (includeTransform)
        {
            sb.AppendLine("<Transforms>");
            sb.AppendLine($"<Transform Algorithm=\"{C14n11}\"></Transform>");
            sb.AppendLine("</Transforms>");
        }
        sb.AppendLine($"<DigestMethod Algorithm=\"{XmlEncSha512}\"></DigestMethod>");
        // JS wrapped DigestValue to lines 76 chars each. We'll follow that formatting.
        sb.AppendLine($"<DigestValue>{SplitBase64Lines(digestBase64)}</DigestValue>");
        sb.AppendLine("</Reference>");
        return sb.ToString();
    }

    private static string EscapeXmlAttribute(string s)
    {
        return s.Replace("&", "&amp;").Replace("\"", "&quot;").Replace("'", "&apos;").Replace("<", "&lt;").Replace(">", "&gt;");
    }

    private static string ComputeSha512Base64(byte[] data)
    {
        using var sha = SHA512.Create();
        var hash = sha.ComputeHash(data);
        return Convert.ToBase64String(hash);
    }

    // Use explicit '\n' to match JS formatting
    private static string SplitBase64Lines(string base64)
    {
        if (string.IsNullOrEmpty(base64)) return base64;
        var sb = new StringBuilder();
        for (int i = 0; i < base64.Length; i += 76)
        {
            var len = Math.Min(76, base64.Length - i);
            sb.Append(base64.Substring(i, len));
            sb.Append('\n');
        }
        return sb.ToString().TrimEnd('\n');
    }

    private static XmlElement CreateXmlFragment(XmlDocument doc, string xml)
    {
        // Parse the fragment in a temporary doc and import the root element
        XmlDocument tmp = new() { PreserveWhitespace = true };
        tmp.LoadXml(xml);

        if (tmp.DocumentElement == null)
            throw new InvalidOperationException("Failed to parse XML fragment.");

        var imported = doc.ImportNode(tmp.DocumentElement, deep: true);
        return (XmlElement)imported;
    }

    private static byte[] CanonicalizeXmlNodeToBytes(XmlNode node)
    {
        // Canonicalize using exclusive C14N (XmlDsigExcC14NTransform)
        var tempDoc = new XmlDocument { PreserveWhitespace = true };
        // Import the node into tempDoc
        var imported = tempDoc.ImportNode(node, true);
        tempDoc.AppendChild(imported);

        var transform = new XmlDsigExcC14NTransform();
        transform.LoadInput(tempDoc);
        using var outStream = (Stream)transform.GetOutput(typeof(Stream));
        using var ms = new MemoryStream();
        outStream.CopyTo(ms);
        return ms.ToArray();
    }
}