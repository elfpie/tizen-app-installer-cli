using System.Text;

namespace TizenAppInstallerCli.SdbClient;

public sealed class SdbFrame
{
    public SdbCommand Command { get; set; }
    public uint Arg0 { get; set; }
    public uint Arg1 { get; set; }
    public uint DataLength { get; set; }
    public uint DataChecksum { get; set; }
    public uint Magic { get; set; }
    public byte[] Payload { get; set; } = [];

    public bool ValidateHeader() => Magic == ((uint)Command ^ 0xffffffffu);

    public bool ValidateChecksum() =>
        DataLength == (uint)(Payload?.Length ?? 0) &&
        DataChecksum == SdbChecksum.Sum32(Payload ?? []);

    public static byte[] StringToAsciiPayload(string s) => Encoding.ASCII.GetBytes(s);
}
