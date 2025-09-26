namespace TizenAppInstallerCli.SdbClient;

public static class SdbChecksum
{
    public static uint Sum32(ReadOnlySpan<byte> payload)
    {
        uint sum = 0;
        if (payload.Length > 0)
        {
            foreach (byte b in payload) sum += b;
        }

        return sum;
    }

    public static uint Sum32(byte[] payload) => Sum32(payload.AsSpan());
}
