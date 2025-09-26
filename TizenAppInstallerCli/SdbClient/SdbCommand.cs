namespace TizenAppInstallerCli.SdbClient;

public enum SdbCommand : uint
{
    Cnxn = 0x4E584E43, // 'CNXN'
    Auth = 0x48545541, // 'AUTH'
    Open = 0x4E45504F, // 'OPEN'
    Okay = 0x59414B4F, // 'OKAY'
    Wrte = 0x45545257, // 'WRTE'
    Clse = 0x45534C43, // 'CLSE'
}