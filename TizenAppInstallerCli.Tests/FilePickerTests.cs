using TizenAppInstallerCli;
using Xunit;

namespace TizenAppInstallerCli.Tests;

public class FilePickerTests
{
    [Theory]
    [InlineData("  /tmp/app.wgt  ", "/tmp/app.wgt")]
    [InlineData("\"D:\\Tizen Studio\\Widgets\\Smotrim.wgt\"", "D:\\Tizen Studio\\Widgets\\Smotrim.wgt")]
    [InlineData("'/tmp/Tizen Apps/app.wgt'", "/tmp/Tizen Apps/app.wgt")]
    [InlineData("\"/tmp/app.wgt'", "\"/tmp/app.wgt'")]
    [InlineData("\"\"", "")]
    public void NormalizeManualPath_TrimsInputAndMatchingQuotes(string input, string expected)
    {
        Assert.Equal(expected, FilePicker.NormalizeManualPath(input));
    }
}
