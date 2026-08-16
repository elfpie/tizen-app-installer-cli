using Xunit;

namespace TizenAppInstallerCli.Tests;

public class TizenInstallerTests
{
    private const string AppId = "sample123.SampleApp";

    [Fact]
    public void InstallSucceeded_AcceptsMatchingCompletionMarker()
    {
        string[] output =
        [
            $"app_id[{AppId}] install start",
            $"app_id[{AppId}] installing[100]",
            $"app_id[{AppId}] install completed",
            "cmd_ret:0"
        ];

        Assert.True(TizenInstaller.InstallSucceeded(AppId, output));
    }

    [Fact]
    public void InstallSucceeded_RejectsCertificateFailureEvenWhenCommandReturnsZero()
    {
        string[] output =
        [
            $"app_id[{AppId}] install start",
            $"app_id[{AppId}] install failed[118, -12], reason: Check certificate error",
            "cmd_ret:0"
        ];

        Assert.False(TizenInstaller.InstallSucceeded(AppId, output));
    }

    [Theory]
    [InlineData("cmd_ret:0")]
    [InlineData("app_id[someOtherApp.OtherApp] install completed")]
    [InlineData("app_id[sample123.SampleApp] installing[100]")]
    public void InstallSucceeded_RejectsOutputWithoutMatchingCompletion(string output)
    {
        Assert.False(TizenInstaller.InstallSucceeded(AppId, [output]));
    }

    [Fact]
    public void InstallSucceeded_RejectsFailureAfterCompletion()
    {
        string[] output =
        [
            $"app_id[{AppId}] install completed",
            $"app_id[{AppId}] install failed[118]"
        ];

        Assert.False(TizenInstaller.InstallSucceeded(AppId, output));
    }
}
