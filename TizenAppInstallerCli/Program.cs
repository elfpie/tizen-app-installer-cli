using Spectre.Console;
using TizenAppInstallerCli.SdbClient;
using TizenAppInstallerCli.Services;

namespace TizenAppInstallerCli;

public static class Program
{
    public static async Task Main(string[] args)
    {
        string userIp = NetworkService.GetLocalIpAddress();
        AnsiConsole.MarkupLineInterpolated($"Set TV host to: [bold yellow]{userIp}[/]");

        List<SdbTcpDevice> devices = await AnsiConsole.Status().StartAsync("Scanning network for Tizen TVs...",
            async ctx =>
            {
                List<SdbTcpDevice> rawDevices = await NetworkService.FindTizenTvsAsync();
                return rawDevices;
            });

        SdbTcpDevice selectedDevice;

        if (devices.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No Tizen TVs found on the network.[/]");

            bool isManualIp = AnsiConsole.Prompt(
                new TextPrompt<bool>("Would you like to enter a manual IP?: ")
                    .AddChoice(true)
                    .AddChoice(false)
                    .DefaultValue(true)
                    .WithConverter(choice => choice ? "y" : "n"));

            if (!isManualIp)
            {
                AnsiConsole.MarkupLine("[red]No devices to operate on. Exiting.[/]");
                return;
            }

            string manualIp = AnsiConsole.Prompt(new TextPrompt<string>("Enter your manual IP: "));

            if (string.IsNullOrEmpty(manualIp))
            {
                AnsiConsole.MarkupLine("[red]No IP provided. Exiting.[/]");
                return;
            }

            SdbTcpDevice? validated = await NetworkService.ValidateManualTizenAddress(manualIp.Trim());

            if (validated == null)
            {
                AnsiConsole.MarkupLine("[red]Manual IP did not validate. Exiting.[/]");
                return;
            }

            selectedDevice = validated;
        }
        else
        {
            selectedDevice = AnsiConsole.Prompt(
                new SelectionPrompt<SdbTcpDevice>()
                    .Title("Select a TV :")
                    .AddChoices(devices)
                    .UseConverter(s => $"{ParseDeviceId(s.DeviceId)} - {s.IpAddress.ToString()}")
            );

            // disconnect unsued devices
            foreach (SdbTcpDevice device in devices.Where(device => selectedDevice != device))
            {
                _ = device.DisconnectAsync();
            }
        }

        AnsiConsole.MarkupLine(
            $"Using device: [green]{ParseDeviceId(selectedDevice.DeviceId)} - {selectedDevice.IpAddress.ToString()}[/]");
        AnsiConsole.MarkupLine($"[bold]Select a .wgt file to install[/]");

        string? appPath = FilePicker.PickFile(allowedExtensions: [".wgt"]);

        if (appPath == null)
        {
            AnsiConsole.MarkupLine("[bold green]No file selected[/]");
            return;
        }

        AnsiConsole.MarkupLineInterpolated($"File selected: [bold green]{appPath}[/]");

        TizenInstaller installer = new(appPath, selectedDevice);

        bool isAppAlreadyInstalled = await installer.IsAppAlreadyInstalled();

        if (isAppAlreadyInstalled)
        {
            bool uninstallApp = AnsiConsole.Prompt(
                new TextPrompt<bool>(
                        "Another version of this app is already installed. Would you like to uninstall it first?: ")
                    .AddChoice(true)
                    .AddChoice(false)
                    .DefaultValue(true)
                    .WithConverter(choice => choice ? "y" : "n"));

            if (uninstallApp)
            {
                await AnsiConsole.Progress()
                    .AutoClear(false)
                    .StartAsync(async ctx =>
                    {
                        ProgressTask task = ctx.AddTask("[green]Uninstalling[/]", maxValue: 100);
                        Progress<double> progress = new Progress<double>(p => task.Value = p);
                        await installer.UninstallApp(progress);

                        // ensure completion
                        task.Value = 100;
                    });
            }
        }

        await installer.SignPackageIfNecessary();

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new RemainingTimeColumn(),
                new SpinnerColumn(),
            })
            .StartAsync(async ctx =>
            {
                ProgressTask uploadTask = ctx.AddTask("[green]Uploading[/]", maxValue: 100);
                ProgressTask installTask = ctx.AddTask("[cyan]Installing[/]", maxValue: 100);

                // Progress adapters
                Progress<double> uploadProgress = new Progress<double>(p => uploadTask.Value = p);
                Progress<double> installProgress = new Progress<double>(p => installTask.Value = p);

                try
                {
                    await installer.InstallApp(uploadProgress, installProgress);
                    // ensure full completion
                    uploadTask.Value = 100;
                    installTask.Value = 100;
                }
                catch (OperationCanceledException)
                {
                    AnsiConsole.MarkupLine("[red]Operation canceled[/]");
                    throw;
                }
                catch (Exception ex)
                {
                    AnsiConsole.MarkupLine($"[red]Install failed: {ex.Message}[/]");
                    throw;
                }
            });

        AnsiConsole.MarkupLine("[bold green]✔ App installed successfully![/]");
        
        AnsiConsole.MarkupLine("[grey]Press any key to exit...[/]");
        Console.ReadKey();
    }

    private static string ParseDeviceId(string deviceId)
    {
        return deviceId.Split("::")[1];
    }
}