// https://github.com/PatrickSt1991/Samsung-Jellyfin-Installer/blob/master/Services/SamsungLoginService.cs

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Spectre.Console;

namespace TizenAppInstallerCli.SigningManager;

public class SamsungLoginService
{
    private IWebHost? _callbackServer;
    private string? _callbackUrl;
    private readonly string _stateValue = "accountcheckdogeneratedstatetext";

    public Action<SamsungAuth>? CallbackReceived;

    public static async Task<SamsungAuth?> PerformSamsungLoginAsync()
    {
        var service = new SamsungLoginService();
        return await service.PerformLoginAsync();
    }

    private async Task<SamsungAuth?> PerformLoginAsync()
    {
        // Use the registered callback port to match the provider's redirect settings.
        int port = 4794;
        _callbackUrl = $"http://localhost:{port}/signin/callback";

        string loginUrl =
            $"https://account.samsung.com/accounts/be1dce529476c1a6d407c4c7578c31bd/signInGate?locale=&clientId=v285zxnl3h&redirect_uri={WebUtility.UrlEncode(_callbackUrl)}&state={_stateValue}&tokenType=TOKEN";

        var tcs = new TaskCompletionSource<SamsungAuth?>();

        CallbackReceived = (auth) => { tcs.TrySetResult(auth); };

        AnsiConsole.MarkupLine("[yellow]Authentication required to sign the app with Samsung certificates.[/]");
        bool open = AnsiConsole.Prompt(
            new TextPrompt<bool>("Open a browser to sign in now? (y/n)")
                .AddChoice(true)
                .AddChoice(false)
                .DefaultValue(true)
                .WithConverter(c => c ? "y" : "n"));

        if (!open)
            return null;

        AnsiConsole.MarkupLine(
            "[grey]Opening browser... you will be prompted to authenticate. If a page doesn't open, paste this URL in your browser:[/]");
        AnsiConsole.MarkupLine($"[blue underline]{loginUrl}[/]");

        try
        {
            await StartCallbackServer(port);
        }
        catch (Exception ex)
        {
            throw new Exception(
                $"Failed to start local callback server on port {port}. Ensure no other process is listening on that port and you have permission to bind to localhost:{port}. Original error: {ex.Message}");
        }

        // Open system browser
        try
        {
            Process.Start(new ProcessStartInfo { FileName = loginUrl, UseShellExecute = true });
        }
        catch
        {
            AnsiConsole.MarkupLine($"[red]Failed to open browser automatically[/]");
            // ignore - user can copy/paste URL
        }

        var completed = await Task.WhenAny(tcs.Task, Task.Delay(TimeSpan.FromMinutes(5)));

        await StopCallbackServer();

        if (completed == tcs.Task && tcs.Task.Result != null)
        {
            Debug.WriteLine(tcs.Task.Result);
            return tcs.Task.Result;
        }

        throw new Exception("Samsung login timed out or failed.");
    }

    private async Task StartCallbackServer(int port)
    {
        _callbackServer = new WebHostBuilder()
            .UseKestrel()
            .UseUrls($"http://localhost:{port}")
            .Configure(app =>
            {
                app.Run(async context =>
                {
                    if (context.Request.Path == "/signin/callback")
                    {
                        // Accept GET (query) or POST (form with code)
                        string? state = null;
                        string? codeJson = null;

                        if (string.Equals(context.Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
                        {
                            state = context.Request.Query["state"];
                            codeJson = context.Request.Query["code"];
                        }
                        else if (string.Equals(context.Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                var form = await context.Request.ReadFormAsync();
                                state = form["state"];
                                codeJson = form["code"];
                            }
                            catch
                            {
                            }
                        }

                        if (!string.IsNullOrEmpty(codeJson))
                        {
                            try
                            {
                                var auth = JsonSerializer.Deserialize<SamsungAuth>(codeJson,
                                    SamsungAuthJsonContext.Default.SamsungAuth);
                                if (auth != null)
                                {
                                    auth.State = state; // set state if present
                                    CallbackReceived?.Invoke(auth);

                                    context.Response.StatusCode = (int)HttpStatusCode.OK;
                                    context.Response.ContentType = "text/html; charset=utf-8";
                                    await context.Response.WriteAsync(
                                        "<html><body><h2>Login successful</h2><p>You may now return to the application.</p></body></html>");
                                    return;
                                }
                            }
                            catch (Exception ex)
                            {
                                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                                await context.Response.WriteAsync($"[CallbackServer] JSON parse error: {ex.Message}");
                                return;
                            }
                        }

                        context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                        await context.Response.WriteAsync("Invalid login response.");
                    }
                    else
                    {
                        context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                        await context.Response.WriteAsync("Not Found");
                    }
                });
            })
            .Build();

        await _callbackServer.StartAsync();
    }

    private async Task StopCallbackServer()
    {
        if (_callbackServer != null)
        {
            await _callbackServer.StopAsync();
            _callbackServer.Dispose();
            _callbackServer = null;
        }
    }
}

public class SamsungAuth
{
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; set; }

    [JsonPropertyName("token_type")]
    public required string TokenType { get; set; }

    [JsonPropertyName("access_token_expires_in")]
    public string? AccessTokenExpiresIn { get; set; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("refresh_token_expires_in")]
    public string? RefreshTokenExpiresIn { get; set; }

    [JsonPropertyName("userId")]
    public required string UserId { get; set; }

    [JsonPropertyName("client_id")]
    public string? ClientId { get; set; }

    [JsonPropertyName("inputEmailID")]
    public string? InputEmailID { get; set; }

    [JsonPropertyName("api_server_url")]
    public string? ApiServerUrl { get; set; }

    [JsonPropertyName("auth_server_url")]
    public string? AuthServerUrl { get; set; }

    [JsonPropertyName("close")]
    public bool Close { get; set; }

    [JsonPropertyName("closedAction")]
    public string? ClosedAction { get; set; }

    [JsonPropertyName("state")]
    public string? State { get; set; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(SamsungAuth))]
internal partial class SamsungAuthJsonContext : JsonSerializerContext
{
}