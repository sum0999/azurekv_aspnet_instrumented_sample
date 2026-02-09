using System.Diagnostics.Tracing;
using System.Net.Http;
using System.Text.RegularExpressions;
using Azure.Core.Diagnostics;
using Azure.Core.Pipeline;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// Azure SDK verbose event-source listener (writes to stdout / console)
// ---------------------------------------------------------------------------
using AzureEventSourceListener listener = new AzureEventSourceListener(
    (args, message) => Console.WriteLine($"[{args.Level}] {ScrubSensitiveHeaders(message)}"),
    level: EventLevel.Verbose);

// ---------------------------------------------------------------------------
// Read configuration
// ---------------------------------------------------------------------------
var config = builder.Configuration;

string tenantId     = config["KeyVault:TenantId"]     ?? throw new InvalidOperationException("KeyVault:TenantId is missing");
string clientId     = config["KeyVault:ClientId"]      ?? throw new InvalidOperationException("KeyVault:ClientId is missing");
string clientSecret = config["KeyVault:ClientSecret"]  ?? throw new InvalidOperationException("KeyVault:ClientSecret is missing");
string vaultUrl     = config["KeyVault:VaultUrl"]      ?? throw new InvalidOperationException("KeyVault:VaultUrl is missing");

// ---------------------------------------------------------------------------
// Build credential + SecretClient with full diagnostics
// ---------------------------------------------------------------------------
var baseCredential = new ClientSecretCredential(
    tenantId,
    clientId,
    clientSecret,
    new TokenCredentialOptions
    {
        Diagnostics =
        {
            IsLoggingEnabled                  = true,
            IsAccountIdentifierLoggingEnabled = true,
            IsDistributedTracingEnabled       = true,
            LoggedHeaderNames                 = { "*" },
            LoggedQueryParameters             = { "*" }
        }
    });

var loggingCredential = new LoggingTokenCredential(baseCredential);

var secretClient = new SecretClient(
    new Uri(vaultUrl),
    loggingCredential,
    new SecretClientOptions
    {
        Diagnostics =
        {
            IsLoggingEnabled       = true,
            LoggedHeaderNames      = { "*" },
            LoggedQueryParameters  = { "*" }
        },
        // WireLoggingHandler sits below the SDK pipeline and sees the final
        // HTTP request — including whether Authorization was actually attached.
        Transport = new HttpClientTransport(
            new WireLoggingHandler(new HttpClientHandler()))
    });

// Register as a singleton so controllers / endpoints can use it
builder.Services.AddSingleton(secretClient);

var app = builder.Build();

app.UseHttpsRedirection();

// ---------------------------------------------------------------------------
// GET /api/secret/{name}  –  fetch a secret from Key Vault
// ---------------------------------------------------------------------------
app.MapGet("/api/secret/{name}", async (string name, SecretClient client) =>
{
    try
    {
        KeyVaultSecret secret = await client.GetSecretAsync(name);
        return Results.Ok(new
        {
            secret.Name,
            Value  = secret.Value,
            secret.Properties.CreatedOn,
            secret.Properties.UpdatedOn
        });
    }
    catch (Azure.RequestFailedException ex)
    {
        return Results.Problem(
            detail: ex.Message,
            statusCode: ex.Status);
    }
});

app.Run();

// ---------------------------------------------------------------------------
// Helper – redact Authorization header values in log messages
// ---------------------------------------------------------------------------
static string ScrubSensitiveHeaders(string message)
{
    if (string.IsNullOrEmpty(message)) return message;

    // Redact Bearer tokens in Authorization headers while indicating presence.
    // Example: "Authorization: Bearer abcdef..." -> "Authorization: Bearer abcde...(redacted)"
    return Regex.Replace(
        message,
        "(?i)(Authorization\\s*:\\s*Bearer\\s*)(\\S+)",
        match =>
        {
            var prefix = match.Groups[1].Value;
            var token = match.Groups[2].Value;
            var first = token.Length <= 5 ? token : token.Substring(0, 5);
            return $"{prefix}{first}...(redacted)";
        });
}
