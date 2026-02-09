using System;
using System.Linq;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Core.Pipeline;

/// <summary>
/// Custom pipeline policy that logs whether each outgoing Key Vault request
/// carries an Authorization header, and captures the 401-challenge flow.
///
/// The Azure SDK for Key Vault uses a "bearer token challenge" pattern:
///   1st request  → sent WITHOUT Authorization to discover auth parameters
///   Key Vault    → replies 401 + WWW-Authenticate header
///   2nd request  → sent WITH Authorization (Bearer token)
///
/// This policy makes that flow visible so you can distinguish the expected
/// initial challenge from unexpected missing-auth scenarios.
/// </summary>
public sealed class AuthDiagnosticsPolicy : HttpPipelinePolicy
{
    private static long _requestCounter;

    public override void Process(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline)
    {
        long seq = System.Threading.Interlocked.Increment(ref _requestCounter);
        LogRequest(seq, message);
        ProcessNext(message, pipeline);
        LogResponse(seq, message);
    }

    public override async ValueTask ProcessAsync(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline)
    {
        long seq = System.Threading.Interlocked.Increment(ref _requestCounter);
        LogRequest(seq, message);
        await ProcessNextAsync(message, pipeline);
        LogResponse(seq, message);
    }

    // -----------------------------------------------------------------------
    private static void LogRequest(long seq, HttpMessage message)
    {
        var req = message.Request;
        bool hasAuth = req.Headers.TryGetValue("Authorization", out string? authValue);
        string method = req.Method.Method;
        string url = req.Uri.ToString();
        string threadInfo = $"Thread={Environment.CurrentManagedThreadId}";

        Console.WriteLine();
        Console.WriteLine($">>> AUTH-DIAG [Req #{seq}] {method} {url}");
        Console.WriteLine($"    {threadInfo} | Time={DateTimeOffset.UtcNow:o}");

        if (hasAuth)
        {
            // Show first 10 chars of the token for correlation, not the full value
            string tokenSnippet = authValue != null && authValue.Length > 17
                ? authValue.Substring(0, 17) + "..."
                : authValue ?? "(null)";
            Console.WriteLine($"    Authorization header PRESENT: {tokenSnippet}");
        }
        else
        {
            Console.WriteLine($"    *** Authorization header MISSING ***");
            Console.WriteLine($"    (This is EXPECTED for the initial bearer-token challenge request)");
        }
    }

    private static void LogResponse(long seq, HttpMessage message)
    {
        var resp = message.Response;
        int status = resp.Status;
        string reason = resp.ReasonPhrase;

        Console.WriteLine($"<<< AUTH-DIAG [Req #{seq}] Response: {status} {reason}");

        if (status == 401)
        {
            // Log WWW-Authenticate header — this is the challenge
            if (resp.Headers.TryGetValue("WWW-Authenticate", out string? wwwAuth))
            {
                Console.WriteLine($"    WWW-Authenticate: {wwwAuth}");
                Console.WriteLine($"    → This is the expected challenge response. The SDK should now acquire a token and retry.");
            }
            else
            {
                Console.WriteLine($"    *** 401 received WITHOUT WWW-Authenticate header — unexpected! ***");
            }
        }
        else if (status == 200)
        {
            Console.WriteLine($"    → Request succeeded.");
        }
        else if (status == 403)
        {
            Console.WriteLine($"    *** 403 Forbidden — the token was sent but access was denied. Check RBAC / access policy. ***");
        }
        else if (status == 429)
        {
            if (resp.Headers.TryGetValue("Retry-After", out string? retryAfter))
            {
                Console.WriteLine($"    429 Throttled — Retry-After: {retryAfter}");
            }
        }

        Console.WriteLine();
    }
}
