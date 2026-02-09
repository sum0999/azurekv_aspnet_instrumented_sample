using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;

/// <summary>
/// Wraps a TokenCredential and logs every token acquisition with:
///   - timing, thread, scopes
///   - token hash (for correlating with pipeline requests without logging the secret)
///   - expiration tracking to detect expired-token scenarios
///   - explicit warnings when the token is empty or already expired
/// </summary>
public sealed class LoggingTokenCredential : TokenCredential
{
    private readonly TokenCredential _inner;
    private DateTimeOffset? _lastExpiresOn;  // track previous expiry
    private long _callCount;

    public LoggingTokenCredential(TokenCredential inner)
    {
        _inner = inner;
    }

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        long seq = Interlocked.Increment(ref _callCount);
        var sw = Stopwatch.StartNew();
        try
        {
            var token = _inner.GetToken(requestContext, cancellationToken);
            sw.Stop();
            LogToken("sync", seq, sw.Elapsed, token, requestContext, exception: null);
            return token;
        }
        catch (Exception ex)
        {
            sw.Stop();
            LogToken("sync", seq, sw.Elapsed, default, requestContext, exception: ex);
            throw;
        }
    }

    public override async ValueTask<AccessToken> GetTokenAsync(
        TokenRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        long seq = Interlocked.Increment(ref _callCount);
        var sw = Stopwatch.StartNew();
        try
        {
            var token = await _inner.GetTokenAsync(requestContext, cancellationToken);
            sw.Stop();
            LogToken("async", seq, sw.Elapsed, token, requestContext, exception: null);
            return token;
        }
        catch (Exception ex)
        {
            sw.Stop();
            LogToken("async", seq, sw.Elapsed, default, requestContext, exception: ex);
            throw;
        }
    }

    private void LogToken(string mode, long seq, TimeSpan elapsed, AccessToken token,
                           TokenRequestContext ctx, Exception? exception)
    {
        Console.WriteLine();
        Console.WriteLine($"=== TOKEN-DIAG [#{seq}] AccessToken {(exception == null ? "acquired" : "FAILED")} ===");
        Console.WriteLine($"    Mode:     {mode}");
        Console.WriteLine($"    Thread:   {Environment.CurrentManagedThreadId}");
        Console.WriteLine($"    Time:     {DateTimeOffset.UtcNow:o}");
        Console.WriteLine($"    Elapsed:  {elapsed.TotalMilliseconds:F1} ms");
        Console.WriteLine($"    Scopes:   {string.Join(", ", ctx.Scopes)}");

        if (exception != null)
        {
            Console.WriteLine($"    *** EXCEPTION: {exception.GetType().Name}: {exception.Message} ***");
            Console.WriteLine($"=== END TOKEN-DIAG [#{seq}] ===");
            Console.WriteLine();
            return;
        }

        int tokenLen = token.Token?.Length ?? 0;
        Console.WriteLine($"    Token length:  {tokenLen}");
        Console.WriteLine($"    ExpiresOn:     {token.ExpiresOn:o}");

        // Compute a short hash of the token for correlation with pipeline logs
        if (!string.IsNullOrEmpty(token.Token))
        {
            string hash = ComputeTokenHash(token.Token);
            Console.WriteLine($"    Token SHA256:  {hash}  (first 12 chars for correlation)");
        }

        // Warn if token is empty
        if (string.IsNullOrWhiteSpace(token.Token))
        {
            Console.WriteLine($"    *** WARNING: Token is EMPTY or WHITESPACE — requests will lack Authorization ***");
        }

        // Warn if the token is already expired at acquisition time
        if (token.ExpiresOn <= DateTimeOffset.UtcNow)
        {
            Console.WriteLine($"    *** WARNING: Token is ALREADY EXPIRED at acquisition time ***");
        }

        // Track whether the new token has a different expiry than the last one
        if (_lastExpiresOn.HasValue)
        {
            if (token.ExpiresOn == _lastExpiresOn.Value)
                Console.WriteLine($"    Note: Same expiry as previous token — possibly cached/reused.");
            else
                Console.WriteLine($"    Note: New expiry differs from previous ({_lastExpiresOn.Value:o}) — fresh token issued.");
        }
        _lastExpiresOn = token.ExpiresOn;

        Console.WriteLine($"=== END TOKEN-DIAG [#{seq}] ===");
        Console.WriteLine();
    }

    private static string ComputeTokenHash(string token)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(bytes).Substring(0, 12);
    }
}