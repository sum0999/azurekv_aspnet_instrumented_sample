using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;

/// <summary>
/// Wraps a TokenCredential to track every call the SDK's auth policy makes.
/// The key diagnostic: if a wire request goes out without Authorization and
/// GetTokenAsync was NOT called since the last wire request, the auth policy
/// decided to skip token acquisition entirely (challenge state lost, internal
/// error swallowed, etc.).
/// </summary>
public sealed class LoggingTokenCredential : TokenCredential
{
    private readonly TokenCredential _inner;

    // ── Shared counters read by WireLoggingHandler ───────────────────────
    // Monotonic call counter — incremented on every GetToken/GetTokenAsync call.
    // WireLoggingHandler snapshots this before/after to detect "no call made".
    public static long CallCounter;

    public static DateTimeOffset? LastExpiresOn;
    public static DateTimeOffset? LastAcquiredUtc;
    public static string?         LastError;
    public static int             FailureCount;

    public LoggingTokenCredential(TokenCredential inner) => _inner = inner;

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref CallCounter);
        var sw = Stopwatch.StartNew();
        try
        {
            var token = _inner.GetToken(requestContext, cancellationToken);
            sw.Stop();
            OnSuccess(sw.Elapsed, token);
            return token;
        }
        catch (Exception ex)
        {
            sw.Stop();
            OnFailure(sw.Elapsed, ex);
            throw;
        }
    }

    public override async ValueTask<AccessToken> GetTokenAsync(
        TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref CallCounter);
        var sw = Stopwatch.StartNew();
        try
        {
            var token = await _inner.GetTokenAsync(requestContext, cancellationToken);
            sw.Stop();
            OnSuccess(sw.Elapsed, token);
            return token;
        }
        catch (Exception ex)
        {
            sw.Stop();
            OnFailure(sw.Elapsed, ex);
            throw;
        }
    }

    private static void OnSuccess(TimeSpan elapsed, AccessToken token)
    {
        LastAcquiredUtc = DateTimeOffset.UtcNow;
        LastExpiresOn   = token.ExpiresOn;
        LastError       = null;

        if (string.IsNullOrWhiteSpace(token.Token))
            Console.WriteLine($"[TOKEN] WARNING: Token is EMPTY  (elapsed {elapsed.TotalMilliseconds:F0}ms)");
        else if (token.ExpiresOn <= DateTimeOffset.UtcNow)
            Console.WriteLine($"[TOKEN] WARNING: Token already EXPIRED  expiresOn={token.ExpiresOn:o}  (elapsed {elapsed.TotalMilliseconds:F0}ms)");
        else
            Console.WriteLine($"[TOKEN] OK  expiresOn={token.ExpiresOn:o}  (elapsed {elapsed.TotalMilliseconds:F0}ms)");
    }

    private static void OnFailure(TimeSpan elapsed, Exception ex)
    {
        Interlocked.Increment(ref FailureCount);
        LastError = $"{ex.GetType().Name}: {ex.Message}";
        Console.WriteLine($"[TOKEN] FAILED  {ex.GetType().Name}: {ex.Message}  (elapsed {elapsed.TotalMilliseconds:F0}ms)");
    }
}