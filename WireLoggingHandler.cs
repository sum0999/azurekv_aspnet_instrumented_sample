using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// DelegatingHandler at the HTTP transport level.
/// Silent on success. On auth-missing non-challenge requests, answers:
///   1. Was GetTokenAsync called at all for this request?
///   2. If yes — did it succeed? What's the token state?
///   3. If no  — the SDK's auth policy skipped token acquisition entirely.
///      This points to lost challenge state or a swallowed internal error.
/// </summary>
public sealed class WireLoggingHandler : DelegatingHandler
{
    private static bool _initialChallengeDone;
    private long _lastSeenTokenCallCounter;

    public WireLoggingHandler(HttpMessageHandler inner) : base(inner) { }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        bool hasAuth = request.Headers.Authorization != null;

        // Snapshot the token call counter BEFORE the request
        long tokenCallsBefore = Interlocked.Read(ref LoggingTokenCredential.CallCounter);

        HttpResponseMessage response;
        try
        {
            response = await base.SendAsync(request, cancellationToken);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WIRE] SEND FAILED  {request.Method} {request.RequestUri}  {ex.GetType().Name}: {ex.Message}");
            throw;
        }

        int status = (int)response.StatusCode;

        // Happy path
        if (hasAuth && status is >= 200 and < 300)
        {
            _initialChallengeDone = true;
            _lastSeenTokenCallCounter = Interlocked.Read(ref LoggingTokenCredential.CallCounter);
            Console.WriteLine($"[WIRE] OK  {request.Method} {request.RequestUri} → {status}");
            return response;
        }

        // Expected initial challenge
        if (!_initialChallengeDone && !hasAuth && status == 401)
        {
            _lastSeenTokenCallCounter = Interlocked.Read(ref LoggingTokenCredential.CallCounter);
            Console.WriteLine($"[WIRE] Initial challenge: {request.Method} {request.RequestUri} → 401 (expected)");
            return response;
        }

        // ── Auth missing on a non-first request — this is the scenario ────
        if (!hasAuth && _initialChallengeDone)
        {
            long tokenCallsAfter = Interlocked.Read(ref LoggingTokenCredential.CallCounter);
            bool tokenWasCalled  = tokenCallsAfter > _lastSeenTokenCallCounter;

            Console.WriteLine($"[WIRE] *** AUTH MISSING (non-challenge) *** {request.Method} {request.RequestUri} → {status}");
            Console.WriteLine($"[WIRE]   GetTokenAsync called for this request: {tokenWasCalled}  (counter: {_lastSeenTokenCallCounter} → {tokenCallsAfter})");

            if (!tokenWasCalled)
            {
                Console.WriteLine($"[WIRE]   >>> The SDK's auth policy did NOT call GetTokenAsync.");
                Console.WriteLine($"[WIRE]   >>> This means the ChallengeBasedAuthenticationPolicy skipped token acquisition.");
                Console.WriteLine($"[WIRE]   >>> Likely cause: challenge cache state was lost or an internal error was swallowed.");
            }
            else
            {
                // Token was requested but still not attached — credential issue
                var expiresOn = LoggingTokenCredential.LastExpiresOn;
                var lastErr   = LoggingTokenCredential.LastError;

                Console.WriteLine($"[WIRE]   >>> GetTokenAsync WAS called but auth still missing.");
                if (lastErr != null)
                    Console.WriteLine($"[WIRE]   >>> Last token error: {lastErr}");
                if (expiresOn.HasValue)
                {
                    var ttl = expiresOn.Value - DateTimeOffset.UtcNow;
                    Console.WriteLine($"[WIRE]   >>> Token expiresOn={expiresOn.Value:o}  TTL={ttl.TotalSeconds:F0}s");
                    if (ttl.TotalSeconds <= 0)
                        Console.WriteLine($"[WIRE]   >>> Token is EXPIRED");
                }
                if (LoggingTokenCredential.FailureCount > 0)
                    Console.WriteLine($"[WIRE]   >>> Total token failures: {LoggingTokenCredential.FailureCount}");
            }

            _lastSeenTokenCallCounter = tokenCallsAfter;
        }

        return response;
    }
}
