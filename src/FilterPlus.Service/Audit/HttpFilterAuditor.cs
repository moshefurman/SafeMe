using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using FilterPlus.Core.Models;
using FilterPlus.Core.Policy;

namespace FilterPlus.Service.Audit;

/// <summary>
/// מבצע את בדיקות הסינון בפועל: תוכן חסום, נגישות לפלטפורמות AI, וטשטוש תמונות.
///
/// כל כתובות הבדיקה מגיעות מהשרת ומצביעות על דומיינים ניטרליים בשליטתו.
/// הסוכן אינו ניגש לתוכן פוגעני, אלא רק לעמודי בדיקה מסומנים.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HttpFilterAuditor
{
    private readonly ILogger<HttpFilterAuditor> _log;
    private readonly IHttpClientFactory _httpFactory;

    public HttpFilterAuditor(ILogger<HttpFilterAuditor> log, IHttpClientFactory httpFactory)
    {
        _log = log;
        _httpFactory = httpFactory;
    }

    // ------------------------------------------------------------ בדיקות תוכן

    public async Task<List<ProbeResult>> RunContentProbesAsync(PolicyBundle policy, CancellationToken ct)
    {
        var results = new List<ProbeResult>();

        // הרצה מקבילית מוגבלת: מספיק מהר, בלי להיראות כסריקה אגרסיבית
        using var throttle = new SemaphoreSlim(4);

        var tasks = policy.ContentProbes.Select(async rule =>
        {
            await throttle.WaitAsync(ct);

            try
            {
                return await RunContentProbeAsync(rule, ct);
            }
            finally
            {
                throttle.Release();
            }
        });

        results.AddRange(await Task.WhenAll(tasks));

        return results;
    }

    private async Task<ProbeResult> RunContentProbeAsync(ContentProbeRule rule, CancellationToken ct)
    {
        var stopwatch = Stopwatch.StartNew();
        var blocked = false;
        var evidence = new Dictionary<string, string>();

        try
        {
            var client = _httpFactory.CreateClient("probe-noredirect");

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(rule.TimeoutMs);

            using var request = new HttpRequestMessage(new HttpMethod(rule.Method), rule.Url);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);

            evidence["status"] = ((int)response.StatusCode).ToString();

            if (rule.BlockedIf.StatusIn.Contains((int)response.StatusCode))
                blocked = true;

            if (response.Headers.Location is { } location)
            {
                evidence["redirect"] = location.ToString();

                var host = location.IsAbsoluteUri ? location.Host : "";

                if (rule.BlockedIf.RedirectHostIn.Any(h => Wildcard.IsMatch(host, h)))
                    blocked = true;
            }

            if (!blocked && rule.BlockedIf.BodyContains.Count > 0)
            {
                var body = await ReadLimitedAsync(response, 64 * 1024, cts.Token);

                if (rule.BlockedIf.BodyContains.Any(marker =>
                        body.Contains(marker, StringComparison.OrdinalIgnoreCase)))
                {
                    blocked = true;
                    evidence["bodyMarker"] = "true";
                }
            }
        }
        catch (HttpRequestException ex) when (IsDnsFailure(ex))
        {
            // סינון ברמת DNS הוא דפוס נפוץ מאוד אצל ספקי סינון
            evidence["error"] = "dns";
            blocked = rule.BlockedIf.DnsFailureCountsAsBlocked;
        }
        catch (HttpRequestException ex) when (ex.InnerException is AuthenticationException)
        {
            // החלפת תעודה על ידי הסינון מייצרת כשל אימות TLS
            evidence["error"] = "tls";
            blocked = rule.BlockedIf.TlsFailureCountsAsBlocked;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            evidence["error"] = "timeout";

            // פסק זמן אינו ראיה מספקת לכאן או לכאן
            return Inconclusive(rule, stopwatch, evidence, "פסק זמן בבדיקה.");
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "בדיקת תוכן {Id} נכשלה באופן לא צפוי.", rule.Id);
            evidence["error"] = ex.GetType().Name;

            return Inconclusive(rule, stopwatch, evidence, "הבדיקה לא הסתיימה.");
        }

        stopwatch.Stop();

        var expectedBlocked = rule.Expect == ProbeExpectation.Blocked;
        var passed = blocked == expectedBlocked;

        var title = string.IsNullOrWhiteSpace(rule.Title) ? $"קטגוריה: {rule.Category}" : rule.Title;

        var result = passed
            ? ProbeResult.Pass(rule.Id, "ContentHttp", rule.Weight,
                expectedBlocked ? "התוכן נחסם כמצופה." : "התוכן נגיש כמצופה.")
            : ProbeResult.Fail(rule.Id, "ContentHttp", rule.Weight, rule.Severity,
                expectedBlocked ? "התוכן אינו חסום." : "התוכן חסום למרות שאמור להיות נגיש.");

        result.Title = title;
        result.DurationMs = stopwatch.ElapsedMilliseconds;

        foreach (var (k, v) in evidence) result.Evidence[k] = v;

        return result;
    }

    // ------------------------------------------------------ בדיקות פלטפורמות AI

    /// <summary>
    /// בודק נגישות לפלטפורמות AI ברמת TCP ו-TLS Handshake בלבד.
    /// אין שליחת בקשה ואין קריאת תוכן; די בכך כדי לדעת אם הסינון חוסם.
    /// </summary>
    public async Task<List<ProbeResult>> RunAiProbesAsync(PolicyBundle policy, CancellationToken ct)
    {
        var results = new List<ProbeResult>();

        foreach (var rule in policy.AiProbes)
        {
            var stopwatch = Stopwatch.StartNew();
            var reachable = await IsReachableAsync(rule.Host, rule.Port, rule.TimeoutMs, ct);

            stopwatch.Stop();

            var expectedBlocked = rule.Expect == ProbeExpectation.Blocked;
            var passed = expectedBlocked ? !reachable : reachable;

            var title = string.IsNullOrWhiteSpace(rule.Title) ? rule.Host : rule.Title;

            var result = passed
                ? ProbeResult.Pass(rule.Id, "AiAccess", rule.Weight,
                    expectedBlocked ? $"{title} חסום כמצופה." : $"{title} נגיש כמצופה.")
                : ProbeResult.Fail(rule.Id, "AiAccess", rule.Weight, rule.Severity,
                    expectedBlocked ? $"{title} נגיש למרות שאמור להיות חסום." : $"{title} אינו נגיש.");

            result.Title = title;
            result.DurationMs = stopwatch.ElapsedMilliseconds;
            result.Evidence["reachable"] = reachable.ToString();

            results.Add(result);
        }

        return results;
    }

    private async Task<bool> IsReachableAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);

            using var tcp = new TcpClient();
            await tcp.ConnectAsync(host, port, cts.Token);

            if (port != 443) return true;

            // לחיצת יד TLS מלאה: סינון רבים מקבלים את חיבור ה-TCP ורק אז חוסמים
            await using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true);

            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host
            }, cts.Token);

            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    // ------------------------------------------------------ בדיקת טשטוש תמונות

    /// <summary>
    /// מוריד תמונת ייחוס ומשווה את ה-hash שלה למקור.
    /// שינוי משמעו שהסינון ביצע טרנספורמציה, כלומר טשטוש פעיל.
    /// </summary>
    public async Task<List<ProbeResult>> RunImageProbesAsync(PolicyBundle policy, CancellationToken ct)
    {
        var results = new List<ProbeResult>();

        foreach (var rule in policy.ImageProbes)
        {
            var stopwatch = Stopwatch.StartNew();

            try
            {
                var client = _httpFactory.CreateClient("probe");

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(rule.TimeoutMs);

                var bytes = await client.GetByteArrayAsync(rule.Url, cts.Token);
                var hash = Convert.ToHexString(SHA256.HashData(bytes));

                stopwatch.Stop();

                var transformed = !string.Equals(hash, rule.OriginalSha256, StringComparison.OrdinalIgnoreCase);
                var passed = transformed == rule.ExpectTransformed;

                var title = string.IsNullOrWhiteSpace(rule.Title) ? "טשטוש תמונות" : rule.Title;

                var result = passed
                    ? ProbeResult.Pass(rule.Id, "ImageBlur", rule.Weight,
                        transformed ? "התמונה עברה עיבוד על ידי הסינון." : "התמונה הוגשה ללא שינוי, כמצופה.")
                    : ProbeResult.Fail(rule.Id, "ImageBlur", rule.Weight, rule.Severity,
                        rule.ExpectTransformed ? "התמונה לא טושטשה." : "התמונה שונתה למרות שלא אמורה.");

                result.Title = title;
                result.DurationMs = stopwatch.ElapsedMilliseconds;
                result.Evidence["sha256"] = hash;
                result.Evidence["sizeBytes"] = bytes.Length.ToString();

                results.Add(result);
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "בדיקת תמונה {Id} נכשלה.", rule.Id);
                results.Add(ProbeResult.Inconclusive(rule.Id, "ImageBlur", "הורדת התמונה נכשלה."));
            }
        }

        return results;
    }

    // ------------------------------------------------------------ עזר

    private static ProbeResult Inconclusive(
        ContentProbeRule rule, Stopwatch stopwatch, Dictionary<string, string> evidence, string detail)
    {
        stopwatch.Stop();

        var result = ProbeResult.Inconclusive(rule.Id, "ContentHttp", detail);
        result.Title = string.IsNullOrWhiteSpace(rule.Title) ? rule.Category : rule.Title;
        result.DurationMs = stopwatch.ElapsedMilliseconds;

        foreach (var (k, v) in evidence) result.Evidence[k] = v;

        return result;
    }

    private static bool IsDnsFailure(HttpRequestException ex) =>
        ex.InnerException is SocketException
        {
            SocketErrorCode: SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain
        };

    private static async Task<string> ReadLimitedAsync(HttpResponseMessage response, int maxBytes, CancellationToken ct)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(ct);

        var buffer = new byte[maxBytes];
        var read = 0;

        while (read < maxBytes)
        {
            var chunk = await stream.ReadAsync(buffer.AsMemory(read, maxBytes - read), ct);

            if (chunk == 0) break;
            read += chunk;
        }

        return System.Text.Encoding.UTF8.GetString(buffer, 0, read);
    }
}
