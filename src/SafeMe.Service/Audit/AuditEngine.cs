using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SafeMe.Core.Audit;
using SafeMe.Core.Models;
using SafeMe.Core.Policy;
using SafeMe.Service.State;

namespace SafeMe.Service.Audit;

/// <summary>
/// מנהל ביקורת מלאה: מזהה את הספק בארבעה וקטורים, מריץ את כל הגששים,
/// ומחשב ציון וסטטוס. זהו הרכיב שמחבר בין המדיניות מהשרת לבין תמונת המצב.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AuditEngine
{
    private readonly ILogger<AuditEngine> _log;
    private readonly RootCaAuditor _rootCa;
    private readonly NetworkIdentityAuditor _network;
    private readonly HttpFilterAuditor _http;
    private readonly PolicyStore _policyStore;

    public AuditEngine(
        ILogger<AuditEngine> log,
        RootCaAuditor rootCa,
        NetworkIdentityAuditor network,
        HttpFilterAuditor http,
        PolicyStore policyStore)
    {
        _log = log;
        _rootCa = rootCa;
        _network = network;
        _http = http;
        _policyStore = policyStore;
    }

    public async Task<AuditReport> RunAsync(bool lockoutActive, CancellationToken ct)
    {
        var policy = _policyStore.Current;
        var stopwatch = Stopwatch.StartNew();

        var report = new AuditReport
        {
            StartedUtc = DateTimeOffset.UtcNow,
            PolicyVersion = policy.Version
        };

        _log.LogInformation("מתחיל ביקורת מול מדיניות גרסה {Version}.", policy.Version);

        try
        {
            var detection = await DetectProviderAsync(policy, ct);
            report.Detection = detection;

            var matchedRule = policy.Providers.FirstOrDefault(p =>
                string.Equals(p.Id, detection.ProviderId, StringComparison.OrdinalIgnoreCase));

            // תוצאת גשש עבור תעודת השורש של הספק שזוהה
            var rootCaMatches = _rootCa.DetectProviders(policy);
            report.Results.Add(_rootCa.BuildProbeResult(matchedRule, rootCaMatches));

            // גשש זהות: האם בכלל זוהה ספק מאושר
            report.Results.Add(BuildIdentityProbe(detection, policy));

            report.Results.AddRange(await _http.RunContentProbesAsync(policy, ct));
            report.Results.AddRange(await _http.RunAiProbesAsync(policy, ct));
            report.Results.AddRange(await _http.RunImageProbesAsync(policy, ct));

            report.Score = ScoreCalculator.ComputeScore(report.Results);
            report.Status = ScoreCalculator.ResolveStatus(
                report.Score, detection, policy.Enforcement, lockoutActive);

            report.Headline = ScoreCalculator.BuildHeadline(report.Status, detection, report.Score);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "הביקורת נכשלה.");

            report.Status = SecurityStatus.Unknown;
            report.Headline = "לא ניתן היה להשלים את הבדיקה.";
        }

        stopwatch.Stop();
        report.CompletedUtc = DateTimeOffset.UtcNow;

        _log.LogInformation(
            "הביקורת הסתיימה תוך {Ms}ms. ציון {Score}, סטטוס {Status}, כשלים {Failures}.",
            stopwatch.ElapsedMilliseconds, report.Score, report.Status, report.Failures.Count());

        return report;
    }

    /// <summary>
    /// מזהה את הספק לפי ארבעת הווקטורים. הבדיקות בלתי תלויות זו בזו,
    /// ולכן זיוף של אחת מהן אינו מספיק כדי להיחשב ספק מאושר.
    /// </summary>
    private async Task<ProviderDetection> DetectProviderAsync(PolicyBundle policy, CancellationToken ct)
    {
        var publicIp = await _network.GetPublicIpAsync(ct);
        var reverseDns = await _network.GetReverseDnsAsync(publicIp, ct);
        var rootCaMatches = _rootCa.DetectProviders(policy);

        ProviderDetection? best = null;

        foreach (var provider in policy.Providers)
        {
            var detection = new ProviderDetection
            {
                ProviderId = provider.Id,
                DisplayName = provider.DisplayName,
                PublicIp = publicIp,
                ReverseDns = reverseDns
            };

            if (rootCaMatches.TryGetValue(provider.Id, out var thumbprints))
            {
                detection.RootCaMatch = true;
                detection.MatchedThumbprints.AddRange(thumbprints);
            }

            if (provider.Network is { } network)
            {
                detection.IpRangeMatch = NetworkIdentityAuditor.IsInAnyCidr(publicIp, network.Cidrs);

                detection.ReverseDnsMatch = reverseDns is not null &&
                    network.ReverseDnsPatterns.Any(p => Wildcard.IsMatch(reverseDns, p));
            }

            // בדיקת הכותרות יקרה יחסית, ולכן מבוצעת רק כשיש כבר סימן אחר לספק
            if (detection.MatchCount > 0)
                detection.HttpMarkerMatch = await _network.CheckHttpMarkersAsync(provider, ct);

            detection.Trust = ScoreCalculator.ResolveTrust(detection, provider);

            if (detection.MatchCount > 0 && (best is null || detection.MatchCount > best.MatchCount))
                best = detection;
        }

        if (best is null)
        {
            _log.LogWarning("לא זוהה אף ספק סינון מאושר.");

            return new ProviderDetection
            {
                PublicIp = publicIp,
                ReverseDns = reverseDns,
                Trust = TrustLevel.None
            };
        }

        _log.LogInformation(
            "זוהה ספק {Provider} ברמת ביטחון {Trust} ({Matches} וקטורים: CA={Ca}, DNS={Dns}, IP={Ip}, HTTP={Http}).",
            best.ProviderId, best.Trust, best.MatchCount,
            best.RootCaMatch, best.ReverseDnsMatch, best.IpRangeMatch, best.HttpMarkerMatch);

        return best;
    }

    private static ProbeResult BuildIdentityProbe(ProviderDetection detection, PolicyBundle policy)
    {
        const int weight = 25;
        var required = policy.Enforcement.AllowedNetworks.RequireProvider;

        if (detection.ProviderId is null)
        {
            var fail = ProbeResult.Fail("provider-identity", "ProviderIdentity", weight, ProbeSeverity.Critical,
                "לא זוהה ספק סינון מאושר.");

            fail.Title = "זיהוי ספק סינון";
            return fail;
        }

        if (required.Count > 0 &&
            !required.Contains(detection.ProviderId, StringComparer.OrdinalIgnoreCase))
        {
            var fail = ProbeResult.Fail("provider-identity", "ProviderIdentity", weight, ProbeSeverity.Critical,
                $"הספק {detection.DisplayName} אינו ברשימת הספקים המאושרים.");

            fail.Title = "זיהוי ספק סינון";
            return fail;
        }

        if (detection.Trust < TrustLevel.High)
        {
            var partial = ProbeResult.Fail("provider-identity", "ProviderIdentity", weight, ProbeSeverity.Warning,
                $"הספק {detection.DisplayName} זוהה בווקטור אחד בלבד, ולכן רמת הביטחון חלקית.");

            partial.Title = "זיהוי ספק סינון";
            return partial;
        }

        var pass = ProbeResult.Pass("provider-identity", "ProviderIdentity", weight,
            $"הספק {detection.DisplayName} זוהה ב-{detection.MatchCount} וקטורים בלתי תלויים.");

        pass.Title = "זיהוי ספק סינון";
        return pass;
    }
}
