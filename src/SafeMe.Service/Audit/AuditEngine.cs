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
    private readonly TlsIssuerAuditor _tls;
    private readonly FilterLevelReader _level;
    private readonly HttpFilterAuditor _http;
    private readonly PolicyStore _policyStore;

    public AuditEngine(
        ILogger<AuditEngine> log,
        RootCaAuditor rootCa,
        NetworkIdentityAuditor network,
        TlsIssuerAuditor tls,
        FilterLevelReader level,
        HttpFilterAuditor http,
        PolicyStore policyStore)
    {
        _log = log;
        _rootCa = rootCa;
        _network = network;
        _tls = tls;
        _level = level;
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

            /*
             * רמת הסינון, אחרי שהספק כבר זוהה ורק אז.
             *
             * זיהוי שהמחשב מסונן אינו אומר כמה. הורה שהגדיר רמה
             * מחמירה ומצא אותה מוקלת לא היה יודע — וזו בדיוק צורת
             * העקיפה שקשה לתפוס: לא ניתוק הסינון, אלא החלשתו בשקט.
             *
             * הקורא בודק בעצמו שהתעודה היא של הספק לפני כל בקשה,
             * ולכן על מחשב שאינו מסונן שום בקשה אינה יוצאת.
             */
            if (matchedRule is not null && detection.ProviderId is not null)
                detection.FilterLevel = await _level.ReadAsync(matchedRule, ct);

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

        /*
         * שורה אחת שעונה על "למה הוא אומר שאינו מסונן".
         *
         * בלי הווקטורים בשמם, כל אבחון של דיווח שגוי דרש ניחוש: הלוג
         * אמר "לא זוהה ספק" או "זוהה", ולא היה שום רמז מה נבדק ומה
         * ענה. זה עלה כמה סבבים שלמים.
         */
        var vectors = report.Detection.MatchedVectors;

        _log.LogInformation(
            "הביקורת הסתיימה תוך {Ms}ms. ציון {Score}, סטטוס {Status}, כשלים {Failures}. "
            + "ספק: {Provider} (ביטחון {Trust}), ווקטורים שהתאימו: {Vectors}.",
            stopwatch.ElapsedMilliseconds, report.Score, report.Status, report.Failures.Count(),
            report.Detection.DisplayName ?? report.Detection.ProviderId ?? "לא זוהה",
            report.Detection.Trust,
            vectors.Count > 0 ? string.Join(", ", vectors) : "אף אחד");

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

        // האם לפחות חיבור אחד החזיר תעודה. ראה DetectionRan.
        var sawAnyIssuer = false;

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

            /*
             * מנפיק התעודה. הווקטור היחיד שנמדד על החיבור עצמו,
             * ולכן היחיד שעובד כשהספק מסנן דרך פרוקסי בלי להתקין
             * דבר במחשב ובלי טווח כתובות ייעודי.
             *
             * הוא רץ גם בלי סימן מוקדם, בניגוד לבדיקת הכותרות: הוא
             * לעיתים קרובות הראיה **היחידה** שקיימת.
             */
            var tls = await _tls.MatchesAsync(provider, ct);

            detection.TlsIssuerMatch = tls.Matched;
            detection.ObservedIssuer = tls.Issuer;

            if (tls.Issuer is not null) sawAnyIssuer = true;

            /*
             * בדיקת הכותרות היא בקשת רשת, ולכן היא רצה רק כשיש סיבה
             * לחשוד בספק הזה — ותעודת שורש מותקנת היא סיבה מצוינת.
             *
             * כאן, ורק כאן, התעודה עדיין שווה משהו: היא מכוונת בדיקה
             * חיה שאולי תמצא ראיה אמיתית. אם לא תמצא, לא נותר ממנה
             * דבר.
             */
            if (detection.HasAnySignal)
                detection.HttpMarkerMatch = await _network.CheckHttpMarkersAsync(provider, ct);

            detection.Trust = ScoreCalculator.ResolveTrust(detection, provider);

            /*
             * הזיהוי נקבע לפי ווקטורים חיים בלבד.
             *
             * קודם נכללה כאן גם תעודת השורש, ומכיוון שהיא נשארת
             * מותקנת לנצח — מחשב שהתנתק מהספק לגמרי המשיך להיבחר
             * כמזוהה, וקיבל שישים אחוז מהמשקל על ראיה בת חודשיים.
             */
            if (detection.MatchCount > 0 && (best is null || detection.MatchCount > best.MatchCount))
                best = detection;
        }

        if (best is null)
        {
            /*
             * שתי סיבות שונות להגיע לכאן, ורק אחת מהן מצדיקה חסימה.
             *
             * אם לא הצלחנו להשיג כתובת ציבורית וגם מאגר התעודות לא
             * החזיר התאמה, לא בדקנו — לא מצאנו כלום כי לא היה לנו
             * במה להסתכל. זה המצב של מחשב בלי רשת, ושל מחשב שהרגע
             * עלה לפני שהחיבור התייצב.
             *
             * ההבחנה הזו חסרה קודם, ומחשב אמיתי ננעל פעמיים: הוא
             * דיווח "אינו מסונן", נחסם, ואז לא יכול היה לבדוק שוב
             * כי הבדיקה זקוקה לרשת.
             */
            var ran = publicIp is not null || rootCaMatches.Count > 0 || sawAnyIssuer;

            if (ran)
            {
                _log.LogWarning("לא זוהה אף ספק סינון מאושר.");
            }
            else
            {
                _log.LogWarning(
                    "לא ניתן היה לבדוק את זהות הספק: אין כתובת ציבורית ואין תעודה מוכרת.");
            }

            return new ProviderDetection
            {
                PublicIp = publicIp,
                ReverseDns = reverseDns,
                Trust = TrustLevel.None,
                DetectionRan = ran
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
            /*
             * ווקטור אחד הוא ראיה, לא היעדרה.
             *
             * קודם זה נספר ככישלון מלא, ומכיוון שזהו לרוב הגשש היחיד
             * שרץ — מדיניות הבסיס אינה מגדירה גששי תוכן — הציון יצא 0
             * והמחשב דיווח "אינו מסונן" דווקא על סמך זיהוי מוצלח של
             * הספק. מחשב מסונן שזוהה בווקטור אחד הופיע בפורטל כמחשב
             * חשוף.
             *
             * שישים אחוז מהמשקל: די כדי לעבור את סף הצהוב לבדו, ולא
             * די כדי להיחשב ירוק. זה בדיוק מה שהמצב הזה אומר —
             * סינון שקיים אך לא הוכח כנדרש.
             */
            var partial = ProbeResult.Partial(
                "provider-identity", "ProviderIdentity", weight, weight * 3 / 5, ProbeSeverity.Warning,
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
