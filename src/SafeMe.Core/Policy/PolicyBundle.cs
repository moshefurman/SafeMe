using System.Text.Json.Serialization;
using SafeMe.Core.Models;

namespace SafeMe.Core.Policy;

/// <summary>
/// חבילת המדיניות הדינמית שמגיעה מהשרת. כל התוכן חתום ב-RSA-PSS ומאומת לפני יישום.
/// </summary>
public sealed class PolicyBundle
{
    public int Version { get; set; }
    public DateTimeOffset IssuedUtc { get; set; }
    public int TtlMinutes { get; set; } = 240;
    public int GraceMinutes { get; set; } = 720;

    /// <summary>חתימת Base64 של השרת על ה-JSON הקנוני (ללא שדה זה).</summary>
    public string? Signature { get; set; }

    public List<ProviderRule> Providers { get; set; } = new();
    public List<ContentProbeRule> ContentProbes { get; set; } = new();
    public List<AiProbeRule> AiProbes { get; set; } = new();
    public List<ImageProbeRule> ImageProbes { get; set; } = new();
    public EnforcementPolicy Enforcement { get; set; } = new();

    [JsonIgnore]
    public bool IsExpired =>
        DateTimeOffset.UtcNow > IssuedUtc.AddMinutes(TtlMinutes + GraceMinutes);

    /// <summary>מדיניות ברירת מחדל מוקשחת, בשימוש כשאין עדיין מדיניות מהשרת.</summary>
    public static PolicyBundle CreateDefault() => new()
    {
        Version = 0,
        IssuedUtc = DateTimeOffset.UtcNow,
        Enforcement = new EnforcementPolicy
        {
            Mode = EnforcementMode.Monitor,
            MinScoreForGreen = 85,
            MinScoreForYellow = 60,
            OnRedAction = RedAction.Warn
        }
    };
}

public sealed class ProviderRule
{
    public required string Id { get; set; }
    public string DisplayName { get; set; } = "";
    public TrustLevel TrustLevel { get; set; } = TrustLevel.Medium;
    public RootCaRule? RootCa { get; set; }
    public NetworkIdentityRule? Network { get; set; }
    public HttpMarkerRule? HttpMarkers { get; set; }
}

public sealed class RootCaRule
{
    /// <summary>טביעות אצבע SHA-1/SHA-256 של תעודות השורש של הספק (ללא רווחים, אותיות גדולות).</summary>
    public List<string> Thumbprints { get; set; } = new();

    /// <summary>תבניות התאמה ל-Subject, תומך בכוכבית. לדוגמה: CN=NetFree*</summary>
    public List<string> SubjectPatterns { get; set; } = new();

    /// <summary>האם נוכחות התעודה היא תנאי הכרחי לזיהוי הספק.</summary>
    public bool Required { get; set; }
}

public sealed class NetworkIdentityRule
{
    public List<int> Asns { get; set; } = new();
    public List<string> Cidrs { get; set; } = new();
    public List<string> ReverseDnsPatterns { get; set; } = new();
}

public sealed class HttpMarkerRule
{
    public string? Url { get; set; }
    public Dictionary<string, string> Headers { get; set; } = new();
    public List<string> BodyContains { get; set; } = new();
}

public sealed class ContentProbeRule
{
    public required string Id { get; set; }
    public string Category { get; set; } = "General";
    public string Title { get; set; } = "";
    public required string Url { get; set; }
    public string Method { get; set; } = "GET";
    public int TimeoutMs { get; set; } = 6000;
    public ProbeExpectation Expect { get; set; } = ProbeExpectation.Blocked;
    public BlockedCriteria BlockedIf { get; set; } = new();
    public int Weight { get; set; } = 10;
    public ProbeSeverity Severity { get; set; } = ProbeSeverity.Warning;
}

public sealed class BlockedCriteria
{
    public List<int> StatusIn { get; set; } = new() { 403, 451, 302, 307 };
    public List<string> BodyContains { get; set; } = new();
    public List<string> RedirectHostIn { get; set; } = new();

    /// <summary>כשל ביישוב שם או תשובת DNS ריקה נחשבים חסימה.</summary>
    public bool DnsFailureCountsAsBlocked { get; set; } = true;

    /// <summary>כשל אימות TLS (החלפת תעודה על ידי הסינון) נחשב חסימה.</summary>
    public bool TlsFailureCountsAsBlocked { get; set; } = true;
}

public sealed class AiProbeRule
{
    public required string Id { get; set; }
    public required string Host { get; set; }
    public int Port { get; set; } = 443;
    public string Title { get; set; } = "";
    public ProbeExpectation Expect { get; set; } = ProbeExpectation.Blocked;
    public int TimeoutMs { get; set; } = 4000;
    public int Weight { get; set; } = 15;
    public ProbeSeverity Severity { get; set; } = ProbeSeverity.Warning;
}

public sealed class ImageProbeRule
{
    public required string Id { get; set; }
    public required string Url { get; set; }
    public string Title { get; set; } = "";

    /// <summary>אם true, מצפים שהתמונה תשונה (טושטשה) על ידי הסינון.</summary>
    public bool ExpectTransformed { get; set; } = true;

    /// <summary>SHA-256 של התמונה המקורית כפי שמוגשת מהשרת ללא סינון.</summary>
    public string? OriginalSha256 { get; set; }

    public int TimeoutMs { get; set; } = 8000;
    public int Weight { get; set; } = 10;
    public ProbeSeverity Severity { get; set; } = ProbeSeverity.Info;
}

public sealed class EnforcementPolicy
{
    public EnforcementMode Mode { get; set; } = EnforcementMode.Monitor;
    public int MinScoreForGreen { get; set; } = 85;
    public int MinScoreForYellow { get; set; } = 60;
    public RedAction OnRedAction { get; set; } = RedAction.Warn;

    /// <summary>זמן חסד בשניות לפני שנעילת חירום נכנסת לתוקף, לאחר התראה למשתמש.</summary>
    public int LockoutGraceSeconds { get; set; } = 120;

    public AllowedNetworks AllowedNetworks { get; set; } = new();
    public AlwaysAllow AlwaysAllow { get; set; } = new();
    public List<ScheduleRule> Schedules { get; set; } = new();

    /// <summary>
    /// מצב default-deny: מותר רק מה שדפדוף מסונן צריך.
    ///
    /// כבוי כברירת מחדל, כדי שסוכן קיים לא ישנה התנהגות ברגע
    /// שהשרת מתעדכן. ההפעלה היא החלטה מפורשת בפורטל.
    /// </summary>
    public EgressRule Egress { get; set; } = new();
}

public sealed class AllowedNetworks
{
    public List<string> WifiSsids { get; set; } = new();
    public List<string> Cidrs { get; set; } = new();

    /// <summary>רשימת מזהי ספקים שרק דרכם מותרת גלישה.</summary>
    public List<string> RequireProvider { get; set; } = new();
}

/// <summary>חורים מוגדרים בנעילת החירום. בלעדיהם המכשיר היה מתנתק לחלוטין.</summary>
public sealed class AlwaysAllow
{
    public List<string> Hosts { get; set; } = new();
    public List<string> Ips { get; set; } = new();
    public List<int> Ports { get; set; } = new() { 443 };
    public bool AllowDns { get; set; } = true;
    public bool AllowDhcp { get; set; } = true;
    public bool AllowLoopback { get; set; } = true;
}

public sealed class ScheduleRule
{
    public required string Id { get; set; }
    public List<DayOfWeek> Days { get; set; } = new();

    /// <summary>שעת התחלה בפורמט HH:mm בשעון מקומי.</summary>
    public string From { get; set; } = "00:00";

    public string To { get; set; } = "00:00";
    public string Action { get; set; } = "BlockAll";

    public bool IsActiveAt(DateTime localNow)
    {
        if (Days.Count > 0 && !Days.Contains(localNow.DayOfWeek)) return false;
        if (!TimeSpan.TryParse(From, out var from) || !TimeSpan.TryParse(To, out var to)) return false;

        var now = localNow.TimeOfDay;

        // חלון שחוצה חצות, לדוגמה 23:30 עד 05:30
        return from <= to ? now >= from && now < to : now >= from || now < to;
    }
}
