namespace SafeMe.Core.Models;

/// <summary>תוצאה של גשש בודד, כולל ראיות לצורך דיווח לשרת.</summary>
public sealed class ProbeResult
{
    public required string ProbeId { get; init; }
    public required string Kind { get; init; }
    public ProbeOutcome Outcome { get; set; } = ProbeOutcome.Inconclusive;
    public ProbeSeverity Severity { get; set; } = ProbeSeverity.Info;
    public int Weight { get; set; }
    public string? Title { get; set; }
    public string? Detail { get; set; }
    public long DurationMs { get; set; }
    public Dictionary<string, string> Evidence { get; init; } = new();

    public static ProbeResult Pass(string id, string kind, int weight, string? detail = null) =>
        new() { ProbeId = id, Kind = kind, Weight = weight, Outcome = ProbeOutcome.Pass, Detail = detail };

    public static ProbeResult Fail(string id, string kind, int weight, ProbeSeverity sev, string? detail = null) =>
        new() { ProbeId = id, Kind = kind, Weight = weight, Outcome = ProbeOutcome.Fail, Severity = sev, Detail = detail };

    public static ProbeResult Inconclusive(string id, string kind, string? detail = null) =>
        new() { ProbeId = id, Kind = kind, Weight = 0, Outcome = ProbeOutcome.Inconclusive, Detail = detail };
}

/// <summary>זיהוי הספק לפי ארבעת הווקטורים הבלתי-תלויים.</summary>
public sealed class ProviderDetection
{
    public string? ProviderId { get; set; }
    public string? DisplayName { get; set; }
    public TrustLevel Trust { get; set; } = TrustLevel.None;

    public bool RootCaMatch { get; set; }
    public bool ReverseDnsMatch { get; set; }
    public bool IpRangeMatch { get; set; }
    public bool HttpMarkerMatch { get; set; }

    public int MatchCount =>
        (RootCaMatch ? 1 : 0) + (ReverseDnsMatch ? 1 : 0) +
        (IpRangeMatch ? 1 : 0) + (HttpMarkerMatch ? 1 : 0);

    public List<string> MatchedThumbprints { get; init; } = new();
    public string? PublicIp { get; set; }
    public string? ReverseDns { get; set; }
}

/// <summary>דוח ביקורת מלא. נשלח לשרת ומשמש לחישוב הסטטוס.</summary>
public sealed class AuditReport
{
    public DateTimeOffset StartedUtc { get; set; }
    public DateTimeOffset CompletedUtc { get; set; }
    public int PolicyVersion { get; set; }
    public ProviderDetection Detection { get; set; } = new();
    public List<ProbeResult> Results { get; init; } = new();

    public int Score { get; set; }
    public SecurityStatus Status { get; set; } = SecurityStatus.Unknown;
    public string Headline { get; set; } = "";

    public IEnumerable<ProbeResult> Failures =>
        Results.Where(r => r.Outcome == ProbeOutcome.Fail);
}

/// <summary>אירוע חבלה/חריגה שמדווח לשרת בעדיפות גבוהה.</summary>
public sealed class TamperEvent
{
    public TamperKind Kind { get; set; }
    public DateTimeOffset Utc { get; set; } = DateTimeOffset.UtcNow;
    public string? Detail { get; set; }
}
