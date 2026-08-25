using SafeMe.Core.Models;
using SafeMe.Core.Policy;

namespace SafeMe.Core.Abstractions;

/// <summary>מספק את מזהה החומרה של המכשיר.</summary>
public interface IHardwareIdProvider
{
    /// <summary>מזהה יציב, מחושב פעם אחת ונשמר בזיכרון.</summary>
    string GetHardwareId();
}

/// <summary>גשש ביקורת בודד. כל גשש עצמאי ואינו מסתמך על תוצאות אחרים.</summary>
public interface IAuditProbe
{
    /// <summary>מזהה סוג הגשש, לדוגמה RootCa או ContentHttp.</summary>
    string Kind { get; }

    Task<IReadOnlyList<ProbeResult>> RunAsync(PolicyBundle policy, CancellationToken ct);
}

/// <summary>מנוע האכיפה. המימוש הנוכחי מבוסס Windows Filtering Platform.</summary>
public interface IEnforcementEngine : IDisposable
{
    /// <summary>מאתחל את התשתית (Provider ו-SubLayer). מחזיר false אם BFE אינו זמין.</summary>
    bool Initialize();

    /// <summary>מיישם את מצב האכיפה הרצוי באופן אטומי.</summary>
    void Apply(EnforcementPlan plan);

    /// <summary>מסיר את כל החוקים של SafeMe. משמש בהסרה מאושרת.</summary>
    void RemoveAll();

    /// <summary>מספר החוקים הפעילים שנרשמו על ידי SafeMe.</summary>
    int ActiveFilterCount { get; }

    /// <summary>בודק שכל החוקים שנרשמו עדיין קיימים ב-BFE.</summary>
    bool VerifyIntegrity();
}

/// <summary>תוכנית האכיפה שמתורגמת לחוקי WFP.</summary>
public sealed class EnforcementPlan
{
    public static EnforcementPlan Disabled => new() { BlockAllOutbound = false };

    /// <summary>אם true, כל התעבורה היוצאת נחסמת פרט לחריגים.</summary>
    public bool BlockAllOutbound { get; init; }

    /// <summary>כתובות IPv4 בפורמט CIDR שמותרות במפורש.</summary>
    public List<string> AllowedRemoteCidrs { get; init; } = new();

    /// <summary>כתובות שרת הניהול, תמיד מותרות כדי לא לנתק את המכשיר.</summary>
    public List<string> ServerIps { get; init; } = new();

    public List<int> AllowedPorts { get; init; } = new();

    public bool AllowDns { get; init; } = true;
    public bool AllowDhcp { get; init; } = true;
    public bool AllowLoopback { get; init; } = true;

    /// <summary>נתיבי הרצה שתמיד מורשים, לדוגמה השירות עצמו.</summary>
    public List<string> AllowedAppPaths { get; init; } = new();

    /// <summary>סיבה לתצוגה ולתיעוד.</summary>
    public string Reason { get; init; } = "";
}

/// <summary>לקוח שרת הניהול.</summary>
public interface IManagementServerClient
{
    Task<EnrollResponse?> EnrollAsync(EnrollRequest request, CancellationToken ct);
    Task<PolicyResponse> GetPolicyAsync(string? etag, CancellationToken ct);
    Task<HeartbeatResponse?> SendHeartbeatAsync(HeartbeatRequest request, CancellationToken ct);
    Task<bool> SendAuditAsync(AuditReport report, CancellationToken ct);
    Task<bool> SendEventsAsync(IReadOnlyList<TamperEvent> events, CancellationToken ct);
}

/// <summary>מקור האמת לסטטוס הנוכחי, משותף בין כל רכיבי השירות.</summary>
public interface IAgentStateProvider
{
    StatusSnapshot Current { get; }
    void Update(Action<StatusSnapshot> mutate);
    event Action<StatusSnapshot>? Changed;
}
