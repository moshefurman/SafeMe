using SafeMe.Core.Models;
using SafeMe.Core.Policy;

namespace SafeMe.Core.Abstractions;

/// <summary>מספק את מזהה החומרה של המחשב.</summary>
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

    /// <summary>כתובות שרת הניהול, תמיד מותרות כדי לא לנתק את המחשב.</summary>
    public List<string> ServerIps { get; init; } = new();

    public List<int> AllowedPorts { get; init; } = new();

    public bool AllowDns { get; init; } = true;
    public bool AllowDhcp { get; init; } = true;
    public bool AllowLoopback { get; init; } = true;

    /// <summary>נתיבי הרצה שתמיד מורשים, לדוגמה השירות עצמו.</summary>
    public List<string> AllowedAppPaths { get; init; } = new();

    /// <summary>סיבה לתצוגה ולתיעוד.</summary>
    public string Reason { get; init; } = "";

    // ---------------------------------------------------- default-deny

    /// <summary>
    /// עמדת היציאה שהתוכנית מבטאת. לתצוגה ולתיעוד בלבד — האכיפה
    /// נגזרת מהשדות עצמם, לא מהערך הזה.
    /// </summary>
    public EgressPosture Posture { get; init; } = EgressPosture.Off;

    /// <summary>
    /// הפורטים שמותר לצאת אליהם. ריק בתוכנית עם BlockAllOutbound
    /// משמעו נעילה מלאה: רק שרת הניהול והלולאה המקומית.
    /// </summary>
    public List<PortPermit> AllowedPortRules { get; init; } = new();

    /// <summary>שרתי DNS מותרים. כשהרשימה מלאה, פורט 53 מותר רק אליהם.</summary>
    public List<string> AllowedResolvers { get; init; } = new();

    /// <summary>פורטים שנחסמים מעל כל היתר.</summary>
    public List<PortBlock> BlockedPorts { get; init; } = new();

    /// <summary>יעדים שנחסמים מעל כל היתר.</summary>
    public List<string> BlockedRemoteCidrs { get; init; } = new();

    /// <summary>שמות קבצי הרצה שנחסמים בלי קשר לפורט או ליעד.</summary>
    public List<string> BlockedProcessNames { get; init; } = new();

    /// <summary>חסימת תעבורה נכנסת. מונע שליטה מרחוק על המחשב הזה.</summary>
    public bool BlockAllInbound { get; init; }
}

/// <summary>מה מצב היציאה אומר, לתצוגה בפורטל ובמגש.</summary>
public enum EgressPosture
{
    /// <summary>ללא default-deny. התנהגות המוצר לפני האפיון הזה.</summary>
    Off = 0,

    /// <summary>יציאה מסוננת: דפדוף רגיל מותר, מנהרות חסומות.</summary>
    Filtered = 1,

    /// <summary>רק שרתי הספק. הצורה החזקה, אפשרית רק בסינון דרך שרתי הספק.</summary>
    ProviderOnly = 2,

    /// <summary>נעילה מלאה: רק שרת הניהול. לא זוהה ספק מאושר.</summary>
    LockedDown = 3,

    /// <summary>
    /// חסימה מוחלטת. אין חשבון, אין שרת, ואין דרך החוצה.
    ///
    /// נבדל מ-LockedDown בכך שגם ערוץ הניהול סגור — אין למי לדבר.
    /// היציאה היחידה היא קוד הסרה שנוצר מול מזהה החומרה, בטלפון.
    /// </summary>
    Sealed = 4
}

/// <summary>היתר לפורט, אולי מוגבל ליעד.</summary>
public sealed class PortPermit
{
    public required int Port { get; init; }

    /// <summary>tcp, udp, או any.</summary>
    public string Protocol { get; init; } = "tcp";

    /// <summary>
    /// הגבלת היעד. ריק משמעו לכל יעד.
    ///
    /// זה ההבדל בין "פורט 53 מותר" לבין "פורט 53 מותר לשרתי הספק
    /// בלבד". הראשון מאפשר להצביע על שרת שאינו מסנן.
    /// </summary>
    public List<string> ToCidrs { get; init; } = new();
}

/// <summary>לקוח שרת הניהול.</summary>
public interface IManagementServerClient
{
    Task<EnrollResponse?> EnrollAsync(EnrollRequest request, CancellationToken ct);
    Task<PolicyResponse> GetPolicyAsync(string? etag, CancellationToken ct);
    Task<HeartbeatResponse?> SendHeartbeatAsync(HeartbeatRequest request, CancellationToken ct);
    Task<bool> SendAuditAsync(AuditReport report, CancellationToken ct);
    Task<bool> SendEventsAsync(IReadOnlyList<TamperEvent> events, CancellationToken ct);

    /// <summary>
    /// מודיע לשרת שהמחשב מוסר, כדי שייעלם מרשימת המחשבים.
    ///
    /// בלי זה המחשב נשאר ברשימה לנצח אחרי הסרה מוצלחת, וההורה רואה
    /// מכשירים שכבר אינם קיימים — כלומר הרשימה מפסיקה להיות תמונה
    /// של מה שמוגן.
    /// </summary>
    Task<bool> ReportUninstalledAsync(CancellationToken ct);
}

/// <summary>מקור האמת לסטטוס הנוכחי, משותף בין כל רכיבי השירות.</summary>
public interface IAgentStateProvider
{
    StatusSnapshot Current { get; }
    void Update(Action<StatusSnapshot> mutate);
    event Action<StatusSnapshot>? Changed;
}
