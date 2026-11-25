namespace FilterPlus.Core.Policy;

/// <summary>
/// איך הספק מסנן בפועל. שתי הצורות דורשות אכיפה שונה לגמרי.
/// </summary>
public enum ProviderEgressMode
{
    /// <summary>
    /// הסינון ברמת הספק. המחשב יוצא לכל האינטרנט, והסינון קורה
    /// בדרך. אין רשימת יעדים לאשר — כל האינטרנט הוא היעד.
    /// </summary>
    IspLevel = 0,

    /// <summary>
    /// הסינון דרך שרתי הספק. המחשב מדבר רק איתם, והם יוצאים
    /// החוצה. כאן רשימת יעדים היא אכיפה אמיתית.
    /// </summary>
    ProxyEndpoint = 1
}

/// <summary>
/// הגדרת ה-default-deny.
///
/// מגיעה מהשרת בחבילת המדיניות ולא מקומפלת לתוך הסוכן, כי רשימת
/// כלי המנהור משתנה מהר יותר מקצב שחרור הגרסאות. כלי חדש שיצא
/// היום צריך להיחסם היום, לא בגרסה הבאה.
/// </summary>
public sealed class EgressRule
{
    /// <summary>האם מצב default-deny פעיל בכלל.</summary>
    public bool Enabled { get; set; }

    public ProviderEgressMode Mode { get; set; } = ProviderEgressMode.IspLevel;

    /// <summary>
    /// היעדים המותרים ב-ProxyEndpoint. חסר משמעו שאין מה לאשר,
    /// והתוצאה תהיה נעילה מלאה — וזה נכון: מוטב בלי אינטרנט
    /// מאשר עם אינטרנט לא מסונן.
    /// </summary>
    public List<string> ProviderCidrs { get; set; } = new();

    /// <summary>הפורטים שדפדוף רגיל צריך. ב-IspLevel זה כל מה שמותר.</summary>
    public List<int> WebPorts { get; set; } = new() { 80, 443 };

    /// <summary>
    /// שרתי ה-DNS המותרים. ריק משמעו שכל שרת DNS מותר — פרצה
    /// שמאפשרת להצביע על שרת שאינו מסנן.
    /// </summary>
    public List<string> Resolvers { get; set; } = new();

    /// <summary>
    /// האם לאפשר QUIC (UDP/443).
    ///
    /// כבוי כברירת מחדל. QUIC מוצפן מקצה לקצה כולל הכותרות, ולכן
    /// חלק ממנגנוני הסינון אינם רואים לתוכו. כשהוא חסום הדפדפן
    /// נופל אחורה ל-TCP, שהסינון כן קורא.
    /// </summary>
    public bool AllowQuic { get; set; }

    /// <summary>פורטים שנחסמים במפורש, גם אם משהו אחר התיר אותם.</summary>
    public List<PortBlock> BlockedPorts { get; set; } = new();

    /// <summary>
    /// יעדים חסומים: שרתי DNS-over-HTTPS, שערי Tor ידועים, ושירותי
    /// VPN שרצים על 443 ולכן אינם נתפסים לפי פורט.
    /// </summary>
    public List<string> BlockedCidrs { get; set; } = new();

    /// <summary>
    /// תוכנות שנחסמות לפי שם הקובץ, בלי קשר לפורט.
    ///
    /// זה מה שתופס את מה שרוכב על 443: WireGuard, AnyDesk, Tor.
    /// חסימה לפי פורט לבדה מפספסת את כולם.
    /// </summary>
    public List<string> BlockedProcessNames { get; set; } = new();

    /// <summary>האם לחסום תעבורה נכנסת. חוסם שליטה מרחוק על המחשב הזה.</summary>
    public bool BlockInbound { get; set; } = true;
}

/// <summary>פורט וקידומת פרוטוקול לחסימה.</summary>
public sealed class PortBlock
{
    public int Port { get; set; }

    /// <summary>tcp, udp, או any.</summary>
    public string Protocol { get; set; } = "any";

    /// <summary>למה. מוצג בפורטל כשמשהו נחסם.</summary>
    public string Label { get; set; } = "";
}
