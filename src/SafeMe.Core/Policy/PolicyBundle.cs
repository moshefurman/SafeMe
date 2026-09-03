using System.Text.Json;
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
        Providers = BuiltInProviders(),
        Enforcement = new EnforcementPolicy
        {
            Mode = EnforcementMode.Monitor,
            MinScoreForGreen = 85,
            MinScoreForYellow = 60,
            OnRedAction = RedAction.Warn
        }
    };

    /// <summary>
    /// כללי זיהוי שנוסעים עם הסוכן.
    ///
    /// עד כה כל כלל זיהוי הגיע מהשרת, ורשימה ריקה אינה נראית כמו
    /// "אינני יודע" — היא נראית כמו "לא זוהה ספק מאושר", כלומר
    /// בדיוק כמו מחשב לא מסונן. סוכן שלא קיבל מדיניות דיווח שהחיבור
    /// אינו מסונן בזמן שהמשתמש גלש דרך רימון.
    ///
    /// זה הכיוון הגרוע מבין השניים: הוא גורר אזהרה, ובמצב אכיפה
    /// גם חסימה, על מחשב מוגן לחלוטין.
    ///
    /// הכללים כאן מכוונים במפורש למינימום: רק מנפיק התעודה, שהוא
    /// הווקטור החזק והיציב ביותר — ספק שמסנן דרך פרוקסי חייב להגיש
    /// תעודה משלו. אין כאן טווחי IP ואין גששי תוכן, כי אלה משתנים
    /// ומקומם בשרת.
    ///
    /// והם נדרסים במלואם ברגע שמגיעה מדיניות עם ספקים. אין מיזוג:
    /// שני מקורות לאותה החלטה מתפצלים, ואז מחשב מזהה ספק שהמנהל
    /// כבר הסיר.
    /// </summary>
    public static List<ProviderRule> BuiltInProviders() =>
    [
        new ProviderRule
        {
            Id = "netfree",
            DisplayName = "נטפרי",
            TrustLevel = TrustLevel.High,
            TlsIssuer = new TlsIssuerRule
            {
                // נמדד בשטח: CN="NetFree Node Intermediate CA, 019 Telzar"
                Patterns = ["*NetFree*"],
                Probes = ["www.bet365.com"]
            }
        },
        new ProviderRule
        {
            Id = "rimon",
            DisplayName = "רימון",
            TrustLevel = TrustLevel.High,
            TlsIssuer = new TlsIssuerRule
            {
                /*
                 * Netspark, לא Rimon.
                 *
                 * רימון מסננת דרך Netspark, והתעודה שהיא מגישה
                 * מונפקת בשמם: CN=www.netspark.com, O=Netspark.
                 * המילה "רימון" אינה מופיעה בה כלל.
                 *
                 * נמדד מתוך הרשת: תבנית שמחפשת את שם הספק המסחרי
                 * לא הייתה מתאימה לעולם, והמחשב היה מדווח שאינו
                 * מסונן בזמן שהוא מסונן.
                 *
                 * שם הספק נשאר גם הוא, למקרה שהתשתית תשתנה.
                 */
                Patterns = ["*Netspark*", "*Rimon*"],
                Probes = ["www.bet365.com"]
            },

            /*
             * הקו עצמו.
             *
             * רימון היא ספקית אינטרנט: המחשב יוצא לאינטרנט מהרשת
             * האוטונומית שלה, AS42925, והכתובת הציבורית שלו יושבת
             * בטווחים שהיא מפרסמת ב-RIPE.
             *
             * נמדד ב-3.9.2026 מקו אמיתי: הכתובת 213.151.47.152 —
             * מחוץ לטווח היחיד שהיה רשום, 213.151.48.0/20, בכמה
             * מאות כתובות — בעוד רימון הפסיקה להגיש תעודת Netspark
             * על אתרים חסומים ועברה לנתק. שני הווקטורים נפלו יחד,
             * והמחשב דווח כלא מסונן על קו של רימון.
             *
             * הרשימה היא הקידומות המכסות של כל מה ש-AS42925 מפרסם,
             * לא רק הבלוק שנפגשנו בו.
             */
            Network = new NetworkIdentityRule
            {
                Asns = [42925],
                Cidrs = [.. RimonPrefixes],
                ReverseDnsPatterns = ["*.rimon.net.il", "*rimon*"]
            },

            /*
             * דף החסימה, ב-HTTP רגיל.
             *
             * ב-HTTPS רימון מנתקת; ב-HTTP היא מגישה דף (lighttpd)
             * שמפנה ל-safepage.neto.net.il עם level= של החשבון.
             * הבקשה יוצאת רק אחרי שהקו הוכח כשלה — ראה HasAnySignal.
             */
            HttpMarkers = new HttpMarkerRule
            {
                Url = "http://xvideo.com/",
                Headers = new Dictionary<string, string> { ["Rimon"] = "*" },
                BodyContains = ["safepage.neto.net.il", "cause=url_level", "urllevel="],
                LevelHosts = ["xvideo.com"]
            }
        }
    ];

    /// <summary>
    /// הקידומות המכסות של AS42925 (Internet Rimon LTD), מתוך
    /// RIPE stat, 3.9.2026. IPv4 בלבד — שירותי הכתובת הציבורית
    /// שהסוכן שואל מחזירים IPv4.
    /// </summary>
    public static readonly string[] RimonPrefixes =
    [
        "31.44.128.0/20",
        "37.60.40.0/21",
        "95.86.64.0/18",
        "147.236.212.0/22",
        "147.236.224.0/22",
        "164.138.112.0/20",
        "185.10.64.0/22",
        "185.139.229.0/24",
        "212.76.96.0/19",
        "213.151.32.0/19",
        "217.194.196.0/22",
        "217.194.200.0/21"
    ];

    /// <summary>
    /// שדות שהגרסה הזו אינה מכירה, נשמרים כפי שהתקבלו.
    ///
    /// המדיניות נשמרת לדיסק מסודרת מחדש מהאובייקט, ולא כפי
    /// שהתקבלה. בלי השדה הזה כל שדה חדש שהשרת מוסיף נמחק בשקט
    /// על ידי סוכן שאינו מכיר אותו — ואינו חוזר לעולם, גם אחרי
    /// שדרוג, כי ה-ETag לא השתנה והמדיניות אינה נמשכת מחדש.
    ///
    /// נצפה בשטח: שני גששי זיהוי לנטפרי נשלחו לסוכן 1.1.26, נמחקו
    /// בשמירה, והסוכן 1.1.28 שהותקן אחריו קרא מהדיסק גוף שכבר לא
    /// הכיל אותם. השרת היה תקין לגמרי, והשדה פשוט לא היה שם.
    ///
    /// זה מה שהופך שדרוג לבטוח: מה שהגרסה הבאה תדע לקרוא עדיין
    /// יהיה שם כשהיא תגיע.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Unknown { get; set; }

}

public sealed class ProviderRule
{
    public required string Id { get; set; }
    public string DisplayName { get; set; } = "";
    public TrustLevel TrustLevel { get; set; } = TrustLevel.Medium;
    public RootCaRule? RootCa { get; set; }
    public NetworkIdentityRule? Network { get; set; }
    public TlsIssuerRule? TlsIssuer { get; set; }
    public HttpMarkerRule? HttpMarkers { get; set; }

    /// <summary>
    /// שדות שהגרסה הזו אינה מכירה, נשמרים כפי שהתקבלו.
    ///
    /// המדיניות נשמרת לדיסק מסודרת מחדש מהאובייקט, ולא כפי
    /// שהתקבלה. בלי השדה הזה כל שדה חדש שהשרת מוסיף נמחק בשקט
    /// על ידי סוכן שאינו מכיר אותו — ואינו חוזר לעולם, גם אחרי
    /// שדרוג, כי ה-ETag לא השתנה והמדיניות אינה נמשכת מחדש.
    ///
    /// נצפה בשטח: שני גששי זיהוי לנטפרי נשלחו לסוכן 1.1.26, נמחקו
    /// בשמירה, והסוכן 1.1.28 שהותקן אחריו קרא מהדיסק גוף שכבר לא
    /// הכיל אותם. השרת היה תקין לגמרי, והשדה פשוט לא היה שם.
    ///
    /// זה מה שהופך שדרוג לבטוח: מה שהגרסה הבאה תדע לקרוא עדיין
    /// יהיה שם כשהיא תגיע.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Unknown { get; set; }

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

/// <summary>
/// זיהוי לפי מנפיק התעודה שמוצגת בגלישה בפועל.
///
/// הווקטור החזק ביותר לספק שמסנן דרך פרוקסי, והוא לא היה קיים.
/// כשהסינון מגיש דף חסימה הוא חייב להציג תעודה משלו — ושם המנפיק
/// הוא חתימה שאי אפשר לזייף בלי המפתח הפרטי שלו.
///
/// נמדד בלחיצת יד בלבד: אין בקשת HTTP, ולא יורד שום תוכן.
/// </summary>
public sealed class TlsIssuerRule
{
    /// <summary>תבניות התאמה לשם המנפיק. תומך בכוכבית.</summary>
    public List<string> Patterns { get; set; } = new();

    /// <summary>
    /// המארחים שאליהם בודקים.
    ///
    /// חייבים להיות כאלה שהסינון מגיש עליהם דף ולא מנתק — ניתוק
    /// אינו מציג תעודה, ואין ממנו מה ללמוד על זהות הספק.
    /// </summary>
    public List<string> Probes { get; set; } = new();
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

    /// <summary>
    /// המארחים שמהם נקראת רמת הסינון.
    /// ריק פירושו שהרמה נקראת מ-Url בלבד.
    ///
    /// הם נבחרים דווקא בקטגוריות שהסינון חוסם בכל רמה — פורנוגרפיה
    /// היא הבחירה המובהקת, כי הימורים או רשתות חברתיות עשויים להיות
    /// מותרים ברמות מקלות, ואז לא מתקבל דף חסימה כלל ואין מה לקרוא.
    ///
    /// הגישה אליהם מותנית: ראה LevelProbeGate. בקשת HTTP נשלחת רק
    /// אחרי שהוכח שהחיבור מסונן, ולכן מה שמתקבל הוא תמיד דף החסימה
    /// של הספק — ולעולם לא האתר עצמו.
    /// </summary>
    public List<string> LevelHosts { get; set; } = new();

    /// <summary>
    /// שמות דרגות ההגנה, כפי שהספק כותב אותם בדף החסימה.
    ///
    /// רשימה סגורה ולא תבנית חילוץ: היא יכולה רק לא למצוא, ולעולם
    /// לא תמציא דרגה שאינה קיימת. השמות מגיעים מהשרת כדי שאפשר
    /// יהיה לעדכן אותם כשהספק משנה ניסוח, בלי גרסה חדשה.
    /// </summary>
    public List<string> LevelNames { get; set; } = new();

    /// <summary>
    /// גששים נוספים, כשלספק יש יותר מדרך אחת להעיד על עצמו.
    ///
    /// Url לבדו הספיק כל עוד לכל ספק הייתה בדיקה אחת. נטפרי חשפה
    /// את הגבול: יש לה שתי נקודות קצה שונות שעונות אחרת מבפנים
    /// ומבחוץ, ואחת מהן נבדקת לפי קוד המצב ולא לפי הגוף.
    ///
    /// כל גשש עומד בפני עצמו, והתאמה של אחד מספיקה. הם אינם
    /// מצטברים לניקוד — כולם יחד הם ווקטור אחד, "כותרת חסימה",
    /// בדיוק כמו קודם.
    /// </summary>
    public List<HttpProbeRule> Probes { get; set; } = new();

    /// <summary>
    /// שדות שהגרסה הזו אינה מכירה, נשמרים כפי שהתקבלו.
    ///
    /// המדיניות נשמרת לדיסק מסודרת מחדש מהאובייקט, ולא כפי
    /// שהתקבלה. בלי השדה הזה כל שדה חדש שהשרת מוסיף נמחק בשקט
    /// על ידי סוכן שאינו מכיר אותו — ואינו חוזר לעולם, גם אחרי
    /// שדרוג, כי ה-ETag לא השתנה והמדיניות אינה נמשכת מחדש.
    ///
    /// נצפה בשטח: שני גששי זיהוי לנטפרי נשלחו לסוכן 1.1.26, נמחקו
    /// בשמירה, והסוכן 1.1.28 שהותקן אחריו קרא מהדיסק גוף שכבר לא
    /// הכיל אותם. השרת היה תקין לגמרי, והשדה פשוט לא היה שם.
    ///
    /// זה מה שהופך שדרוג לבטוח: מה שהגרסה הבאה תדע לקרוא עדיין
    /// יהיה שם כשהיא תגיע.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Unknown { get; set; }

}

/// <summary>
/// בדיקה אחת מול מארח אחד.
///
/// שלושת התנאים נבדקים יחד, ומי שמוגדר חייב להתקיים. גשש בלי אף
/// תנאי אינו מתאים לעולם — זה מכוון, כדי שהגדרה חסרה לא תיצור
/// זיהוי חיובי על כל תשובה שהיא.
/// </summary>
public sealed class HttpProbeRule
{
    public required string Url { get; set; }

    /// <summary>קוד מצב שחייב לחזור. null פירושו שכל קוד מתקבל.</summary>
    public int? Status { get; set; }

    /// <summary>מחרוזות שאחת מהן חייבת להופיע בגוף.</summary>
    public List<string> BodyContains { get; set; } = new();

    /// <summary>
    /// מחרוזות שאף אחת מהן לא תופיע בגוף.
    ///
    /// קיים בשביל נקודות קצה שאומרות במפורש "אינך אצלנו". שם
    /// ההיעדר הוא הראיה, ולכן היא חייבת להיות מלווה בתנאי חיובי —
    /// אחרת כל שגיאת רשת שמחזירה גוף ריק הייתה נחשבת התאמה.
    /// </summary>
    public List<string> BodyNotContains { get; set; } = new();
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

    /// <summary>
    /// כמה ימים מחשב יכול לא לשמוע מהשרת לפני שהאכיפה משוחררת.
    ///
    /// זו רשת הביטחון שנדרשה ברגע שההסרה הכפויה נסגרה: מאותה נקודה
    /// קוד הסרה נחתם ב-KMS ואין דרך אחרת, ומפתח שיאבד היה נועל את
    /// כל הצי לצמיתות — גם את המוקד וגם אותנו.
    ///
    /// שישים יום, ובנדיבות מכוונת. ההורה מקבל התראה על מחשב ששותק
    /// הרבה לפני כן, וחלון קצר היה הופך כל חופשה או מחשב שהיה
    /// במגירה לשחרור אכיפה. חלון ארוך הופך את השתיקה לבולטת.
    ///
    /// אפס מכבה את המנגנון. זו אינה ברירת המחדל, אבל ארגון שמפעיל
    /// שרת משלו ומוכן לקחת את הסיכון רשאי.
    /// </summary>
    public int MaxOfflineDays { get; set; } = 60;

}

public sealed class AllowedNetworks
{
    public List<string> WifiSsids { get; set; } = new();
    public List<string> Cidrs { get; set; } = new();

    /// <summary>רשימת מזהי ספקים שרק דרכם מותרת גלישה.</summary>
    public List<string> RequireProvider { get; set; } = new();

    /// <summary>
    /// האם רשת שטרם הוכרעה נחסמת עד שההורה מאשר.
    ///
    /// עד כה הסוכן לא ידע דבר על הדרישה הזו — היא הייתה קיימת רק
    /// בשרת, שמחזיר await_approval בפעימה. וכשהרשת מתחלפת הסוכן
    /// מוחק את ההכרעה הקודמת, כי היא נאמרה על רשת אחרת, ואז הוא
    /// **מאשר** את החדשה עד שתגיע הכרעה.
    ///
    /// זה נצפה בשטח: לקוח שהגדיר שאף רשת לא תאושר עד אישור התחבר
    /// לרשת חדשה וגלש. חלון של פעימה שלמה, עד שלוש דקות, בכל
    /// החלפת רשת — כלומר בדיוק ברגע שההגדרה נועדה לו.
    ///
    /// כשהדגל דלוק הכיוון הבטוח מתהפך: חוסמים ומחכים. מה שהופך
    /// את זה לאפשרי הוא AlwaysAllow — השרת והפורטל נשארים פתוחים
    /// גם בחסימה, ולכן ההכרעה מגיעה וההורה יכול לאשר. בלי החורים
    /// האלה חסימה כזו הייתה מלכודת בלי מוצא.
    ///
    /// כבוי כברירת מחדל, כדי שמדיניות קיימת לא תשנה התנהגות ברגע
    /// שהשרת מתעדכן.
    /// </summary>
    public bool BlockUntilApproved { get; set; }
}

/// <summary>חורים מוגדרים בנעילת החירום. בלעדיהם המחשב היה מתנתק לחלוטין.</summary>
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
