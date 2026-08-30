namespace SafeMe.Core.Models;

/// <summary>תוצאה של גשש בודד, כולל ראיות לצורך דיווח לשרת.</summary>
public sealed class ProbeResult
{
    public required string ProbeId { get; init; }
    public required string Kind { get; init; }
    public ProbeOutcome Outcome { get; set; } = ProbeOutcome.Inconclusive;
    public ProbeSeverity Severity { get; set; } = ProbeSeverity.Info;
    public int Weight { get; set; }

    /// <summary>
    /// כמה מהמשקל נזקף בפועל. תמיד בין 0 ל-Weight.
    ///
    /// קיים כדי שראיה חלקית לא תיספר כאפס. עד שהוא נוסף, גשש
    /// שמצא משהו אמיתי אך לא מספיק תרם בדיוק כמו גשש שלא מצא
    /// דבר — וכשהוא היה הגשש היחיד שרץ, הציון היה 0 והמחשב
    /// דיווח "אינו מסונן" על סמך ראיה חיובית.
    /// </summary>
    public int Credit { get; set; }

    public string? Title { get; set; }
    public string? Detail { get; set; }
    public long DurationMs { get; set; }
    public Dictionary<string, string> Evidence { get; init; } = new();

    public static ProbeResult Pass(string id, string kind, int weight, string? detail = null) =>
        new()
        {
            ProbeId = id, Kind = kind, Weight = weight, Credit = weight,
            Outcome = ProbeOutcome.Pass, Detail = detail
        };

    public static ProbeResult Fail(string id, string kind, int weight, ProbeSeverity sev, string? detail = null) =>
        new()
        {
            ProbeId = id, Kind = kind, Weight = weight, Credit = 0,
            Outcome = ProbeOutcome.Fail, Severity = sev, Detail = detail
        };

    /// <summary>ראיה חלקית. credit נחתך לטווח 0..weight.</summary>
    public static ProbeResult Partial(
        string id, string kind, int weight, int credit, ProbeSeverity sev, string? detail = null) =>
        new()
        {
            ProbeId = id, Kind = kind, Weight = weight,
            Credit = Math.Clamp(credit, 0, weight),
            Outcome = ProbeOutcome.Partial, Severity = sev, Detail = detail
        };

    public static ProbeResult Inconclusive(string id, string kind, string? detail = null) =>
        new() { ProbeId = id, Kind = kind, Weight = 0, Outcome = ProbeOutcome.Inconclusive, Detail = detail };
}

/// <summary>זיהוי הספק לפי ארבעת הווקטורים הבלתי-תלויים.</summary>
public sealed class ProviderDetection
{
    public string? ProviderId { get; set; }
    public string? DisplayName { get; set; }
    public TrustLevel Trust { get; set; } = TrustLevel.None;

    /// <summary>
    /// רמת הסינון כפי שהספק מדווח אותה על עצמו.
    ///
    /// null כשלא הצלחנו לקרוא — וזה שונה מ"אין סינון". הורה שהגדיר
    /// רמה מחמירה ומצא אותה מוקלת לא היה יודע, וזו בדיוק צורת
    /// העקיפה שקשה לתפוס: לא ניתוק הסינון, אלא החלשתו בשקט.
    /// </summary>
    public Policy.FilterLevel? FilterLevel { get; set; }

    /// <summary>
    /// תעודת השורש של הספק מותקנת במחשב.
    ///
    /// אינה נספרת כווקטור, ומשקלה אפס.
    ///
    /// תעודת שורש נשארת בחנות התעודות לנצח. היא נכונה באותה מידה
    /// כשהמחשב מחובר לספק וכשהוא מחובר לרשת סלולרית זרה, וכשהמנוי
    /// בוטל לפני חודש. היא עונה על "המחשב הוכן פעם לרימון" — ולא
    /// על השאלה היחידה שיש לסוכן, "האם הוא מסונן עכשיו".
    ///
    /// כך זה נראה בשטח: מחשב שהתנתק מרימון לגמרי המשיך להציג את
    /// רימון כספק שלו, עם שישים אחוז מהמשקל, מפני שהתעודה עדיין
    /// שם. זיהוי חיובי שגוי — הכשל היחיד שאסור לתוכנה הזו.
    ///
    /// היא נשארת בשני תפקידים שאינם מזכים בניקוד: רמז זול לאיזה
    /// ספק כדאי לבדוק לעומק, וּוטו — ספק שהמדיניות דורשת את
    /// תעודתו ואינה נמצאת, מזוהה ברמת ביטחון נמוכה בלבד. שניהם
    /// יכולים רק להוריד את הטענה להגנה, לעולם לא להעלות אותה.
    /// </summary>
    public bool RootCaMatch { get; set; }

    public bool ReverseDnsMatch { get; set; }
    public bool IpRangeMatch { get; set; }
    public bool HttpMarkerMatch { get; set; }

    /// <summary>
    /// מנפיק התעודה שהוצגה בגלישה תאם לספק.
    ///
    /// הווקטור החזק ביותר: הוא נמדד על החיבור עצמו, ולא על מה
    /// שמותקן במחשב או על הכתובת שממנה הוא יוצא.
    /// </summary>
    public bool TlsIssuerMatch { get; set; }

    /// <summary>
    /// הווקטורים שהתאימו, בשמם.
    ///
    /// קיים כדי שאפשר יהיה לענות על "למה הוא אומר שאינו מסונן" בלי
    /// לנחש. MatchCount לבדו אומר כמה, ולא אילו — וההבדל בין "רק
    /// טווח הכתובות" לבין "מנפיק התעודה" הוא ההבדל בין זיהוי חלש
    /// לזיהוי שאי אפשר לזייף.
    /// </summary>
    public IReadOnlyList<string> MatchedVectors
    {
        get
        {
            var matched = new List<string>(4);

            if (TlsIssuerMatch) matched.Add("מנפיק תעודה");
            if (HttpMarkerMatch) matched.Add("כותרת חסימה");
            if (IpRangeMatch) matched.Add("טווח כתובות");
            if (ReverseDnsMatch) matched.Add("שם הפוך");

            return matched;
        }
    }

    /// <summary>
    /// כמה ווקטורים חיים התאימו.
    ///
    /// "חי" הוא ווקטור שנמדד על החיבור ברגע זה — מי הנפיק את
    /// התעודה שהוצגה, איזו כותרת חזרה, מאיזו כתובת אנחנו יוצאים.
    /// כולם מתאפסים ברגע שהמחשב עובר רשת, וזו בדיוק התכונה
    /// שהופכת אותם לראיה.
    ///
    /// תעודת השורש אינה כאן. היא מצב של המחשב, לא של החיבור.
    /// </summary>
    public int MatchCount =>
        (ReverseDnsMatch ? 1 : 0) + (IpRangeMatch ? 1 : 0) +
        (HttpMarkerMatch ? 1 : 0) + (TlsIssuerMatch ? 1 : 0);

    /// <summary>
    /// יש סיבה כלשהי לחשוד שזה הספק — כולל תעודת השורש.
    ///
    /// לשימוש בהחלטות שעולות כסף ולא בהחלטות שנותנות ניקוד:
    /// בדיקת הכותרות היא בקשת רשת, ואין טעם לשלוח אותה לכל ספק
    /// ברשימה. תעודה מותקנת היא רמז מצוין לאן לכוון — היא פשוט
    /// אינה ראיה בפני עצמה.
    /// </summary>
    public bool HasAnySignal => MatchCount > 0 || RootCaMatch;

    /// <summary>שם המנפיק שנצפה בפועל, לתצוגה ולאבחון.</summary>
    public string? ObservedIssuer { get; set; }

    public List<string> MatchedThumbprints { get; init; } = new();
    public string? PublicIp { get; set; }
    public string? ReverseDns { get; set; }

    /// <summary>
    /// האם הבדיקה בכלל הצליחה לרוץ.
    ///
    /// ההבחנה הזו קריטית, והיעדרה נעל מחשב אמיתי: "בדקתי ולא מצאתי
    /// ספק" ו"לא הצלחתי לבדוק" הם שני דברים שונים לגמרי, ורק
    /// הראשון מצדיק חסימה.
    ///
    /// כשאין רשת, שירות הכתובת הציבורית אינו נגיש והזיהוי לפי IP
    /// אינו יכול לרוץ. אם גם מאגר התעודות לא נתן תשובה, אין בידינו
    /// שום ראיה — לא לכאן ולא לכאן. חסימה במצב הזה יוצרת מלכוד:
    /// היא מונעת את הבדיקה שהייתה משחררת אותה.
    /// </summary>
    public bool DetectionRan { get; set; } = true;
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
