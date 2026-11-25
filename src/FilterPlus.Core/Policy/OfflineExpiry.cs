namespace FilterPlus.Core.Policy;

/// <summary>מה עושים עם מחשב שמזמן לא שמע מהשרת.</summary>
public enum OfflineState
{
    /// <summary>בקשר, או בתוך החלון. אכיפה כרגיל.</summary>
    Live,

    /// <summary>מתקרב לפקיעה. עדיין אוכף, אבל מזהיר.</summary>
    Warning,

    /// <summary>פג. האכיפה משוחררת, וההסרה אינה דורשת קוד.</summary>
    Expired
}

/// <summary>
/// תוקף מוגבל לסוכן שנותק מהשרת.
///
/// נבנה אחרי שנסגרה ההסרה הכפויה. מאותו רגע קוד הסרה נחתם ב-KMS
/// ואין דרך אחרת — ומפתח שיאבד, או שירות שייסגר, נועל את כל הצי
/// לצמיתות. לא רק את ההורה: גם את המוקד, וגם אותנו.
///
/// זו הדרך היחידה מבין השלוש שנשקלו שאינה תלויה בשמירת סוד. גיבוי
/// מפתח ומפתח חילוץ שני שניהם מחליפים סוד אחד בסוד אחר, ושניהם
/// נכשלים באותה נקודה: מישהו צריך לשמור משהו, לנצח.
///
/// היא פותרת גם מקרים שאין להם קשר לאובדן מפתח — מחשב שנמכר,
/// משפחה שעזבה, חברה שנסגרה. בכולם המחשב פשוט מפסיק לשמוע, ואחרי
/// זמן מספיק ארוך הוא משחרר.
///
/// ---
///
/// והמחיר, כי יש כזה: מי שיחסום לסוכן את הגישה לשרת ויחכה מספיק
/// זמן, יקבל מחשב לא אכוף. זה אינו חור שנפתח כאן — ההורה מקבל
/// התראה על מחשב ששותק, וחודשיים של התעלמות מהתראות הם החלטה.
/// מה שכן נדרש הוא שהחלון יהיה ארוך מספיק כדי שהשתיקה תבלוט,
/// ולכן ברירת המחדל נדיבה במכוון.
/// </summary>
public static class OfflineExpiry
{
    /// <summary>
    /// מתי מתחילים להזהיר, כשיעור מהחלון.
    ///
    /// שלושת רבעי הדרך. מוקדם מדי הופך את האזהרה לרעש שמתעלמים
    /// ממנו, ומאוחר מדי אינו משאיר זמן לפעול.
    /// </summary>
    private const double WarnAt = 0.75;

    /// <summary>
    /// <paramref name="maxOfflineDays"/> אפס או פחות פירושו שאין
    /// פקיעה כלל. זו אינה ברירת המחדל, אבל היא צריכה להיות אפשרית:
    /// ארגון שמפעיל שרת משלו ומוכן לקחת את הסיכון רשאי לכבות את זה.
    ///
    /// <paramref name="lastContactUtc"/> ריק פירושו שמעולם לא היה
    /// קשר. זה אינו "מנותק מזמן" אלא מחשב שרק הותקן, והוא נספר
    /// מרגע ההתקנה — אחרת כל התקנה חדשה הייתה נולדת פגה.
    /// </summary>
    public static OfflineState Evaluate(
        DateTimeOffset? lastContactUtc,
        DateTimeOffset installedUtc,
        DateTimeOffset now,
        int maxOfflineDays)
    {
        if (maxOfflineDays <= 0) return OfflineState.Live;

        var since = lastContactUtc ?? installedUtc;

        /*
         * שעון שקפץ אחורה.
         *
         * מגע עתידי היה מייצר משך שלילי, וכל השוואה הייתה מחזירה
         * Live לנצח — כלומר שינוי שעון היה מבטל את הפקיעה. הכיוון
         * הבטוח כאן הוא להתייחס לזה כאילו המגע קרה עכשיו.
         */
        if (since > now) return OfflineState.Live;

        var offline = now - since;
        var window = TimeSpan.FromDays(maxOfflineDays);

        if (offline >= window) return OfflineState.Expired;

        return offline >= window * WarnAt ? OfflineState.Warning : OfflineState.Live;
    }

    /// <summary>כמה ימים נשארו עד הפקיעה. שלילי אחרי שפג.</summary>
    public static double DaysLeft(
        DateTimeOffset? lastContactUtc,
        DateTimeOffset installedUtc,
        DateTimeOffset now,
        int maxOfflineDays)
    {
        if (maxOfflineDays <= 0) return double.PositiveInfinity;

        var since = lastContactUtc ?? installedUtc;

        if (since > now) return maxOfflineDays;

        return maxOfflineDays - (now - since).TotalDays;
    }
}
