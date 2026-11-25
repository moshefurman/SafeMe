namespace FilterPlus.Core.Watchdog;

/// <summary>מצב שירות, כפי שהשומר רואה אותו.</summary>
public enum ServiceState
{
    /// <summary>לא הצלחנו לברר. אינו נחשב עצור.</summary>
    Unknown = 0,
    Running = 1,
    Stopped = 2,

    /// <summary>אינו רשום כלל. מישהו הסיר אותו.</summary>
    Missing = 3,
}

/// <summary>מה השומר עושה עכשיו.</summary>
public enum WatchAction
{
    /// <summary>שום דבר. הכול תקין.</summary>
    None = 0,
    Start = 1,

    /// <summary>ממתין: ניסיון קודם היה לפני רגע.</summary>
    Backoff = 2,

    /// <summary>השירות אינו רשום. הפעלה לא תעזור, וצריך התקנה מחדש.</summary>
    ReportMissing = 3,
}

public sealed record WatchDecision(WatchAction Action, string Reason);

/// <summary>
/// מתי להחיות שירות שנעצר.
///
/// זהו הפער האמיתי בהגנה העצמית. sc failure מחזיר שירות שקרס, אך לא
/// שירות שנעצר בפקודה — עצירה נקייה אינה כשל, ומבחינת Windows לא
/// קרה דבר. מי שמריץ sc stop משאיר את ההגנה מכובה עד שהמשימה
/// המתוזמנת תתעורר, וזה עד רבע שעה.
///
/// הלוגיקה כאן טהורה בכוונה: היא מכריעה מתוך מצב וזמן, בלי לגעת
/// ב-Windows. כך אפשר לבדוק כל צירוף — כולל אלה שקשה לייצר על
/// מכונה אמיתית — בלי להפיל שירות אמיתי.
/// </summary>
public static class WatchdogGate
{
    /// <summary>
    /// המתנה בין ניסיונות.
    ///
    /// שירות שנכשל בעלייה שוב ושוב אינו מתוקן על ידי ניסיון שלישי
    /// בשנייה הבאה — הוא רק ממלא את היומן ומעמיס. שלוש שניות נראות
    /// מיידיות למי שמסתכל, ורחוקות מספיק מלולאה.
    /// </summary>
    public static readonly TimeSpan Backoff = TimeSpan.FromSeconds(3);

    /// <summary>
    /// מכריע.
    ///
    /// Unknown אינו נחשב עצור, ובמכוון: כשלא הצלחנו לברר את המצב,
    /// הפעלה עיוורת יכולה להתנגש בעצירה מכוונת שבאמצע. הספק מוכרע
    /// לטובת אי-פעולה, כי הצד השני מייצר לולאה בין השומר למתקין.
    /// </summary>
    public static WatchDecision Decide(
        ServiceState state,
        DateTimeOffset now,
        DateTimeOffset? lastAttempt,
        bool updateInProgress = false)
    {
        if (state == ServiceState.Missing)
        {
            return new WatchDecision(
                WatchAction.ReportMissing,
                "השירות אינו רשום במערכת. הפעלה לא תעזור.");
        }

        if (state is ServiceState.Running or ServiceState.Unknown)
            return new WatchDecision(WatchAction.None, "");

        /*
         * עדכון בעיצומו.
         *
         * המתקין עוצר את השירות בכוונה כדי להחליף את הקבצים שלו.
         * שומר שיחזיר אותו באותו רגע יחזיק את הקבצים נעולים והעדכון
         * ייכשל — ואז יופעל שוב, ייכשל שוב, ולא ייגמר.
         */
        if (updateInProgress)
        {
            return new WatchDecision(
                WatchAction.None,
                "עדכון בעיצומו. השירות ייעצר ויחזור על ידי המתקין.");
        }

        if (lastAttempt is { } previous && now - previous < Backoff)
        {
            return new WatchDecision(
                WatchAction.Backoff,
                "ניסיון הפעלה קודם היה זה עתה.");
        }

        return new WatchDecision(WatchAction.Start, "השירות נעצר. מופעל מחדש.");
    }
}
