namespace FilterPlus.Core.Models;

/// <summary>
/// מה נצפה על תג המצב ברגע נתון. נאסף ב-TrayApp, מוכרע כאן.
/// </summary>
/// <param name="IsVisible">החלון מוצג — גם לפי WPF וגם לפי Windows.</param>
/// <param name="OnCurrentDesktop">החלון שייך לשולחן העבודה הווירטואלי הנוכחי.</param>
/// <param name="InsideWorkArea">החלון כולו בתוך שטח העבודה של המסך.</param>
/// <param name="CoveredBy">
/// תיאור החלון שמכסה את מרכז התג, או null כשהתג הוא מה שנמצא שם.
/// </param>
/// <param name="CoverIsShell">
/// המכסה הוא ממשק המערכת עצמו — תפריט התחלה, חיפוש, מסך נעילה.
/// מעליהם לא מטפסים: הם מוצגים לרגע ובכוונת המשתמש.
/// </param>
public sealed record BadgeObservation(
    bool IsVisible,
    bool OnCurrentDesktop,
    bool InsideWorkArea,
    string? CoveredBy,
    bool CoverIsShell = false);

[Flags]
public enum BadgeRepair
{
    None = 0,
    Show = 1,
    MoveToCurrentDesktop = 2,
    Reposition = 4,
    RaiseAboveCover = 8
}

/// <summary>
/// ההכרעה מה לתקן בתג שנעלם.
///
/// "האייקון נעלם" הוא דיווח שחוזר, והתהליך עצמו חי בכל פעם שנבדק.
/// כלומר החלון קיים ומשהו מסתיר אותו: שולחן עבודה וירטואלי אחר,
/// חלון topmost שנפתח מעליו, שטח עבודה שהשתנה, או משטח שכבה שלא
/// צויר מחדש אחרי שינה. אף אחד מאלה אינו נרשם בשום מקום, ולכן אי
/// אפשר היה לדעת איזה מהם.
///
/// לוגיקה טהורה כאן, כדי שתיבדק; המדידה והתיקון ב-TrayApp, שאינו
/// ניתן להפניה מפרויקט הבדיקות.
/// </summary>
public static class BadgeKeeperPlan
{
    public static BadgeRepair Decide(BadgeObservation o)
    {
        ArgumentNullException.ThrowIfNull(o);

        var repair = BadgeRepair.None;

        if (!o.IsVisible) repair |= BadgeRepair.Show;
        if (!o.OnCurrentDesktop) repair |= BadgeRepair.MoveToCurrentDesktop;
        if (!o.InsideWorkArea) repair |= BadgeRepair.Reposition;

        /*
         * מעל מכסה מטפסים, מעל ממשק המערכת לא.
         *
         * חלון topmost של תוכנה אחרת שנשאר מעל התג מסתיר אותו לצמיתות
         * — הוא לעולם אינו מופעל (NOACTIVATE) ולכן שוקע לתחתית רצועת
         * ה-topmost. תפריט התחלה או מסך נעילה מכסים אותו לרגע, בכוונת
         * המשתמש, וטיפוס מעליהם היה מפריע בלי להועיל.
         */
        if (o.CoveredBy is not null && !o.CoverIsShell) repair |= BadgeRepair.RaiseAboveCover;

        return repair;
    }

    /// <summary>תיאור לרישום. הוא מה שיאפשר לענות "למה הוא נעלם" בפעם הבאה.</summary>
    public static string Describe(BadgeRepair repair, BadgeObservation o)
    {
        ArgumentNullException.ThrowIfNull(o);

        var parts = new List<string>(4);

        if (repair.HasFlag(BadgeRepair.Show)) parts.Add("החלון היה מוסתר");
        if (repair.HasFlag(BadgeRepair.MoveToCurrentDesktop)) parts.Add("היה בשולחן עבודה וירטואלי אחר");
        if (repair.HasFlag(BadgeRepair.Reposition)) parts.Add("היה מחוץ לשטח העבודה");
        if (repair.HasFlag(BadgeRepair.RaiseAboveCover)) parts.Add($"היה מכוסה על ידי {o.CoveredBy}");

        return parts.Count == 0 ? "התג במקומו" : "התג שוחזר: " + string.Join("; ", parts) + ".";
    }
}
