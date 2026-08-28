using System.Text.RegularExpressions;

namespace SafeMe.Core.Policy;

/// <summary>
/// רמת הסינון, כפי שהספק עצמו מדווח אותה.
///
/// זו אינה הערכה שלנו אלא ציטוט: כשרימון חוסמת דף היא מחזירה בגוף
/// התשובה את הרמה שהחשבון מוגדר בה ואת הרמה שהאתר דורש. שני מספרים
/// שאומרים בדיוק כמה הסינון מחמיר, בלי שנצטרך לנחש מבדיקות עקיפות.
///
/// למה זה חשוב מעבר לתצוגה: הורה שהגדיר רמה מחמירה ומצא אותה מוקלת
/// לא היה יודע. עכשיו השינוי נראה, וזו בדיוק הצורה של עקיפה שהמוצר
/// אמור לתפוס — לא ניתוק הסינון, אלא החלשתו בשקט.
/// </summary>
public sealed record FilterLevel
{
    /// <summary>הרמה שהחשבון מוגדר בה. נמוך יותר = מחמיר יותר.</summary>
    public int? Account { get; init; }

    /// <summary>הרמה שהיעד שנבדק דורש.</summary>
    public int? Required { get; init; }

    /// <summary>מזהה הקטגוריה שהיעד שויך אליה.</summary>
    public int? Category { get; init; }

    /// <summary>מה הספק אמר על סיבת החסימה.</summary>
    public string? Cause { get; init; }

    public bool HasAny => Account is not null || Required is not null;
}

/// <summary>
/// קורא את הרמה מדף החסימה.
///
/// הערכים נמדדו על מכונה מסוננת אמיתית: רימון מחזירה בגוף התשובה
/// מחרוזת בסגנון level=-30&amp;urllevel=-35&amp;category=41&amp;cause=url_level.
///
/// מה שהמחלקה הזו **אינה** קוראת, ובמכוון: user_id ו-sigid שמופיעים
/// באותה מחרוזת. הם מזהים את החשבון אצל הספק, אין בהם שום צורך
/// לתפקוד המוצר, ואיסוף מידע שאין בו צורך הוא בדיוק מה שהופך כלי
/// הגנה לכלי מעקב.
/// </summary>
public static partial class FilterLevelReader
{
    [GeneratedRegex(@"(?<![a-z])level=(-?\d{1,4})(?![0-9])", RegexOptions.IgnoreCase)]
    private static partial Regex AccountLevel();

    [GeneratedRegex(@"urllevel=(-?\d{1,4})", RegexOptions.IgnoreCase)]
    private static partial Regex RequiredLevel();

    [GeneratedRegex(@"category=(\d{1,5})", RegexOptions.IgnoreCase)]
    private static partial Regex Category();

    [GeneratedRegex(@"cause=([a-z_]{1,40})", RegexOptions.IgnoreCase)]
    private static partial Regex Cause();

    /// <summary>
    /// מחלץ מה שאפשר. מחזיר רשומה ריקה כשאין מה למצוא.
    ///
    /// אינה זורקת על שום קלט: הגוף מגיע מצד שלישי, ותקלה בפענוח
    /// אינה סיבה להפיל ביקורת שלמה.
    /// </summary>
    public static FilterLevel Read(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return new FilterLevel();

        /*
         * "urllevel" מכיל בתוכו את "level", ולכן הוא נקרא ראשון
         * והתבנית של הרמה עצמה דורשת שלא תקדם לה אות. בלי זה
         * שתי התבניות היו נלחמות על אותה מחרוזת, והתוצאה הייתה
         * תלויה בסדר ההופעה בגוף.
         */
        return new FilterLevel
        {
            Required = Number(RequiredLevel(), body),
            Account = Number(AccountLevel(), body),
            Category = Number(Category(), body),
            Cause = Text(Cause(), body),
        };
    }

    private static int? Number(Regex pattern, string body)
    {
        var match = pattern.Match(body);

        return match.Success && int.TryParse(match.Groups[1].Value, out var value)
            ? value
            : null;
    }

    private static string? Text(Regex pattern, string body)
    {
        var match = pattern.Match(body);

        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>
    /// מנסח את הרמה בשפה שהורה קורא.
    ///
    /// המספרים שליליים ולא אינטואיטיביים — נמוך יותר הוא מחמיר
    /// יותר — ולכן הם מוצגים עם ההסבר ולא לבדם.
    /// </summary>
    public static string Describe(FilterLevel level)
    {
        if (!level.HasAny) return "רמת הסינון אינה ידועה.";

        if (level.Account is not { } account) return "רמת הסינון אינה ידועה.";

        var strictness = account switch
        {
            <= -40 => "מחמירה מאוד",
            <= -25 => "מחמירה",
            <= -10 => "בינונית",
            < 0 => "מקלה",
            _ => "מקלה מאוד",
        };

        return level.Required is { } required
            ? $"רמת הסינון בחשבון: {account} ({strictness}). היעד שנבדק דורש {required}."
            : $"רמת הסינון בחשבון: {account} ({strictness}).";
    }
}
