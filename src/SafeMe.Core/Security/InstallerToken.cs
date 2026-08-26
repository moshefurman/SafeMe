using System.Text.RegularExpressions;

namespace SafeMe.Core.Security;

/// <summary>
/// חילוץ אסימון ההתקנה משם קובץ המתקין.
///
/// הרעיון: המשתמש מוריד מהאתר קובץ בשם
/// SafeMe-Setup-ENR-XXXXXXXX....exe, והמתקין קורא את שם הקובץ של
/// עצמו כדי לדעת לאיזה חשבון להתחבר. כך אין צורך לבנות מתקין נפרד
/// לכל לקוח — קובץ אחד חתום משרת את כולם, וההתאמה האישית היא שורה
/// בשרת בלבד.
///
/// שינוי שם קובץ אינו פוגע בחתימת Authenticode: החתימה מכסה את
/// תוכן הקובץ ולא את שמו. זה מה שהופך את השיטה לאפשרית.
///
/// מה שצריך לזכור: האסימון גלוי בשם הקובץ, ולכן מי שמקבל את הקובץ
/// יכול לרשום מכשיר לחשבון. ההגנה על כך אינה כאן אלא בשרת — מספר
/// שימושים מוגבל, תוקף קצר, והתראה לבעל החשבון על כל רישום.
/// </summary>
public static partial class InstallerToken
{
    /// <summary>הקידומת שמסמנת אסימון בשם הקובץ.</summary>
    public const string Prefix = "ENR-";

    /// <summary>אורך החלק ההקסדצימלי, כפי שהשרת מנפיק.</summary>
    public const int BodyLength = 24;

    /*
     * הביטוי דורש שהאסימון יהיה מוקף בגבול שאינו הקסדצימלי, כדי
     * שרצף ארוך יותר לא ייחתך באמצע ויתקבל כאסימון תקין.
     *
     * IgnoreCase כי חלק ממערכות הקבצים ומהדפדפנים משנים רישיות,
     * והשרת ממילא מגבב את האסימון אחרי המרה לאותיות גדולות.
     */
    [GeneratedRegex(
        @"(?<![0-9A-Fa-f])ENR-([0-9A-Fa-f]{24})(?![0-9A-Fa-f])",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TokenPattern();

    /// <summary>
    /// מחלץ אסימון משם קובץ, או null אם אין בו אסימון תקין.
    ///
    /// מקבל נתיב מלא או שם קובץ בלבד. סובל את מה שדפדפנים ומערכות
    /// הפעלה עושים לשמות: סיומת כפילות בהורדה חוזרת, רווחים,
    /// וסוגריים.
    /// </summary>
    public static string? FromFileName(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;

        string name;

        try
        {
            name = Path.GetFileName(path.Trim());
        }
        catch (ArgumentException)
        {
            // נתיב עם תווים לא חוקיים. אין ממה לחלץ.
            return null;
        }

        if (string.IsNullOrEmpty(name)) return null;

        var matches = TokenPattern().Matches(name);

        // שני אסימונים בשם אחד הם מצב לא צפוי, וניחוש בין השניים
        // גרוע מסירוב: הוא היה מחבר את המכשיר לחשבון שרירותי.
        if (matches.Count != 1) return null;

        return Prefix + matches[0].Groups[1].Value.ToUpperInvariant();
    }

    /// <summary>
    /// בונה שם קובץ להורדה. משמש בצד השרת ומתועד כאן כדי ששני
    /// הצדדים של אותו הסכם יישבו במקום אחד.
    /// </summary>
    public static string ToFileName(string token, string product = "SafeMe-Setup")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        var normalized = token.Trim().ToUpperInvariant();

        if (!IsWellFormed(normalized))
            throw new ArgumentException($"אסימון בפורמט לא צפוי: {token}", nameof(token));

        return $"{product}-{normalized}.exe";
    }

    /// <summary>בודק שהאסימון בפורמט שהשרת מנפיק.</summary>
    public static bool IsWellFormed(string? token)
    {
        if (token is null) return false;

        var match = TokenPattern().Match(token.Trim());

        return match.Success
            && match.Index == 0
            && match.Length == token.Trim().Length;
    }
}
