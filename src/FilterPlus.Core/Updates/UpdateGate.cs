using FilterPlus.Core.Models;

namespace FilterPlus.Core.Updates;

/// <summary>למה הצעת עדכון נדחתה. null פירושו שהיא מקובלת.</summary>
public enum UpdateRejection
{
    None = 0,
    Expired,
    WrongDevice,
    NotNewer,
    BadVersion,
    BadUrl,
    BadDigest,
    TooLarge,
}

public sealed record UpdateVerdict(bool Accepted, UpdateRejection Reason, string Explanation);

/// <summary>
/// השער שלפני הרצת עדכון.
///
/// עדכון הוא הרצת קוד שרירותי בהרשאות SYSTEM על מחשב מוגן — הסמכות
/// החזקה ביותר במוצר, חזקה מהסרה. החתימה מוכיחה שהשרת שלנו הנפיק
/// את ההצעה; המחלקה הזו בודקת שגם התוכן שלה שפוי.
///
/// היא טהורה במכוון: אין בה רשת ואין בה מערכת קבצים, ולכן אפשר
/// לבדוק כל צירוף בלי מכונה ובלי שרת.
/// </summary>
public static class UpdateGate
{
    /// <summary>תקרת גודל. גרסה גדולה מזה היא סימן לתקלה, לא לגרסה.</summary>
    public const long MaxBytes = 300L * 1024 * 1024;

    /// <summary>
    /// סטייה מותרת בשעון.
    ///
    /// שעון מקומי שזז בכמה דקות הוא מצב רגיל לחלוטין, ודחייה בגללו
    /// הייתה משביתה עדכונים במחשבים שלמים בלי סיבה. חמש דקות מספיקות
    /// לסטייה טבעית וקצרות מכדי להאריך הצעה באופן משמעותי.
    /// </summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>
    /// האם מותר לפעול לפי ההצעה.
    ///
    /// הבדיקות מסודרות מהזולה ליקרה, ומהמסוכנת לפחות מסוכנת: קודם
    /// למי ההצעה נועדה, ורק אז מה היא מציעה.
    /// </summary>
    public static UpdateVerdict Evaluate(
        UpdateOffer offer,
        string currentVersion,
        string hwidHash,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(offer);

        /*
         * המחשב קודם.
         *
         * הצעה שנלכדה ברשת ונשלחה למחשב אחר היא הצורה הפשוטה
         * ביותר של התקפה כאן, והבדיקה הזו עולה השוואת מחרוזות.
         */
        if (!string.Equals(offer.HwidHash, hwidHash, StringComparison.OrdinalIgnoreCase))
        {
            return new UpdateVerdict(false, UpdateRejection.WrongDevice,
                "ההצעה נועדה למחשב אחר.");
        }

        if (now > offer.ExpiresUtc + ClockSkew)
        {
            return new UpdateVerdict(false, UpdateRejection.Expired,
                $"תוקף ההצעה פג ב-{offer.ExpiresUtc:u}.");
        }

        /*
         * הצעה "מהעתיד" נדחית גם היא.
         *
         * היא אינה בהכרח זדונית — שעון שזז אחורה מייצר אותה — אבל
         * קבלתה הייתה מרחיבה את חלון החיים של כל הצעה שנלכדה.
         */
        if (offer.IssuedUtc - ClockSkew > now)
        {
            return new UpdateVerdict(false, UpdateRejection.Expired,
                "ההצעה נחתמה בעתיד. ייתכן שהשעון אינו מסונכרן.");
        }

        // ---- מה שמוצע ----

        if (!TryParse(offer.Version, out var offered))
        {
            return new UpdateVerdict(false, UpdateRejection.BadVersion,
                $"מספר גרסה לא תקין: {offer.Version}");
        }

        if (!TryParse(currentVersion, out var current))
        {
            return new UpdateVerdict(false, UpdateRejection.BadVersion,
                $"הגרסה הנוכחית אינה קריאה: {currentVersion}");
        }

        /*
         * ירידת גרסה נדחית.
         *
         * זו ההגנה מפני החזרת המחשב לגרסה ישנה עם פגם ידוע — התקפה
         * שאינה דורשת לפרוץ לשרת אלא רק לשמור הצעה ישנה ולשדר אותה
         * שוב. השרת בודק זאת גם הוא; כאן זה נבדק שוב, כי הסוכן אינו
         * אמור לסמוך על כך שהשרת לא נפרץ.
         */
        if (Compare(offered, current) <= 0)
        {
            return new UpdateVerdict(false, UpdateRejection.NotNewer,
                $"הגרסה המוצעת {offer.Version} אינה חדשה מ-{currentVersion}.");
        }

        // ---- מה שיורד ----

        if (!IsHttps(offer.DownloadUrl))
        {
            return new UpdateVerdict(false, UpdateRejection.BadUrl,
                "כתובת ההורדה אינה https.");
        }

        // 64 תווים הקסדצימליים. גיבוב שאינו בצורה הזו לא יתאים
        // לעולם, וההורדה כולה תהיה בזבוז.
        if (offer.Sha256.Length != 64 || !IsHex(offer.Sha256))
        {
            return new UpdateVerdict(false, UpdateRejection.BadDigest,
                "גיבוב הקובץ אינו תקין.");
        }

        if (offer.SizeBytes <= 0 || offer.SizeBytes > MaxBytes)
        {
            return new UpdateVerdict(false, UpdateRejection.TooLarge,
                $"גודל חריג: {offer.SizeBytes} בתים.");
        }

        return new UpdateVerdict(true, UpdateRejection.None,
            $"עדכון ל-{offer.Version}.");
    }

    // ---------------------------------------------------------------- עזר

    /// <summary>
    /// השוואת גרסאות לפי רכיבים.
    ///
    /// לא כמחרוזת: "1.10.0" קטן מ-"1.9.0" לקסיקוגרפית, וזה בדיוק
    /// ההפך מהנכון.
    /// </summary>
    public static int Compare((int Major, int Minor, int Patch) a, (int Major, int Minor, int Patch) b)
    {
        if (a.Major != b.Major) return a.Major.CompareTo(b.Major);
        if (a.Minor != b.Minor) return a.Minor.CompareTo(b.Minor);

        return a.Patch.CompareTo(b.Patch);
    }

    public static bool TryParse(string? value, out (int Major, int Minor, int Patch) parsed)
    {
        parsed = default;

        if (string.IsNullOrWhiteSpace(value)) return false;

        var parts = value.Trim().Split('.');

        if (parts.Length != 3) return false;

        if (!int.TryParse(parts[0], out var major) || major < 0) return false;
        if (!int.TryParse(parts[1], out var minor) || minor < 0) return false;
        if (!int.TryParse(parts[2], out var patch) || patch < 0) return false;

        parsed = (major, minor, patch);

        return true;
    }

    private static bool IsHttps(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var uri)
           && uri.Scheme == Uri.UriSchemeHttps;

    private static bool IsHex(string value)
    {
        foreach (var c in value)
        {
            var ok = c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';

            if (!ok) return false;
        }

        return true;
    }
}
