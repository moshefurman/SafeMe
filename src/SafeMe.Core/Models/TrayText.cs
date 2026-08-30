using SafeMe.Core.Policy;

namespace SafeMe.Core.Models;

/// <summary>
/// הטקסט שההורה רואה בלי לפתוח דבר.
///
/// יושב ב-Core ולא במגש כי הוא לוגיקה טהורה — ומפני שהוא המקום
/// היחיד שנקרא בלי שביקשו אותו, ולכן דווקא הוא צריך להיות נבדק.
/// </summary>
public static class TrayText
{
    /// <summary>Windows חותך את הכיתוב על האייקון. החיתוך נעשה כאן, ובאופן צפוי.</summary>
    public const int MaxTooltip = 62;

    public static string Status(SecurityStatus status) => status switch
    {
        SecurityStatus.Safe => "מוגן",
        SecurityStatus.LowFilter => "סינון חלקי",
        SecurityStatus.Unfiltered => "אינו מסונן",
        SecurityStatus.Blocked => "חסום",
        _ => "לא ידוע"
    };

    /// <summary>
    /// מה שנכתב על האייקון.
    ///
    /// שם הספק ראשון, ולא הסטטוס. "מוגן" לבדו אינו עונה על השאלה
    /// שההורה שואל כשהוא מרחף מעל האייקון — הוא רוצה לדעת דרך מה
    /// המחשב יוצא, ואם זה מה שהוא הגדיר.
    ///
    /// המקום קצוב, ולכן הסדר כאן הוא סדר החשיבות: מה שנחתך ראשון
    /// הוא הפרט הפחות חשוב.
    /// </summary>
    public static string Tooltip(StatusSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var head = snapshot.ProviderDisplayName ?? snapshot.ProviderId;

        var first = head is null
            ? $"SafeMe · {Status(snapshot.Status)}"
            : $"SafeMe · {head}";

        var second = head is null ? snapshot.Headline : LevelLine(snapshot);

        var tooltip = string.IsNullOrWhiteSpace(second)
            ? first
            : first + "\n" + second;

        return tooltip.Length > MaxTooltip ? tooltip[..MaxTooltip] : tooltip;
    }

    /// <summary>
    /// השורה השנייה: המצב, ואיתו הרמה כשהיא ידועה.
    ///
    /// הרמה היא מה שמבדיל בין "מסונן" לבין "מסונן כמו שהגדרתי".
    /// העקיפה שקשה לתפוס אינה ניתוק הסינון אלא החלשתו בשקט, והמספר
    /// הזה הוא מה שהופך אותה לנראית.
    /// </summary>
    private static string LevelLine(StatusSnapshot snapshot)
    {
        var status = Status(snapshot.Status);

        if (snapshot.FilterLevel is not { Account: { } account }) return status;

        return $"{status} · רמה {account} ({Strictness(account)})";
    }

    /// <summary>
    /// השורה התחתונה בתג הצף: מי מסנן, ובאיזו דרגה.
    ///
    /// זהו הטקסט היחיד שנמצא על המסך כל הזמן, בלי ריחוף ובלי לחיצה,
    /// ולכן הוא ההודעה שהמוצר מוסר לאורך היום.
    ///
    /// הוא הראה את הציון, שהוא המספר הפחות מעניין מבין השלושה: הוא
    /// אומר כמה מהבדיקות שלנו עברו. הדרגה אומרת כמה הספק עצמו
    /// מחמיר — וזה מה שההורה הגדיר ומה שהוא בא לוודא.
    ///
    /// הדרגה מצטרפת לשם ואינה מחליפה אותו. "רמה -30" לבדה אינה
    /// אומרת דבר בלי לדעת של מי.
    /// </summary>
    public static string BadgeDetail(StatusSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var name = snapshot.ProviderDisplayName ?? snapshot.ProviderId;

        var level = snapshot.FilterLevel is { Account: { } account }
            ? $"רמה {account}"
            : null;

        return snapshot.Status switch
        {
            SecurityStatus.Safe or SecurityStatus.LowFilter when name is not null =>
                level is null ? name : $"{name} · {level}",

            // בלי ספק מזוהה אין מה לצרף, והציון הוא כל מה שיש
            SecurityStatus.Safe => $"ציון {snapshot.Score}",
            SecurityStatus.LowFilter => $"ציון {snapshot.Score} מתוך 100",

            SecurityStatus.Unfiltered => "החיבור אינו מוגן",
            SecurityStatus.Blocked => "נעילה פעילה",
            _ => "אין קשר לשירות"
        };
    }

    /// <summary>
    /// המספרים שליליים ולא אינטואיטיביים — נמוך יותר מחמיר יותר —
    /// ולכן הם מוצגים עם השם ולא לבדם.
    /// </summary>
    public static string Strictness(int account) => account switch
    {
        <= -40 => "מחמירה מאוד",
        <= -25 => "מחמירה",
        <= -10 => "בינונית",
        < 0 => "מקלה",
        _ => "מקלה מאוד",
    };
}
