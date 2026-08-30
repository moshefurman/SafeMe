namespace SafeMe.Core.Browsing;

/// <summary>
/// מה שיוצא מהמחשב על גלישה. ספירה בלבד.
///
/// זו הגבלה מכוונת ולא חוסר. הכתובות והכותרות נשארות במחשב ואינן
/// עוזבות אותו לעולם — השרת יודע רק **שנחסם משהו**, ולא מה.
///
/// למה זה נאכף בטיפוס ולא בהסכמה: דיווח שנוסח נכון היום ייפרץ ביום
/// שמישהו יוסיף שדה "לצורכי אבחון". טיפוס שאין בו מקום לכתובת אינו
/// יכול לשאת אותה, וכל ניסיון להוסיף אותה נראה בבדיקת הקוד.
///
/// מה שההורה מקבל: "נחסמו שלושה ניסיונות היום". מה שהוא צריך לעשות
/// אם זה מטריד: לדבר עם הילד, לא לקרוא את ההיסטוריה שלו.
/// </summary>
public sealed record BrowsingBlockSummary
{
    /// <summary>כמה לשוניות נחסמו מאז הדיווח הקודם.</summary>
    public required int Blocked { get; init; }

    /// <summary>
    /// כמה מתוכן זוהו לפי שם המארח, ולא לפי כותרת.
    ///
    /// היחס הזה הוא איכות הזיהוי: התאמה על כותרת עלולה לטעות,
    /// והורה שרואה שכל ההתראות מבוססות כותרת יודע לקחת אותן בעירבון.
    /// </summary>
    public required int ByHost { get; init; }

    /// <summary>מתי נחסם האחרון. בלי לומר מה הוא היה.</summary>
    public DateTimeOffset? LastAtUtc { get; init; }

    public static readonly BrowsingBlockSummary Empty =
        new() { Blocked = 0, ByHost = 0 };

    /// <summary>מסכם התאמות מקומיות לדיווח שאין בו תוכן.</summary>
    public static BrowsingBlockSummary From(
        IReadOnlyList<TabMatch> matches, DateTimeOffset? lastAtUtc = null)
    {
        ArgumentNullException.ThrowIfNull(matches);

        return new BrowsingBlockSummary
        {
            Blocked = matches.Count,
            ByHost = matches.Count(m => m.ByHost),
            LastAtUtc = matches.Count == 0 ? null : lastAtUtc ?? DateTimeOffset.UtcNow,
        };
    }
}
