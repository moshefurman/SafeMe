using SafeMe.Core.Integrity;
using Xunit;

namespace SafeMe.Tests;

/// <summary>
/// שחזור מה שקרה למחשב בזמן שהסוכן לא פעל.
///
/// התרחיש המרכזי כאן הוא ההשבתה המכוונת: מקריסים את המחשב, מנטרלים
/// את התוכנה, גולשים, מקריסים שוב, ומחזירים. מהפעימות זה נראה כמו
/// שתי נפילות חשמל — ומיומן האירועים זה נראה כמו מה שהיה באמת.
/// </summary>
public class PowerTimelineTests
{
    private static readonly DateTimeOffset Day =
        new(2026, 8, 27, 0, 0, 0, TimeSpan.Zero);

    private static DateTimeOffset At(int hour, int minute = 0) =>
        Day.AddHours(hour).AddMinutes(minute);

    private static PowerEvent Ev(PowerEventKind kind, int hour, int minute = 0) =>
        new(At(hour, minute), kind);

    // ─────────────────────────────────────────── מה שתקין

    /// <summary>
    /// לילה רגיל: המחשב כובה ב-22:00, נדלק ב-07:00. הסוכן שתק תשע
    /// שעות, ובצדק. אין מה לדווח.
    /// </summary>
    [Fact]
    public void כיבוי_לילה_רגיל_אינו_פער()
    {
        var events = new[]
        {
            Ev(PowerEventKind.CleanShutdown, 22),
            Ev(PowerEventKind.Boot, 31), // 07:00 למחרת
        };

        var gaps = PowerTimeline.FindGaps(events, At(21, 58), At(31, 2));

        Assert.Empty(gaps);
    }

    /// <summary>
    /// נפילת חשמל אמיתית: המחשב נפל וחזר. הוא היה כבוי כל הזמן,
    /// ולכן אין חלון שבו הוא היה דלוק בלי הסוכן.
    /// </summary>
    [Fact]
    public void נפילת_חשמל_אמיתית_אינה_פער()
    {
        var events = new[]
        {
            Ev(PowerEventKind.UnexpectedShutdown, 14),
            Ev(PowerEventKind.Boot, 16),
        };

        var gaps = PowerTimeline.FindGaps(events, At(13, 58), At(16, 2));

        Assert.Empty(gaps);
    }

    /// <summary>אתחול רגיל אורך דקות. הסבילות בשוליים בולעת אותו.</summary>
    [Fact]
    public void אתחול_קצר_אינו_פער()
    {
        var events = new[]
        {
            Ev(PowerEventKind.CleanShutdown, 10),
            Ev(PowerEventKind.Boot, 10, 3),
        };

        var gaps = PowerTimeline.FindGaps(events, At(9, 58), At(10, 6));

        Assert.Empty(gaps);
    }

    // ─────────────────────────────────────────── מה שאינו תקין

    /// <summary>
    /// התרחיש המלא. הסוכן דיווח לאחרונה ב-21:38. מקריסים ב-21:40,
    /// המחשב עולה ב-21:41 בלי הסוכן, שעתיים של גלישה, מקריסים שוב
    /// ב-23:55, והסוכן חוזר ב-23:58.
    ///
    /// מהפעימות: שתי נפילות חשמל.
    /// מהיומן: שעתיים שבהן המחשב היה דלוק ואיש לא דיווח.
    /// </summary>
    [Fact]
    public void השבתה_בין_שתי_קריסות_מתגלה()
    {
        var events = new[]
        {
            Ev(PowerEventKind.UnexpectedShutdown, 21, 40),
            Ev(PowerEventKind.Boot, 21, 41),
            Ev(PowerEventKind.UnexpectedShutdown, 23, 55),
            Ev(PowerEventKind.Boot, 23, 56),
        };

        var gaps = PowerTimeline.FindGaps(events, At(21, 38), At(23, 58));

        var gap = Assert.Single(gaps);

        Assert.True(gap.Duration > TimeSpan.FromHours(2));
        Assert.True(gap.BracketedByCrashes, "שתי הקריסות מקיפות את החלון");

        var text = PowerTimeline.Describe(gap, TimeZoneInfo.Utc);

        Assert.Contains("לא פעל", text);
        Assert.Contains("כפויים", text);
    }

    /// <summary>
    /// ניטרול השירות בלי לכבות את המחשב: אין קריסות בכלל, רק חלון
    /// שקט בזמן שהמחשב רץ ברציפות.
    /// </summary>
    [Fact]
    public void ניטרול_בלי_כיבוי_מתגלה()
    {
        var events = new[]
        {
            Ev(PowerEventKind.Boot, 8),
            Ev(PowerEventKind.ServiceConfigChanged, 15, 10),
        };

        var gaps = PowerTimeline.FindGaps(events, At(15), At(18));

        var gap = Assert.Single(gaps);

        Assert.False(gap.BracketedByCrashes);
        Assert.True(gap.ServiceReconfigured, "שינוי הגדרת השירות נרשם בחלון");
        Assert.Contains("הגדרת השירות", PowerTimeline.Describe(gap, TimeZoneInfo.Utc));
    }

    /// <summary>
    /// ניקוי היומן אינו מסתיר את הפער — הוא מוסיף לו.
    /// </summary>
    [Fact]
    public void ניקוי_היומן_מתועד_בפער()
    {
        var events = new[]
        {
            Ev(PowerEventKind.Boot, 9),
            Ev(PowerEventKind.LogCleared, 12),
        };

        var gaps = PowerTimeline.FindGaps(events, At(11), At(14));

        var gap = Assert.Single(gaps);

        Assert.True(gap.LogCleared);
        Assert.Contains("נוקה", PowerTimeline.Describe(gap, TimeZoneInfo.Utc));
    }

    /// <summary>
    /// הדלקה בזמן שחלון פתוח פירושה שהכיבוי לא נרשם — למשל כי מישהו
    /// ניקה חלק מהיומן. החלון נסגר בהדלקה, ולא בולע את הפער.
    /// </summary>
    [Fact]
    public void כיבוי_חסר_אינו_בולע_את_הפער()
    {
        var events = new[]
        {
            Ev(PowerEventKind.Boot, 8),
            Ev(PowerEventKind.Boot, 14), // ההדלקה השנייה, בלי כיבוי ביניהן
        };

        var gaps = PowerTimeline.FindGaps(events, At(9), At(16));

        Assert.NotEmpty(gaps);
        Assert.True(gaps.Sum(g => g.Duration.TotalHours) > 4);
    }

    // ─────────────────────────────────────────── מקרי קצה

    [Fact]
    public void בלי_אירועים_אין_פער()
    {
        Assert.Empty(PowerTimeline.FindGaps([], At(10), At(12)));
    }

    [Fact]
    public void חלון_קצר_מהסבילות_אינו_נבדק()
    {
        var events = new[] { Ev(PowerEventKind.Boot, 8) };

        Assert.Empty(PowerTimeline.FindGaps(events, At(10), At(10, 5)));
    }

    /// <summary>סדר האירועים ביומן אינו מובטח, והמיון הוא באחריותנו.</summary>
    [Fact]
    public void סדר_האירועים_אינו_משנה()
    {
        var shuffled = new[]
        {
            Ev(PowerEventKind.Boot, 23, 56),
            Ev(PowerEventKind.UnexpectedShutdown, 21, 40),
            Ev(PowerEventKind.UnexpectedShutdown, 23, 55),
            Ev(PowerEventKind.Boot, 21, 41),
        };

        var gaps = PowerTimeline.FindGaps(shuffled, At(21, 38), At(23, 58));

        var gap = Assert.Single(gaps);

        Assert.True(gap.BracketedByCrashes);
    }

    /// <summary>פער קצר מהמינימום הוא רעש ולא מדווח.</summary>
    [Fact]
    public void פער_קצר_מהמינימום_אינו_מדווח()
    {
        var events = new[] { Ev(PowerEventKind.Boot, 8) };

        // חלון של 12 דקות, שממנו נותרות 2 אחרי הסבילות משני הצדדים
        Assert.Empty(PowerTimeline.FindGaps(events, At(10), At(10, 12)));
    }
    /// <summary>
    /// פער שחוצה יום חייב לשאת תאריך. בלי זה "בין 23:00 ל-02:00"
    /// נראה כאילו ההתחלה מאוחרת מהסוף.
    /// </summary>
    [Fact]
    public void פער_שחוצה_יום_מציג_תאריך()
    {
        var events = new[] { Ev(PowerEventKind.Boot, 20) };

        var gaps = PowerTimeline.FindGaps(events, At(22), At(28)); // עד 04:00 למחרת

        var text = PowerTimeline.Describe(Assert.Single(gaps), TimeZoneInfo.Utc);

        Assert.Contains("/", text);
        Assert.DoesNotContain("בין", text);
    }

    /// <summary>פער בתוך אותו יום נשאר קצר וקריא.</summary>
    [Fact]
    public void פער_באותו_יום_בלי_תאריך()
    {
        var events = new[] { Ev(PowerEventKind.Boot, 8) };

        var gaps = PowerTimeline.FindGaps(events, At(10), At(14));

        var text = PowerTimeline.Describe(Assert.Single(gaps), TimeZoneInfo.Utc);

        Assert.Contains("בין", text);
    }
}