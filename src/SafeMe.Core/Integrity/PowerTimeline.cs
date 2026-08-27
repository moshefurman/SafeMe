namespace SafeMe.Core.Integrity;

/// <summary>סוג אירוע במעברי ההפעלה של המחשב.</summary>
public enum PowerEventKind
{
    /// <summary>המחשב נדלק. יומן האירועים עלה (6005).</summary>
    Boot = 0,

    /// <summary>כיבוי מסודר (6006 / 1074).</summary>
    CleanShutdown = 1,

    /// <summary>
    /// כיבוי לא צפוי (6008 / Kernel-Power 41).
    ///
    /// החותמת היא הזמן שבו הסשן הקודם נפסק בפועל, ולא הזמן שבו
    /// האירוע נרשם — Windows רושם אותו רק בהדלקה הבאה.
    /// </summary>
    UnexpectedShutdown = 2,

    /// <summary>סוג ההפעלה של שירות שונה (7040).</summary>
    ServiceConfigChanged = 3,

    /// <summary>יומן האירועים נוקה (1102).</summary>
    LogCleared = 4,
}

public sealed record PowerEvent(DateTimeOffset Utc, PowerEventKind Kind);

/// <summary>חלון שבו המחשב היה דלוק והסוכן לא דיווח.</summary>
public sealed record CoverageGap
{
    public required DateTimeOffset From { get; init; }
    public required DateTimeOffset To { get; init; }

    public TimeSpan Duration => To - From;

    /// <summary>
    /// החלון נפתח בכיבוי לא צפוי ונסגר בכיבוי לא צפוי.
    ///
    /// זו החתימה של השבתה מכוונת: מקריסים כדי להיפטר מהסוכן,
    /// משתמשים, ומקריסים שוב כדי להחזיר אותו. שתי נפילות חשמל
    /// שמקיפות בדיוק את הזמן שבו התוכנה לא פעלה אינן צירוף מקרים.
    /// </summary>
    public bool BracketedByCrashes { get; init; }

    /// <summary>סוג ההפעלה של שירות שונה בתוך החלון.</summary>
    public bool ServiceReconfigured { get; init; }

    /// <summary>יומן האירועים נוקה בתוך החלון.</summary>
    public bool LogCleared { get; init; }
}

/// <summary>
/// משחזר מה קרה למחשב בזמן שהסוכן לא פעל.
///
/// כשהסוכן מושבת, Windows ממשיך לרשום. יומן האירועים הוא העד היחיד
/// ששורד את ההשבתה, ולכן ההשוואה בין מה שהוא מתעד לבין מה שהסוכן
/// דיווח היא הראיה.
///
/// התרחיש שזה נבנה בשבילו: מקריסים את המחשב, מנטרלים את התוכנה,
/// גולשים, מקריסים שוב, ומחזירים. משתי הפעימות זה נראה כמו שתי
/// נפילות חשמל. מיומן האירועים זה נראה כמו שעתיים שבהן המחשב היה
/// דלוק ואיש לא דיווח.
///
/// המחלקה טהורה ואינה נוגעת ב-Windows, כדי שתהיה נבדקת.
/// </summary>
public static class PowerTimeline
{
    /// <summary>
    /// סבילות לקצוות.
    ///
    /// הסוכן עולה שניות אחרי ההדלקה, והפעימה האחרונה לפני כיבוי היא
    /// עד שלוש דקות לפניו. בלי סבילות כל אתחול רגיל היה מדווח כפער.
    /// </summary>
    public static readonly TimeSpan EdgeTolerance = TimeSpan.FromMinutes(5);

    /// <summary>פער קצר מזה אינו מדווח. רעש, לא חבלה.</summary>
    public static readonly TimeSpan MinimumGap = TimeSpan.FromMinutes(10);

    /// <summary>
    /// מוצא חלונות שבהם המחשב היה דלוק והסוכן שתק.
    /// </summary>
    /// <param name="events">אירועי הפעלה מהיומן, בכל סדר.</param>
    /// <param name="lastAgentReport">מתי הסוכן דיווח לאחרונה.</param>
    /// <param name="now">הרגע הנוכחי, בדרך כלל עליית הסוכן.</param>
    public static IReadOnlyList<CoverageGap> FindGaps(
        IEnumerable<PowerEvent> events,
        DateTimeOffset lastAgentReport,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(events);

        var ordered = events.OrderBy(e => e.Utc).ToList();

        // חלון החקירה: מהדיווח האחרון ועד עכשיו, מקוצץ בשוליים
        var windowStart = lastAgentReport + EdgeTolerance;
        var windowEnd = now - EdgeTolerance;

        if (windowEnd <= windowStart) return [];

        var gaps = new List<CoverageGap>();

        foreach (var (upFrom, upTo) in PoweredIntervals(ordered, now))
        {
            var from = upFrom > windowStart ? upFrom : windowStart;
            var to = upTo < windowEnd ? upTo : windowEnd;

            if (to - from < MinimumGap) continue;

            gaps.Add(new CoverageGap
            {
                From = from,
                To = to,
                BracketedByCrashes =
                    EndedUnexpectedlyAt(ordered, upFrom) && EndsUnexpectedly(ordered, upTo),
                ServiceReconfigured = Any(ordered, PowerEventKind.ServiceConfigChanged, from, to),
                LogCleared = Any(ordered, PowerEventKind.LogCleared, from, to),
            });
        }

        return gaps;
    }

    /// <summary>
    /// בונה את החלונות שבהם המחשב היה דלוק.
    ///
    /// הדלקה פותחת חלון, כיבוי סוגר. חלון שנפתח ולא נסגר נמשך עד
    /// עכשיו — זה המצב הרגיל בזמן שהמחשב פועל.
    /// </summary>
    private static List<(DateTimeOffset From, DateTimeOffset To)> PoweredIntervals(
        List<PowerEvent> ordered,
        DateTimeOffset now)
    {
        var intervals = new List<(DateTimeOffset, DateTimeOffset)>();
        DateTimeOffset? openedAt = null;

        foreach (var e in ordered)
        {
            switch (e.Kind)
            {
                case PowerEventKind.Boot:
                    // הדלקה בזמן שחלון פתוח פירושה שהכיבוי הקודם לא
                    // נרשם. סוגרים בזמן ההדלקה כדי לא לבלוע את הפער.
                    if (openedAt is not null) intervals.Add((openedAt.Value, e.Utc));

                    openedAt = e.Utc;
                    break;

                case PowerEventKind.CleanShutdown:
                case PowerEventKind.UnexpectedShutdown:
                    if (openedAt is not null)
                    {
                        intervals.Add((openedAt.Value, e.Utc));
                        openedAt = null;
                    }

                    break;
            }
        }

        if (openedAt is not null) intervals.Add((openedAt.Value, now));

        return intervals;
    }

    private static bool Any(
        List<PowerEvent> ordered,
        PowerEventKind kind,
        DateTimeOffset from,
        DateTimeOffset to) =>
        ordered.Any(e => e.Kind == kind && e.Utc >= from && e.Utc <= to);

    /// <summary>האם החלון שנסגר ב-at הסתיים בכיבוי לא צפוי.</summary>
    private static bool EndsUnexpectedly(List<PowerEvent> ordered, DateTimeOffset at) =>
        ordered.Any(e => e.Kind == PowerEventKind.UnexpectedShutdown && e.Utc == at);

    /// <summary>האם החלון שנפתח ב-at בא מיד אחרי כיבוי לא צפוי.</summary>
    private static bool EndedUnexpectedlyAt(List<PowerEvent> ordered, DateTimeOffset at)
    {
        var previous = ordered
            .Where(e => e.Utc <= at
                && e.Kind is PowerEventKind.CleanShutdown or PowerEventKind.UnexpectedShutdown)
            .OrderBy(e => e.Utc)
            .LastOrDefault();

        return previous?.Kind == PowerEventKind.UnexpectedShutdown;
    }

    /// <summary>מנסח את הפער בשפה שהורה יכול להבין ולבדוק.</summary>
    public static string Describe(CoverageGap gap, TimeZoneInfo? local = null)
    {
        var zone = local ?? TimeZoneInfo.Local;

        var from = TimeZoneInfo.ConvertTime(gap.From, zone);
        var to = TimeZoneInfo.ConvertTime(gap.To, zone);

        var hours = gap.Duration.TotalHours;

        var length = hours >= 1
            ? $"{hours:0.#} שעות"
            : $"{gap.Duration.TotalMinutes:0} דקות";

        // פער שחוצה יום דורש תאריך. בלעדיו "בין 11:00 ל-10:50" נראה
        // כאילו ההתחלה מאוחרת מהסוף, וההורה מפסיק להאמין להתראה.
        var span = from.Date == to.Date
            ? $"בין {from:HH:mm} ל-{to:HH:mm}"
            : $"מ-{from:HH:mm} ב-{from:dd/MM} עד {to:HH:mm} ב-{to:dd/MM}";

        var text = $"המחשב היה פעיל {length}, {span}, ו-SafeMe לא פעל בזמן הזה.";

        if (gap.BracketedByCrashes)
            text += " הכיבויים לפני ואחרי היו כפויים.";

        if (gap.ServiceReconfigured)
            text += " הגדרת השירות שונתה באותו חלון.";

        if (gap.LogCleared)
            text += " יומן האירועים נוקה באותו חלון.";

        return text;
    }
}
