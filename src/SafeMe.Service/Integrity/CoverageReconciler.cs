using System.Runtime.Versioning;

using Microsoft.Extensions.Logging;

using SafeMe.Core.Integrity;
using SafeMe.Core.Models;
using SafeMe.Service.State;
using SafeMe.Service.Workers;

namespace SafeMe.Service.Integrity;

/// <summary>
/// משווה, בכל עלייה, בין מה שהסוכן דיווח לבין מה שקרה למחשב בפועל.
///
/// זו הפעולה היחידה במערכת שמתעדת תקופה שבה התוכנה **לא** פעלה. כל
/// שאר האירועים נרשמים בזמן שהיא כן פעלה, ולכן הם עיוורים בדיוק
/// לתרחיש שחשוב לתפוס: השבתה מכוונת בין שתי קריסות.
///
/// רץ פעם אחת, בעלייה, ולפני שהסוכן מספיק לדווח שוב. מהרגע שהוא
/// מדווח, הפער ייסגר ולא יהיה מה לגלות.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CoverageReconciler
{
    /// <summary>
    /// כמה אחורה לחפש.
    ///
    /// מחשב שהיה כבוי חודש אינו אמור לייצר מפולת אירועים בעלייה,
    /// והפער שמעניין הוא זה שקרוב בזמן. שבועיים מכסים חופשה.
    /// </summary>
    private static readonly TimeSpan LookBack = TimeSpan.FromDays(14);

    /// <summary>
    /// תקרת דיווח בהרצה אחת.
    ///
    /// יומן פגום או שעון שהשתבש עלולים לייצר עשרות חלונות. עדיף
    /// לדווח על הגדולים ולציין שהיו נוספים, מאשר להציף את ההורה.
    /// </summary>
    private const int MaxReported = 5;

    private readonly ILogger<CoverageReconciler> _log;
    private readonly EventLogPowerReader _reader;
    private readonly DeviceStateStore _deviceStore;
    private readonly EventQueue _events;

    public CoverageReconciler(
        ILogger<CoverageReconciler> log,
        EventLogPowerReader reader,
        DeviceStateStore deviceStore,
        EventQueue events)
    {
        _log = log;
        _reader = reader;
        _deviceStore = deviceStore;
        _events = events;
    }

    /// <summary>
    /// מריץ פיוס אחד ומדווח את הפערים שנמצאו.
    /// מחזיר את מספר הפערים, לצורכי יומן ובדיקה.
    /// </summary>
    public int Reconcile(DateTimeOffset? nowUtc = null)
    {
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        var state = _deviceStore.Load();

        var lastReport = state.LastServerContactUtc;

        if (lastReport is null)
        {
            // התקנה טרייה. אין מה להשוות מולו, וכל היומן שקדם להתקנה
            // אינו מעניינו.
            _log.LogDebug("אין דיווח קודם, מדלג על פיוס.");
            return 0;
        }

        // שעון שזז אחורה, או מצב שנשמר מעתיד. אין מה להסיק מזה.
        if (lastReport > now)
        {
            _log.LogWarning("הדיווח האחרון מאוחר מהזמן הנוכחי. מדלג על פיוס.");
            return 0;
        }

        var since = lastReport.Value < now - LookBack ? now - LookBack : lastReport.Value;
        var events = _reader.Read(since);

        if (events.Count == 0)
        {
            // היעדר ראיה אינו ראיה. יומן ריק פירושו שלא ניתן לקרוא
            // אותו, או שלא קרה דבר — ואין להאשים על סמך זה.
            _log.LogDebug("לא נמצאו אירועי הפעלה מאז {Since}.", since);
            return 0;
        }

        var gaps = PowerTimeline.FindGaps(events, lastReport.Value, now);

        if (gaps.Count == 0)
        {
            _log.LogInformation(
                "פיוס הושלם: {Count} אירועים, אין תקופות ללא כיסוי.", events.Count);

            return 0;
        }

        var ordered = gaps.OrderByDescending(g => g.Duration).ToList();

        foreach (var gap in ordered.Take(MaxReported))
        {
            var detail = PowerTimeline.Describe(gap);

            _log.LogWarning("תקופה ללא כיסוי: {Detail}", detail);

            _events.Enqueue(new TamperEvent
            {
                Kind = TamperKind.CoverageGap,
                Utc = gap.From,
                Detail = detail,
            });
        }

        if (ordered.Count > MaxReported)
        {
            _events.Enqueue(new TamperEvent
            {
                Kind = TamperKind.CoverageGap,
                Utc = now,
                Detail = $"נמצאו עוד {ordered.Count - MaxReported} תקופות ללא כיסוי "
                    + "שלא פורטו. ייתכן שיומן האירועים או שעון המערכת שובשו.",
            });
        }

        return ordered.Count;
    }
}
