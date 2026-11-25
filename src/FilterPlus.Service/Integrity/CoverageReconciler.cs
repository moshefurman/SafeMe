using System.Runtime.Versioning;

using Microsoft.Extensions.Logging;

using FilterPlus.Core.Integrity;
using FilterPlus.Core.Models;
using FilterPlus.Service.State;
using FilterPlus.Service.Workers;

namespace FilterPlus.Service.Integrity;

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

    /// <summary>
    /// מדווח על עצירות שירות שנרשמו בזמן שהסוכן לא פעל.
    ///
    /// אינו מבדיל בין עצירה מכוונת לכיבוי מחשב, ובכוונה: השירות
    /// אמור לעלות עם המערכת ולרדת איתה, וכיבוי מסודר מותיר גם
    /// אירוע כיבוי לצדו. ההורה רואה את שניהם ואת סדר הזמנים, וזה
    /// מספיק כדי להבחין.
    ///
    /// ניסיון לנחש כאן היה גרוע יותר: החמצה של עצירה אמיתית עולה
    /// הרבה יותר מדיווח על עצירה שהייתה לגיטימית.
    /// </summary>
    private void ReportServiceStops(DateTimeOffset since)
    {
        try
        {
            var stops = new ServiceStopReader(_log).StopsSince(since);

            foreach (var stop in stops.Take(MaxReported))
            {
                var detail =
                    $"השירות {stop.Service} נעצר ב-{stop.WhenUtc.ToLocalTime():HH:mm dd/MM} "
                    + "בזמן שהסוכן לא פעל.";

                _log.LogWarning("{Detail}", detail);

                _events.Enqueue(new TamperEvent
                {
                    Kind = TamperKind.ServiceStopAttempt,
                    Utc = stop.WhenUtc,
                    Detail = detail,
                });
            }

            if (stops.Count > MaxReported)
            {
                _events.Enqueue(new TamperEvent
                {
                    Kind = TamperKind.ServiceStopAttempt,
                    Detail = $"ועוד {stops.Count - MaxReported} עצירות שירות באותה תקופה.",
                });
            }
        }
        catch (Exception ex)
        {
            // כלי גילוי, לא תנאי
            _log.LogWarning(ex, "איתור עצירות שירות נכשל.");
        }
    }

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

        /*
         * מה שקרה לשירותים בזמן שלא היינו.
         *
         * כל שאר ההגנות פועלות בזמן שהסוכן חי. ברגע שהוא עצור אין
         * מי שיבחין בדבר — וזה בדיוק החלון שמעניין את מי שמנסה.
         *
         * מנהל השירותים של Windows רושם כל שינוי מצב ביומן המערכת,
         * בין אם הסוכן פועל ובין אם לא. כלומר העדות קיימת גם על
         * התקופה הזו, וצריך רק לקרוא אותה.
         */
        ReportServiceStops(since);

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
