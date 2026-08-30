using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;

using Microsoft.Extensions.Logging;

using SafeMe.Core.Integrity;

namespace SafeMe.Service.Integrity;

/// <summary>
/// קורא את ציר ההפעלה של המחשב מיומן האירועים של Windows.
///
/// זהו העד היחיד ששורד את השבתת הסוכן: כשהשירות מת, Windows ממשיך
/// לרשום. ההשוואה בין מה שהיומן מתעד לבין מה שהסוכן דיווח היא
/// הראיה שחושפת השבתה מכוונת.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EventLogPowerReader
{
    private const string SystemLog = "System";
    private const string SecurityLog = "Security";

    /// <summary>יומן האירועים עלה — המחשב נדלק.</summary>
    private const int EventBoot = 6005;

    /// <summary>יומן האירועים נעצר — כיבוי מסודר.</summary>
    private const int EventCleanShutdown = 6006;

    /// <summary>הכיבוי הקודם היה לא צפוי. נרשם בהדלקה שאחריו.</summary>
    private const int EventDirtyShutdown = 6008;

    /// <summary>המערכת אותחלה בלי כיבוי מסודר.</summary>
    private const int EventKernelPower = 41;

    /// <summary>סוג ההפעלה של שירות שונה.</summary>
    private const int EventServiceConfig = 7040;

    /// <summary>יומן האירועים נוקה.</summary>
    private const int EventLogCleared = 1102;

    private readonly ILogger<EventLogPowerReader> _log;

    public EventLogPowerReader(ILogger<EventLogPowerReader> log) => _log = log;

    /// <summary>
    /// אוסף את אירועי ההפעלה מאז מועד נתון.
    ///
    /// מחזיר רשימה ריקה כשהיומן אינו נגיש. היעדר ראיה אינו ראיה
    /// לחבלה, ואין לדווח על פער שלא הוכח.
    /// </summary>
    public IReadOnlyList<PowerEvent> Read(DateTimeOffset since)
    {
        var events = new List<PowerEvent>();

        events.AddRange(ReadSystemLog(since));
        events.AddRange(ReadSecurityLog(since));

        return events;
    }

    private List<PowerEvent> ReadSystemLog(DateTimeOffset since)
    {
        var found = new List<PowerEvent>();

        // שאילתת XPath ולא סינון בקוד: יומן המערכת מכיל עשרות אלפי
        // רשומות, וסינון בצד שלנו היה קורא את כולן.
        var ids = string.Join(" or ", new[]
        {
            EventBoot, EventCleanShutdown, EventDirtyShutdown,
            EventKernelPower, EventServiceConfig,
        }.Select(id => $"EventID={id}"));

        var query = $"*[System[({ids}) and TimeCreated[@SystemTime>='{since.UtcDateTime:o}']]]";

        // הזמן שבו המחשב נעצר בפועל אינו נרשם באירוע 6008 בצורה
        // שאפשר לפענח בלי תלות בשפת המערכת. במקומו משמש האירוע
        // האחרון ביומן שקדם להדלקה — Windows רושם בתדירות גבוהה
        // מספיק כדי שהקירוב יהיה של דקות.
        DateTimeOffset? lastSeen = null;
        var pendingDirty = new List<DateTimeOffset>();

        foreach (var record in Query(SystemLog, query))
        {
            var at = new DateTimeOffset(record.TimeCreated!.Value.ToUniversalTime(), TimeSpan.Zero);
            var id = record.Id;

            switch (id)
            {
                case EventBoot:
                    found.Add(new PowerEvent(at, PowerEventKind.Boot));
                    break;

                case EventCleanShutdown:
                    found.Add(new PowerEvent(at, PowerEventKind.CleanShutdown));
                    lastSeen = at;
                    break;

                case EventDirtyShutdown:
                case EventKernelPower:
                    // האירוע נרשם בהדלקה. הכיבוי עצמו קרה קודם, ואת
                    // מועדו נשלים מהאירוע האחרון שקדם לו.
                    pendingDirty.Add(at);
                    break;

                case EventServiceConfig:
                    found.Add(new PowerEvent(at, PowerEventKind.ServiceConfigChanged));
                    break;
            }

            if (id != EventDirtyShutdown && id != EventKernelPower) lastSeen = at;
        }

        foreach (var reportedAt in pendingDirty)
        {
            var actual = LastActivityBefore(reportedAt) ?? reportedAt;

            found.Add(new PowerEvent(actual, PowerEventKind.UnexpectedShutdown));
        }

        return found;
    }

    private List<PowerEvent> ReadSecurityLog(DateTimeOffset since)
    {
        var query =
            $"*[System[(EventID={EventLogCleared}) and TimeCreated[@SystemTime>='{since.UtcDateTime:o}']]]";

        return Query(SecurityLog, query)
            .Select(r => new PowerEvent(
                new DateTimeOffset(r.TimeCreated!.Value.ToUniversalTime(), TimeSpan.Zero),
                PowerEventKind.LogCleared))
            .ToList();
    }

    /// <summary>
    /// מוצא את האירוע האחרון ביומן המערכת שקדם למועד נתון.
    ///
    /// זהו הקירוב הטוב ביותר לרגע שבו המחשב נעצר: Windows רושם
    /// אירועים ברציפות, והאחרון שבהם הוא הסימן האחרון לחיים.
    /// </summary>
    private DateTimeOffset? LastActivityBefore(DateTimeOffset boot)
    {
        // תו גולמי ולא ישות XML. ראה ההסבר ב-ServiceStopReader: ישות
        // כאן פוסלת את השאילתה, והכשל שקט — האירוע שקדם להדלקה פשוט
        // לא נמצא לעולם, ופיוס הכיסוי איבד את נקודת הייחוס שלו.
        var query = $"*[System[TimeCreated[@SystemTime<'{boot.UtcDateTime:o}']]]";

        try
        {
            using var reader = new EventLogReader(
                new EventLogQuery(SystemLog, PathType.LogName, query)
                {
                    ReverseDirection = true,
                });

            using var record = reader.ReadEvent();

            return record?.TimeCreated is { } t
                ? new DateTimeOffset(t.ToUniversalTime(), TimeSpan.Zero)
                : null;
        }
        catch (EventLogException ex)
        {
            _log.LogDebug(ex, "לא ניתן לאתר את האירוע שקדם להדלקה.");
            return null;
        }
    }

    private List<EventRecord> Query(string log, string xpath)
    {
        var records = new List<EventRecord>();

        try
        {
            using var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, xpath));

            while (reader.ReadEvent() is { } record) records.Add(record);
        }
        catch (UnauthorizedAccessException)
        {
            // יומן האבטחה דורש הרשאות מוגברות. השירות רץ כ-SYSTEM
            // ולכן זה לא אמור לקרות, אך אין להפיל את העלייה בגללו.
            _log.LogWarning("אין גישה ליומן {Log}.", log);
        }
        catch (EventLogException ex)
        {
            _log.LogWarning(ex, "קריאת יומן {Log} נכשלה.", log);
        }

        return records;
    }
}
