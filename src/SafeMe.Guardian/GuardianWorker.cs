using System.Diagnostics;
using System.Runtime.Versioning;
using System.ServiceProcess;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using SafeMe.Core.Watchdog;

namespace SafeMe.Guardian;

/// <summary>
/// מחזיר את הסוכן אם מישהו עצר אותו.
///
/// למה שירות נפרד ולא עוד עובד בתוך הסוכן: שירות אינו יכול לשמור על
/// עצמו. ברגע שהוא נעצר, כל מה שרץ בתוכו נעצר איתו — כולל כל קוד
/// שהיה אמור להבחין בכך.
///
/// מה שהיה קיים לא סגר את זה. sc failure מחזיר שירות שקרס, אך עצירה
/// בפקודה אינה כשל ומבחינת Windows לא קרה דבר. המשימה המתוזמנת כן
/// מחזירה, אבל פעם ברבע שעה — וזה חלון ארוך דיו לכל מה שרוצים
/// לעשות בו.
///
/// השמירה הדדית: הסוכן מחזיר את השומר באותו אופן. כדי להשבית את
/// ההגנה צריך לעצור את שניהם בתוך פחות משתי שניות, ואז גם המשימה
/// המתוזמנת עוד ממתינה ברקע.
///
/// מה שהוא **אינו**: הגנה מפני מי ששולט על המחשב במלואו. מי שיכול
/// לאתחל מדיסק חיצוני יכול הכול. המטרה הריאלית היא שכל הסרה תשאיר
/// סימן שההורה יראה — ולכן כל החייאה נרשמת ומדווחת.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class GuardianWorker : BackgroundService
{
    /// <summary>שם השירות שעליו שומרים.</summary>
    public const string AgentServiceName = "SafeMeAgent";

    /// <summary>
    /// תדירות הבדיקה.
    ///
    /// שתי שניות. די מהר כדי שחלון ההשבתה יהיה קצר מכדי להספיק בו
    /// משהו, ורחוק מספיק מלהעמיס על מחשב שרץ כך כל היום.
    /// </summary>
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(2);

    private readonly ILogger<GuardianWorker> _log;

    private DateTimeOffset? _lastAttempt;
    private bool _reportedMissing;

    public GuardianWorker(ILogger<GuardianWorker> log) => _log = log;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("שומר SafeMe עלה. משגיח על {Service}.", AgentServiceName);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                Check();
            }
            catch (Exception ex)
            {
                // כשל בבדיקה אחת אינו סיבה להפיל את השומר. הוא ינסה שוב.
                _log.LogWarning(ex, "בדיקת מצב השירות נכשלה.");
            }

            try
            {
                await Task.Delay(Interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private void Check()
    {
        var state = ReadState();

        var decision = WatchdogGate.Decide(
            state, DateTimeOffset.UtcNow, _lastAttempt, UpdateInProgress());

        switch (decision.Action)
        {
            case WatchAction.Start:
                _lastAttempt = DateTimeOffset.UtcNow;
                Start(decision.Reason);
                break;

            case WatchAction.ReportMissing:
                /*
                 * פעם אחת, ולא בכל מחזור.
                 *
                 * שירות שהוסר יישאר מוסר, והודעה כל שתי שניות תקבור
                 * את היומן ותסתיר בדיוק את מה שחשוב בו.
                 */
                if (!_reportedMissing)
                {
                    _reportedMissing = true;
                    _log.LogError("שירות SafeMe הוסר מהמערכת. {Reason}", decision.Reason);
                }

                break;

            default:
                _reportedMissing = false;
                break;
        }
    }

    private ServiceState ReadState()
    {
        try
        {
            using var controller = new ServiceController(AgentServiceName);

            return controller.Status switch
            {
                ServiceControllerStatus.Running => ServiceState.Running,
                ServiceControllerStatus.Stopped => ServiceState.Stopped,

                // בתהליך עלייה או ירידה. לא נוגעים.
                _ => ServiceState.Unknown,
            };
        }
        catch (InvalidOperationException)
        {
            // ServiceController זורק כך כשהשירות אינו רשום
            return ServiceState.Missing;
        }
    }

    /// <summary>
    /// האם מתקין רץ כרגע.
    ///
    /// המתקין עוצר את השירות בכוונה כדי להחליף את קבציו, והחייאה
    /// באותו רגע תחזיק אותם נעולים ותפיל את העדכון. הבדיקה היא על
    /// שם התהליך, כי זה מה שזמין בלי לתאם בין שני שירותים.
    /// </summary>
    private static bool UpdateInProgress() =>
        Process.GetProcessesByName("SafeMe-Setup").Length > 0
        || Process.GetProcessesByName("SafeMe.Installer").Length > 0;

    private void Start(string reason)
    {
        _log.LogWarning("{Reason} מפעיל את {Service}.", reason, AgentServiceName);

        try
        {
            using var controller = new ServiceController(AgentServiceName);

            controller.Start();
            controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));

            _log.LogWarning("שירות SafeMe הוחזר לפעולה על ידי השומר.");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "החזרת שירות SafeMe נכשלה.");
        }
    }
}
