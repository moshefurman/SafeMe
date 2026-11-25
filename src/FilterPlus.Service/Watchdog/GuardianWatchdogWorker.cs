using System.Diagnostics;
using System.Runtime.Versioning;
using System.ServiceProcess;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using FilterPlus.Core.Models;
using FilterPlus.Core.Watchdog;
using FilterPlus.Service.Workers;

using FilterPlus.Core.Updates;

namespace FilterPlus.Service.Watchdog;

/// <summary>
/// מחזיר את שירות השומר אם מישהו עצר אותו.
///
/// הצד השני של השמירה ההדדית. שירות אינו יכול לשמור על עצמו — ברגע
/// שהוא נעצר, כל קוד שבתוכו נעצר איתו — ולכן כל אחד מהשניים שומר
/// על האחר.
///
/// זה מה שהופך את ההשבתה למשימה עם חלון זמן: כדי לכבות את ההגנה
/// צריך לעצור את שני השירותים בתוך פחות משתי שניות. עצירה של אחד
/// מהם מוחזרת כמעט מיד, ונרשמת כניסיון חבלה.
///
/// והרישום חשוב לא פחות מההחזרה. הגנה מושלמת מפני מי ששולט על
/// המחשב אינה קיימת — מי שיכול לאתחל מדיסק חיצוני יכול הכול —
/// והמטרה הריאלית היא שכל ניסיון ישאיר סימן שההורה יראה.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class GuardianWatchdogWorker : BackgroundService
{
    public const string GuardianServiceName = "FilterPlusGuardian";

    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(2);

    private readonly ILogger<GuardianWatchdogWorker> _log;
    private readonly EventQueue _events;
    private readonly UninstallCoordinator _uninstall;

    private DateTimeOffset? _lastAttempt;
    private bool _reported;

    public GuardianWatchdogWorker(
        ILogger<GuardianWatchdogWorker> log,
        EventQueue events,
        UninstallCoordinator uninstall)
    {
        _log = log;
        _events = events;
        _uninstall = uninstall;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                Check();
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "בדיקת מצב השומר נכשלה.");
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
        /*
         * הסרה מאושרת אינה חבלה.
         *
         * זה היה העובד היחיד שלא בדק את המצב הזה, וזה הספיק כדי
         * שההסרה תיכשל תמיד: הסקריפט עוצר ומוחק את השומר, והעובד
         * הזה מחזיר אותו שתי שניות אחר כך. אז השומר שחזר מחזיר את
         * הסוכן, ושניהם עולים מחדש מתוך תיקייה שכבר נמחקה למחצה.
         *
         * נצפה בדיוק כך: ההסרה דיווחה הצלחה, ושני השירותים היו
         * רשומים ורצים דקה אחריה, עם קבצים חסרים.
         *
         * השמירה ההדדית נועדה למי שמנסה לעצור בלי רשות. מי שהציג
         * קוד תקף כבר קיבל רשות, והמשך ההתנגדות אינו הגנה אלא
         * תוכנה שאי אפשר להסיר.
         */
        if (_uninstall.Disarmed) return;

        var state = ReadState();

        var decision = WatchdogGate.Decide(
            state, DateTimeOffset.UtcNow, _lastAttempt, UpdateInProgress());

        if (decision.Action == WatchAction.Start)
        {
            _lastAttempt = DateTimeOffset.UtcNow;
            Start();

            return;
        }

        if (decision.Action == WatchAction.ReportMissing && !_reported)
        {
            _reported = true;

            _log.LogError("שירות השומר הוסר מהמערכת.");

            _events.Enqueue(new TamperEvent
            {
                Kind = TamperKind.ServiceStopAttempt,
                Detail = "שירות השומר הוסר מהמערכת.",
            });

            return;
        }

        if (decision.Action == WatchAction.None && state == ServiceState.Running)
            _reported = false;
    }

    private static ServiceState ReadState()
    {
        try
        {
            using var controller = new ServiceController(GuardianServiceName);

            return controller.Status switch
            {
                ServiceControllerStatus.Running => ServiceState.Running,
                ServiceControllerStatus.Stopped => ServiceState.Stopped,
                _ => ServiceState.Unknown,
            };
        }
        catch (InvalidOperationException)
        {
            return ServiceState.Missing;
        }
    }

    /// <summary>
    /// האם עדכון פעיל, ולכן אין להתערב.
    ///
    /// נבדק לפי שם תהליך בלבד — "FilterPlus-Setup" או "FilterPlus.Installer" —
    /// והמתקין שהעדכון האוטומטי מפעיל נקרא בכלל FilterPlus-Update-{גרסה}.exe.
    /// השער היה קיים ומעולם לא ירה.
    ///
    /// מה שקרה בשטח: המתקין מחק את שני השירותים, השומר החזיר אחד
    /// מהם תוך שתי שניות, הקבצים נעלו, ההעתקה נכשלה — והמחשב נשאר
    /// בלי שירות סוכן כלל. העדכונים שעברו לפני כן עברו במזל תזמון.
    ///
    /// הסימן קודם, ושמות התהליכים נשארו אחריו: התקנה ידנית עדיין
    /// מריצה FilterPlus-Setup, ואין סיבה לוותר על מה שכן עבד שם.
    /// </summary>
    private static bool UpdateInProgress() =>
        UpdateMarker.IsActive(DateTimeOffset.UtcNow)
        || Process.GetProcessesByName("FilterPlus-Setup").Length > 0
        || Process.GetProcessesByName("FilterPlus.Installer").Length > 0;

    private void Start()
    {
        try
        {
            using var controller = new ServiceController(GuardianServiceName);

            controller.Start();
            controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));

            _log.LogWarning("שירות השומר נעצר והוחזר לפעולה.");

            /*
             * נרשם כניסיון חבלה, ולא כאירוע תפעולי.
             *
             * עצירה של שירות ההגנה אינה קורית מעצמה. גם אם הייתה
             * תקלה ולא כוונה — ההורה צריך לדעת שההגנה הייתה מכובה,
             * ולו לרגע.
             */
            _events.Enqueue(new TamperEvent
            {
                Kind = TamperKind.ServiceStopAttempt,
                Detail = "שירות השומר נעצר והוחזר על ידי הסוכן.",
            });
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "החזרת שירות השומר נכשלה.");
        }
    }
}
