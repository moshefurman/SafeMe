using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SafeMe.Core.Abstractions;
using SafeMe.Core.Models;
using SafeMe.Service.State;
using SafeMe.Service.Integrity;

namespace SafeMe.Service.Workers;

/// <summary>
/// שומר על שלמות האכיפה ומונע מצב של נעילה בלתי הפיכה.
///
/// שתי אחריות:
///   1. אימות שחוקי ה-WFP עדיין קיימים; מחיקה ידנית מטופלת כחבלה ובנייה מחדש.
///   2. דיווח על ניתוק ממושך מהשרת. שים לב: הניתוק **אינו** מרפה את
///      האכיפה. הגרסה הקודמת שחררה נעילה אוטומטית אחרי חלון החסד,
///      וזו הייתה דרך עקיפה זולה — די היה לחסום את השרת ולהמתין.
///      במקומה, כל נעילה נושאת זמן סיום משלה שהמחשב סופר לבד.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class IntegrityWorker : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(30);

    private readonly ILogger<IntegrityWorker> _log;
    private readonly IEnforcementEngine _engine;
    private readonly IAgentStateProvider _state;
    private readonly EnforcementCoordinator _enforcement;
    private readonly PolicyStore _policy;
    private readonly DeviceStateStore _deviceStore;
    private readonly EventQueue _events;
    private readonly Integrity.ServiceHardening _hardening;

    // פעם אחת לכל שירות. הודעה כל שלושים שניות הייתה קוברת את היומן.
    private readonly HashSet<string> _registryReported = new(StringComparer.OrdinalIgnoreCase);
    private readonly UninstallCoordinator _uninstall;
    private readonly CoverageReconciler _reconciler;

    private bool _graceReported;

    public IntegrityWorker(
        ILogger<IntegrityWorker> log,
        IEnforcementEngine engine,
        IAgentStateProvider state,
        EnforcementCoordinator enforcement,
        PolicyStore policy,
        DeviceStateStore deviceStore,
        EventQueue events,
        UninstallCoordinator uninstall,
        CoverageReconciler reconciler)
    {
        _log = log;
        _engine = engine;
        _state = state;
        _enforcement = enforcement;
        _policy = policy;
        _deviceStore = deviceStore;
        _events = events;
        _hardening = new Integrity.ServiceHardening(log);
        _reconciler = reconciler;
        _uninstall = uninstall;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // פיוס ראשון, לפני כל דבר אחר.
        //
        // זו ההזדמנות היחידה לגלות תקופה שבה התוכנה לא פעלה: מרגע
        // שהסוכן מדווח שוב, הפער נסגר ואין מה לגלות. לכן זה קורה
        // בעלייה, ולפני הפעימה הראשונה.
        try
        {
            var found = _reconciler.Reconcile();

            if (found > 0)
                _log.LogWarning("נמצאו {Count} תקופות שבהן המחשב פעל בלי הסוכן.", found);
        }
        catch (Exception ex)
        {
            // פיוס שנכשל לא יעצור את האכיפה. הוא כלי גילוי, לא תנאי.
            _log.LogError(ex, "פיוס ציר ההפעלה נכשל.");
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            if (!_uninstall.Disarmed)
            {
                CheckWfpIntegrity();
                CheckServiceHardening();
                ReportProlongedDisconnect();
            }

            try
            {
                await Task.Delay(CheckInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// בודק שהרשאות השירותים לא רופפו.
    ///
    /// ההתקנה מסירה ממנהלים את הזכות לעצור את השירותים, ולכן
    /// sc stop נכשל. מנהל עדיין יכול להחזיר לעצמו את הזכות — וזה
    /// הצעד הראשון בכל ניסיון לעצור.
    ///
    /// בלי מנהל התקן חתום אי אפשר למנוע ממנו את הצעד הזה. מה שכן
    /// אפשר הוא להפוך אותו לאירוע: ההרשאות מוחזרות, והניסיון נרשם
    /// ומדווח. מי שמנסה צריך לחזור על הצעד בכל פעם, וכל חזרה
    /// מותירה סימן.
    /// </summary>
    private void CheckServiceHardening()
    {
        foreach (var service in new[] { "SafeMeAgent", "SafeMeGuardian" })
        {
            // null פירושו שלא הצלחנו לברר, ואז לא עושים דבר.
            // בדיקה שלא רצה אינה בדיקה שנכשלה.
            if (_hardening.IsHardened(service) is not false) continue;

            _log.LogWarning("הרשאות השירות {Service} רופפו מחוץ לסוכן.", service);

            _events.Enqueue(new TamperEvent
            {
                Kind = TamperKind.ServiceStopAttempt,
                Detail = $"הרשאות השירות {service} שונו כך שניתן לעצור אותו. הוחזרו.",
            });

            _hardening.Restore(service);
        }

        /*
         * הרשאות הרישום נבדקות ומדווחות, אך אינן מוחזרות מכאן.
         *
         * החזרתן דורשת פתיחת המפתח עם ChangePermissions, וזה בדיוק
         * מה שנכשל בהתקנה. תיקון מהסוכן היה מסתיר את הסיבה במקום
         * לחשוף אותה — ומה שצריך כאן הוא לדעת שההגנה אינה שם.
         *
         * בלעדיה אפשר להריץ reg add על ImagePath ולהחליף את נתיב
         * ההרצה: שירות בשם SafeMe שמריץ משהו אחר, והכול נראה תקין.
         */
        foreach (var service in new[] { "SafeMeAgent", "SafeMeGuardian" })
        {
            if (_hardening.RegistryProtected(service) is not false) continue;

            if (!_registryReported.Add(service)) continue;

            _log.LogError(
                "מפתח הרישום של {Service} אינו מוגן. אפשר להחליף את נתיב ההרצה.",
                service);

            _events.Enqueue(new TamperEvent
            {
                Kind = TamperKind.ServiceStopAttempt,
                Detail = $"מפתח הרישום של {service} אינו מוגן. ההגנה לא הוחלה בהתקנה.",
            });
        }
    }

    private void CheckWfpIntegrity()
    {
        try
        {
            if (_engine.VerifyIntegrity())
            {
                _state.Update(s => s.WfpFilterCount = _engine.ActiveFilterCount);
                return;
            }

            _events.Enqueue(new TamperEvent
            {
                Kind = TamperKind.WfpFiltersMissing,
                Detail = "חוקי WFP נמחקו מחוץ לסוכן. מתבצעת בנייה מחדש."
            });

            // בנייה מחדש מהמצב הרצוי, ולא ניסיון לתקן הפרשים
            _ = _enforcement.ReevaluateAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "בדיקת שלמות חוקי WFP נכשלה.");
        }
    }

    /// <summary>
    /// מדווח על ניתוק ממושך מהשרת. אינו משנה את מצב האכיפה.
    ///
    /// מחשב שמנותק שבוע ממשיך לאכוף בדיוק את מה שידע. זו התנהגות
    /// מכוונת: ההגנה אינה תלויה בזמינות השרת.
    /// </summary>
    private void ReportProlongedDisconnect()
    {
        var device = _deviceStore.Load();
        var lastContact = device.LastServerContactUtc;

        // מחשב שמעולם לא יצר קשר עדיין בתהליך התקנה
        if (lastContact is null) return;

        var offlineFor = DateTimeOffset.UtcNow - lastContact.Value;
        var grace = TimeSpan.FromMinutes(_policy.Current.GraceMinutes);

        if (offlineFor <= grace)
        {
            _graceReported = false;
            return;
        }

        if (_graceReported) return;

        _graceReported = true;

        _log.LogWarning(
            "אין קשר לשרת כבר {Hours:F1} שעות. האכיפה נמשכת כרגיל.",
            offlineFor.TotalHours);

        _events.Enqueue(new TamperEvent
        {
            Kind = TamperKind.ServiceCrash,
            Detail = $"נותק מהשרת {offlineFor.TotalHours:F1} שעות. האכיפה נשמרה."
        });
    }
}
