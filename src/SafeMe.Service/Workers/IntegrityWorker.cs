using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SafeMe.Core.Abstractions;
using SafeMe.Core.Models;
using SafeMe.Service.State;
using SafeMe.Service.Integrity;

using SafeMe.Core.Updates;
using SafeMe.Service.Browser;

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
    private readonly BrowserPolicyEnforcer _browser;

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
        CoverageReconciler reconciler,
        BrowserPolicyEnforcer browser)
    {
        _log = log;
        _engine = engine;
        _state = state;
        _enforcement = enforcement;
        _policy = policy;
        _deviceStore = deviceStore;
        _events = events;
        _hardening = new Integrity.ServiceHardening(log);
        _browser = browser;
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
                CheckBrowserPolicy();
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
    /// <summary>
    /// כמה כשלי החזרה רצופים לפני שמפסיקים לרשום.
    ///
    /// ניסיון חבלה אמיתי צריך להשאיר סימן בכל פעם — זו הכוונה
    /// המקורית, והיא נכונה. אבל היא מניחה שההחזרה מצליחה.
    ///
    /// כשהיא נכשלת, החזרה כל שלושים שניות אינה תיעוד אלא לולאה:
    /// נצפו בשטח מאתיים אירועים תוך אחת עשרה דקות, שניים לכל
    /// מחזור, ובקצב הזה יומן האירועים של Windows מתמלא ביום.
    /// גם תור האירועים לשרת מוצף, וההורה מקבל התראה על "חבלה"
    /// שהיא בעצם הרשאה חסרה.
    ///
    /// שלושה ניסיונות מספיקים כדי לדעת שזה לא הולך להסתדר מעצמו.
    /// </summary>
    private const int MaxRestoreFailures = 3;

    private readonly Dictionary<string, int> _restoreFailures = new(StringComparer.OrdinalIgnoreCase);

    private void CheckServiceHardening()
    {
        /*
         * לא בזמן התקנה.
         *
         * המתקין משחרר את ההקשחה כדי לעצור ולמחוק את השירותים,
         * ואז מעתיק קבצים. בדיקה שרצה כל שלושים שניות מחזירה את
         * ההקשחה בדיוק בחלון הזה — ואז Stop-Service ו-sc delete
         * נכשלים, הקבצים נשארים נעולים, וההעתקה נופלת.
         *
         * זה נצפה בשטח: המתקין נכשל בזמן שהסוכן רץ, ואותו סקריפט
         * בדיוק הצליח כשהסוכן כבר לא הקשיח דבר. הסוכן הגן על עצמו
         * מפני העדכון של עצמו.
         */
        if (UpdateMarker.IsActive(DateTimeOffset.UtcNow)) return;

        foreach (var service in new[] { "SafeMeAgent", "SafeMeGuardian" })
        {
            // null פירושו שלא הצלחנו לברר, ואז לא עושים דבר.
            // בדיקה שלא רצה אינה בדיקה שנכשלה.
            if (_hardening.IsHardened(service) is not false)
            {
                /*
                 * חזר להיות מוקשח.
                 *
                 * המונה מתאפס, כדי שחבלה עתידית תירשם מלכתחילה.
                 * ואם הוא היה גבוה — כלומר היינו תקועים — זה נרשם,
                 * כי "הפסקנו לדווח" ו"הסתדר" חייבים להיראות שונה.
                 */
                if (_restoreFailures.TryGetValue(service, out var had) && had >= MaxRestoreFailures)
                    _log.LogWarning("הרשאות השירות {Service} חזרו להיות מוקשחות.", service);

                _restoreFailures.Remove(service);
                continue;
            }

            var failures = _restoreFailures.GetValueOrDefault(service);

            if (failures >= MaxRestoreFailures)
            {
                /*
                 * ממשיכים לנסות ובשקט.
                 *
                 * הניסיון עצמו זול, והמצב עשוי להשתנות — התקנה
                 * שתרוץ מאוחר יותר תחזיר את ההרשאות. מה שמפסיק
                 * הוא הרישום, לא התיקון.
                 */
                _hardening.Restore(service);
                continue;
            }

            _log.LogWarning("הרשאות השירות {Service} רופפו מחוץ לסוכן.", service);

            _events.Enqueue(new TamperEvent
            {
                Kind = TamperKind.ServiceStopAttempt,
                Detail = $"הרשאות השירות {service} שונו כך שניתן לעצור אותו. הוחזרו.",
            });

            if (_hardening.Restore(service))
            {
                _restoreFailures.Remove(service);
                continue;
            }

            _restoreFailures[service] = failures + 1;

            if (failures + 1 >= MaxRestoreFailures)
            {
                _log.LogError(
                    "החזרת ההרשאות של {Service} נכשלה {Count} פעמים. מפסיק לרשום, וממשיך לנסות בשקט. " +
                    "נדרשת התקנה מחדש כדי להחזיר את ההקשחה.",
                    service, failures + 1);
            }
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

    /// <summary>
    /// בודק שמדיניות תוסף הדפדפן ברישום תואמת למדיניות מהשרת.
    ///
    /// כשיוטיוב שמע בלבד מופעל במדיניות, התוסף חייב להיות רשום
    /// ב-ExtensionInstallForcelist. מחיקת המפתח מסירה את התוסף,
    /// ולכן היא מוחזרת — בדיוק כמו שינוי הרשאות השירותים.
    /// </summary>
    private void CheckBrowserPolicy()
    {
        try
        {
            var br = _policy.Current.Enforcement.Browser;
            var wanted = br.YouTubeAudioOnly || br.YouTubeHideThumbnails;
            _browser.VerifyAndRestore(wanted);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "בדיקת מדיניות הדפדפן נכשלה.");
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
