using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SafeMe.Core.Abstractions;
using SafeMe.Core.Models;
using SafeMe.Service.State;
using SafeMe.Service.Wfp;

namespace SafeMe.Service.Workers;

/// <summary>
/// מבצע את פירוק האכיפה לאחר שקוד ההסרה אומת בהצלחה.
///
/// הפירוק כולל: הסרת כל חוקי WFP, כיבוי ה-Watchdog, כתיבת אסימון ההסרה
/// למקום שהמתקין יכול לקרוא ממנו, ודיווח לשרת. הפעולה חד-כיוונית עד
/// לאתחול השירות.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class UninstallCoordinator
{
    /// <summary>מפתח שממנו המתקין קורא את אישור ההסרה.</summary>
    private const string RegistryPath = @"SOFTWARE\SafeMe\Agent";

    private readonly ILogger<UninstallCoordinator> _log;
    private readonly IEnforcementEngine _enforcement;
    private readonly IAgentStateProvider _state;
    private readonly EventQueue _events;

    /// <summary>נדלק לאחר אישור הסרה. שאר ה-Workers בודקים אותו ומשביתים את עצמם.</summary>
    public bool Disarmed { get; private set; }

    public UninstallCoordinator(
        ILogger<UninstallCoordinator> log,
        IEnforcementEngine enforcement,
        IAgentStateProvider state,
        EventQueue events)
    {
        _log = log;
        _enforcement = enforcement;
        _state = state;
        _events = events;
    }

    public Task DisarmAsync(string? token, CancellationToken ct)
    {
        Disarmed = true;

        try
        {
            if (_enforcement is WfpEnforcementEngine wfp)
                wfp.Uninstall();
            else
                _enforcement.RemoveAll();
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "הסרת חוקי האכיפה נכשלה.");
        }

        WriteUninstallToken(token);

        _state.Update(snapshot =>
        {
            snapshot.LockoutActive = false;
            snapshot.LockoutUntil = null;
            snapshot.LockoutReason = null;
            snapshot.Status = SecurityStatus.Unknown;
            snapshot.Headline = "ההסרה אושרה. האכיפה כבויה.";
        });

        _events.Enqueue(new TamperEvent
        {
            Kind = TamperKind.ServiceStopAttempt,
            Detail = "הסרה מאושרת בוצעה לאחר אימות קוד תקף."
        });

        _log.LogWarning("הסוכן פורק. אין אכיפה פעילה עד להתקנה מחדש.");

        return Task.CompletedTask;
    }

    /// <summary>
    /// פותח הסרה בלי קוד, למחשב שמזמן לא שמע מהשרת.
    ///
    /// זה הצד השני של התוקף המוגבל. שחרור האכיפה לבדו אינו מספיק:
    /// המחשב היה נשאר עם תוכנה שאי אפשר להסיר, וזו בדיוק המלכודת
    /// שנפתחה כשההסרה הכפויה נסגרה.
    ///
    /// האישור נכתב פעם אחת ונשאר. הוא תקף לשעה לפי הסקריפט, ולכן
    /// הוא נכתב מחדש בכל בדיקה כל עוד המצב פג — מחשב נטוש אינו
    /// אמור לדרוש תזמון.
    ///
    /// נרשם כאזהרה ולא כמידע: זה אירוע שראוי שיישאר ביומן, וגם
    /// אם אין מי שיקרא אותו כרגע, מי שיבדוק בדיעבד למה מחשב הפסיק
    /// להיות מוגן ימצא כאן את התשובה.
    /// </summary>
    public void ApproveBecauseOffline(double daysOffline)
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(RegistryPath, writable: true);

            key?.SetValue("UninstallApproved", "1", RegistryValueKind.String);
            key?.SetValue("UninstallApprovedUtc", DateTimeOffset.UtcNow.ToString("o"), RegistryValueKind.String);
            key?.SetValue("UninstallApprovedReason", "offline-expiry", RegistryValueKind.String);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "פתיחת ההסרה למחשב מנותק נכשלה.");
            return;
        }

        _log.LogWarning(
            "המחשב לא שמע מהשרת {Days:N0} ימים. ההסרה נפתחה בלי קוד, והאכיפה שוחררה.",
            daysOffline);
    }

    /// <summary>
    /// כותב את אסימון ההסרה לרג'יסטרי ולקובץ. המתקין מאמת את קיומו
    /// לפני שהוא מסיר את הקבצים, כדי שהסרה בכפייה לא תעקוף את התהליך.
    /// </summary>
    private void WriteUninstallToken(string? token)
    {
        if (string.IsNullOrWhiteSpace(token)) return;

        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(RegistryPath, writable: true);

            key?.SetValue("UninstallApproved", "1", RegistryValueKind.String);
            key?.SetValue("UninstallToken", token, RegistryValueKind.String);
            key?.SetValue("UninstallApprovedUtc", DateTimeOffset.UtcNow.ToString("o"), RegistryValueKind.String);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "כתיבת אסימון ההסרה לרג'יסטרי נכשלה.");
        }

        try
        {
            var path = Path.Combine(SafeMePaths.StateDir, "uninstall-approved.txt");
            File.WriteAllText(path, token, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "כתיבת אסימון ההסרה לקובץ נכשלה.");
        }
    }
}
