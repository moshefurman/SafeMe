using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using FilterPlus.Core.Abstractions;
using FilterPlus.Core.Models;
using FilterPlus.Service.State;
using FilterPlus.Service.Wfp;

namespace FilterPlus.Service.Workers;

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
    private const string RegistryPath = @"SOFTWARE\FilterPlus\Agent";

    private readonly ILogger<UninstallCoordinator> _log;
    private readonly IEnforcementEngine _enforcement;
    private readonly IAgentStateProvider _state;
    private readonly EventQueue _events;
    private readonly IManagementServerClient _server;
    private readonly DnsFilter.DnsGate _gate;

    /// <summary>נדלק לאחר אישור הסרה. שאר ה-Workers בודקים אותו ומשביתים את עצמם.</summary>
    public bool Disarmed { get; private set; }

    /// <summary>
    /// רישום מוצלח מוכיח שהשרת פעיל ושהמחשב שייך לחשבון. מצב Disarmed
    /// שנקבע בגלל היעדר קשר כבר אינו רלוונטי — ההגנה חוזרת.
    /// </summary>
    public void RearmAfterEnrollment()
    {
        if (!Disarmed) return;

        Disarmed = false;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath, writable: true);
            key?.SetValue("UninstallApproved", "0", RegistryValueKind.String);
        }
        catch
        {
            // כישלון כתיבה לרג'יסטרי אינו סיבה להשאיר Disarmed.
        }
    }

    public UninstallCoordinator(
        ILogger<UninstallCoordinator> log,
        IEnforcementEngine enforcement,
        IAgentStateProvider state,
        EventQueue events,
        IManagementServerClient server,
        DnsFilter.DnsGate gate)
    {
        _log = log;
        _gate = gate;
        _enforcement = enforcement;
        _state = state;
        _events = events;
        _server = server;

        /*
         * שירות שעולה מחדש אינו שוכח שההסרה אושרה.
         *
         * Disarmed הוא שדה בזיכרון, ולכן כל הפעלה מחדש איפסה אותו.
         * זה מה שהפך החזרה אחת של השומר למפל שלם: השומר החזיר את
         * הסוכן, הסוכן קם "חמוש" מחדש, והחזיר את השומר בחזרה.
         *
         * האישור נכתב לרישום ממילא — הסקריפט קורא ממנו — ולכן אותו
         * מקור משמש כאן. אותו חלון של שעה בדיוק, כדי ששני הצדדים
         * לא יחליטו אחרת על אותו אישור.
         */
        Disarmed = ApprovalIsFresh();
    }

    /// <summary>
    /// האם קיים אישור הסרה בתוקף.
    ///
    /// שעה, כמו בסקריפט. אישור ישן אינו מפרק סוכן שההסרה שלו מעולם
    /// לא הושלמה — אחרת תקלה אחת הייתה משאירה מחשב לא מוגן לצמיתות.
    /// </summary>
    private static bool ApprovalIsFresh()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath);

            if (key?.GetValue("UninstallApproved") as string != "1") return false;

            if (key.GetValue("UninstallApprovedUtc") is not string stamp) return false;

            return DateTimeOffset.TryParse(
                       stamp,
                       System.Globalization.CultureInfo.InvariantCulture,
                       System.Globalization.DateTimeStyles.RoundtripKind,
                       out var approved)
                   && DateTimeOffset.UtcNow - approved <= TimeSpan.FromHours(1)
                   && approved <= DateTimeOffset.UtcNow;
        }
        catch
        {
            // רישום שאי אפשר לקרוא אינו סיבה לפרק אכיפה.
            return false;
        }
    }

    public async Task DisarmAsync(string? token, CancellationToken ct)
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

        /*
         * גם הפניית ה-DNS יורדת, ולפני שהתהליך נעצר.
         *
         * היא מפתח רישום ולא חוק WFP, ולכן אינה נעלמת עם התהליך.
         * הסרה שמשאירה אותה מאחור משאירה מחשב שכל שאלת DNS שלו
         * מופנית לשרת שכבר אינו קיים.
         */
        try
        {
            _gate.Stop();
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "הסרת הפניית ה-DNS נכשלה.");
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

        /*
         * הדיווח אחרון, ואינו חוסם דבר.
         *
         * תיעוד המחלקה הבטיח "ודיווח לשרת" מהיום הראשון, ולא היה כזה —
         * ולכן מחשב שהוסר בהצלחה נשאר ברשימה בפורטל לנצח, וההורה ראה
         * מכשירים שכבר אינם קיימים.
         *
         * הוא אחרי הפירוק כדי שכישלון רשת לא ימנע הסרה: המחשב עשוי
         * להיות מנותק בדיוק בגלל מה שמסירים.
         */
        if (!await _server.ReportUninstalledAsync(ct))
            _log.LogWarning("לא הצלחנו לדווח לשרת על ההסרה. יש להסיר את המחשב מהפורטל ידנית.");
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
            var path = Path.Combine(FilterPlusPaths.StateDir, "uninstall-approved.txt");
            File.WriteAllText(path, token, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "כתיבת אסימון ההסרה לקובץ נכשלה.");
        }
    }
}
