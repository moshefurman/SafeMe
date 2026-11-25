using System.Diagnostics;
using System.ServiceProcess;

namespace FilterPlus.TrayApp.Services;

/// <summary>
/// הצד של אפליקציית המגש ב-Watchdog הכפול.
///
/// בודק שהשירות רץ, ומנסה להפעילו מחדש. משתמש רגיל אינו רשאי להפעיל שירות,
/// ולכן נעשה ניסיון ישיר ואם הוא נדחה מוצגת בקשת הרמה חד-פעמית.
/// אין ניסיון להסתיר את הפעולה מהמשתמש.
/// </summary>
public sealed class ServiceGuardian : IDisposable
{
    private const string ServiceName = "FilterPlusAgent";

    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(10);

    /// <summary>מרווח מינימלי בין ניסיונות הפעלה, למניעת לולאת בקשות UAC.</summary>
    private static readonly TimeSpan RestartCooldown = TimeSpan.FromMinutes(2);

    private readonly StatusPoller _poller;
    private readonly CancellationTokenSource _cts = new();

    private DateTimeOffset _lastRestartAttempt = DateTimeOffset.MinValue;
    private Task? _loop;

    public ServiceGuardian(StatusPoller poller) => _poller = poller;

    public void Start() => _loop ??= Task.Run(() => LoopAsync(_cts.Token));

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (!IsServiceRunning() && CanAttemptRestart())
                    TryStartService();
            }
            catch (Exception)
            {
                // בדיקת שירות היא מאמץ מיטבי; כשל בה לא מפיל את אפליקציית המגש
            }

            try
            {
                await Task.Delay(CheckInterval, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// בדיקה בשני מסלולים, כי למסלול הראשון יש דרך להיכשל בלי להיות שגוי.
    ///
    /// ServiceController פותח את השירות בשמו, ולשם כך SCM קורא את
    /// DisplayName ממפתח הרישום בהתחזות לקורא. הקשחת הרישום הסירה
    /// מ-BUILTIN\Users את זכות הקריאה, והקריאה חזרה Access denied —
    /// ש-.NET מתרגם ל-InvalidOperationException עם הטקסט
    /// "was not found on computer". שגיאת הרשאה שנראית בדיוק כמו
    /// שירות שאינו מותקן.
    ///
    /// התוצאה הייתה שקטה ומטעה: המגש הסיק שהסוכן הוסר בזמן שהוא רץ,
    /// וניסה להפעילו כל שתי דקות. ההרשאה הוחזרה במתקין, אבל מחשב
    /// שהותקן קודם עדיין נושא את המפתח הישן עד העדכון הבא.
    ///
    /// המנייה אינה פותחת כל שירות בנפרד ולכן אינה נוגעת ברישום.
    /// היא עובדת גם כשהמסלול הראשון נחסם, ובזכות זה שאלת ההרשאות
    /// מופרדת משאלת המצב.
    /// </summary>
    public static bool IsServiceRunning()
    {
        try
        {
            using var controller = new ServiceController(ServiceName);
            return IsUp(controller.Status);
        }
        catch (InvalidOperationException)
        {
            return IsRunningByEnumeration();
        }
    }

    private static bool IsRunningByEnumeration()
    {
        try
        {
            foreach (var service in ServiceController.GetServices())
            {
                using (service)
                {
                    if (string.Equals(service.ServiceName, ServiceName, StringComparison.OrdinalIgnoreCase))
                        return IsUp(service.Status);
                }
            }

            // עברנו על כל השירותים ולא מצאנו. זו התשובה היחידה שאפשר
            // לקרוא לה "אינו מותקן", ורק כאן.
            return false;
        }
        catch (Exception)
        {
            /*
             * גם המנייה נכשלה. אין ידיעה, ומחזירים "רץ" בכוונה:
             * הערך הזה מוביל רק להימנעות מניסיון הפעלה, וניסיון
             * הפעלה מיותר בזמן עדכון מזיק יותר מהימנעות מיותרת.
             */
            return true;
        }
    }

    private static bool IsUp(ServiceControllerStatus status) =>
        status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending;

    private bool CanAttemptRestart() =>
        DateTimeOffset.UtcNow - _lastRestartAttempt > RestartCooldown;

    /// <summary>
    /// מנסה להפעיל את השירות — בשקט, ורק בשקט.
    ///
    /// כאן הייתה בקשת הסלמה: כשההפעלה הישירה נכשלה, המגש הריץ
    /// sc.exe עם runas ופתח תיבת UAC. היא נפתחה בדיוק בזמן העדכון
    /// האוטומטי, שבו השירות עצור לכעשרים וחמש שניות בכוונה —
    /// והמשתמש קיבל בקשת הרשאה שלא ביקש, על המסך הבטוח, בלי שום
    /// הקשר שמסביר אותה.
    ///
    /// היא הוסרה משלוש סיבות, וכל אחת מהן מספיקה:
    ///
    /// היא מיותרת. שירות השומר מחזיר את הסוכן תוך שתי שניות, ומעליו
    /// יש התאוששות מקריסה ומשימה מתוזמנת. שלוש שכבות שרצות כ-SYSTEM
    /// ואינן צריכות איש.
    ///
    /// היא מזיקה. אם המשתמש מאשר באמצע עדכון, ההפעלה מתנגשת במתקין
    /// שמחליף את הקבצים — בדיוק הלולאה שהשומר נזהר ממנה.
    ///
    /// והיא מלמדת הרגל רע. תוכנת הגנה שמקפיצה בקשת הרשאה בלי שהמשתמש
    /// עשה דבר מאמנת אותו לאשר תיבות UAC שצצות מעצמן. זו בדיוק
    /// ההתנהגות שתוקף זקוק לה.
    ///
    /// מה שנשאר: ניסיון שקט אחד. הוא מצליח כשהמשתמש מנהל, נכשל
    /// בשקט כשלא, והמצב האפור מדווח לשרת בשני המקרים.
    /// </summary>
    private void TryStartService()
    {
        _lastRestartAttempt = DateTimeOffset.UtcNow;

        // מתקין פעיל עוצר את השירות בכוונה. הפעלה עכשיו תחזיק את
        // הקבצים נעולים ותפיל את העדכון.
        if (UpdateInProgress()) return;

        try
        {
            using var controller = new ServiceController(ServiceName);

            controller.Start();
            controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
        }
        catch (Exception)
        {
            /*
             * צפוי כשהמשתמש אינו מנהל, ואין לזה המשך.
             *
             * המצב יישאר אפור ויידווח לשרת, וההורה יראה שהמחשב
             * הפסיק לדווח. זו התשובה הנכונה — לא בקשה מהילד לאשר
             * הרשאת מנהל.
             */
        }
    }

    private static bool UpdateInProgress() =>
        Process.GetProcessesByName("FilterPlus-Setup").Length > 0
        || Process.GetProcessesByName("FilterPlus.Installer").Length > 0;

    public void Dispose()
    {
        _cts.Cancel();

        try
        {
            _loop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // סגירה בכל מקרה
        }

        _cts.Dispose();
    }
}
