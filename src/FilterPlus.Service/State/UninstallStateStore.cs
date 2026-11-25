using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using FilterPlus.Core.Models;
using FilterPlus.Core.Security;

namespace FilterPlus.Service.State;

/// <summary>
/// אחסון מוגן של מצב ההסרה (ניסיונות, נעילות ואתגר פתוח).
///
/// מדיניות Fail-Secure: אם הקובץ נמחק או נפגם, המצב מאותחל למצב נעול
/// ולא למצב פתוח. אחרת מחיקת קובץ הייתה דרך זולה לאפס את מונה הניסיונות.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class UninstallStateStore : IUninstallStateStore
{
    private readonly ILogger<UninstallStateStore> _log;
    private readonly Action<TamperEvent> _reportTamper;
    private readonly object _sync = new();

    private UninstallAttemptState? _cached;

    /// <summary>משך הנעילה שנכפה כשמזוהה חבלה בקובץ המצב.</summary>
    private static readonly TimeSpan TamperLockout = TimeSpan.FromMinutes(15);

    private readonly DeviceStateStore _device;

    public UninstallStateStore(
        ILogger<UninstallStateStore> log,
        DeviceStateStore device,
        Action<TamperEvent> reportTamper)
    {
        _log = log;
        _device = device;
        _reportTamper = reportTamper;
    }

    public UninstallAttemptState Load()
    {
        lock (_sync)
        {
            if (_cached is not null) return _cached;

            var path = FilterPlusPaths.UninstallStateFile;

            /*
             * האם קובץ מצב ההסרה נוצר אי פעם.
             *
             * זה היה File.Exists(device.dat), וזו הייתה טעות: device.dat
             * נוצר ברישום, ו-uninstall.dat נוצר רק בשימוש הראשון. כלומר
             * בניסיון ההסרה הראשון על כל מחשב רשום הקובץ חסר בעוד
             * device.dat קיים — והמסקנה הייתה חבלה.
             *
             * התוצאה: ההסרה נעלה את עצמה בניסיון הראשון, על כל מחשב,
             * תמיד. המשתמש ראה "ניסיונות הסרה שגויים" בלי שהיה ולו
             * ניסיון אחד. נצפה בשטח.
             *
             * הדגל נשמר במצב המחשב, שמוצפן ב-DPAPI כמו הקובץ עצמו.
             * מכאן והלאה היעדר הקובץ אחרי שהדגל הודלק הוא באמת מחיקה,
             * וה-fail-secure נשמר — הוא פשוט מפסיק לירות על מצב תקין.
             */
            var everInitialized = _device.Load().UninstallStateInitialized;

            if (SecureStore.IsCorrupted(path))
            {
                _log.LogWarning("קובץ מצב ההסרה פגום. המצב מאותחל לנעול.");
                ReportTamper(TamperKind.StateFileTampered, "uninstall.dat אינו ניתן לפענוח.");

                return _cached = CreateLockedState();
            }

            var loaded = SecureStore.Read<UninstallAttemptState>(path);

            if (loaded is null)
            {
                // היעדר קובץ בהתקנה חדשה הוא תקין. היעדרו לאחר שהמחשב כבר
                // נרשם משמעו שמישהו מחק אותו, וזו חבלה.
                if (everInitialized)
                {
                    _log.LogWarning("קובץ מצב ההסרה נמחק. המצב מאותחל לנעול.");
                    ReportTamper(TamperKind.StateFileMissing, "uninstall.dat נמחק.");

                    return _cached = CreateLockedState();
                }

                /*
                 * הפעם הראשונה. נוצר מצב נקי, נשמר, והדגל נדלק —
                 * כדי שמחיקה עתידית תזוהה כמחיקה ולא כפעם ראשונה.
                 */
                var fresh = new UninstallAttemptState { LastSeenUtc = DateTimeOffset.UtcNow };

                _cached = fresh;

                Save(fresh);
                _device.Update(d => d.UninstallStateInitialized = true);

                return fresh;
            }

            // זיהוי הזזת שעון אחורה מול העוגן המונוטוני
            if (DateTimeOffset.UtcNow < loaded.LastSeenUtc - TimeSpan.FromMinutes(5))
            {
                _log.LogWarning("שעון המערכת הוזז אחורה. הנעילה נמדדת לפי הזמן האחרון שנרשם.");
                ReportTamper(TamperKind.ClockRolledBack,
                    $"שעון מקומי {DateTimeOffset.UtcNow:o} מול עוגן {loaded.LastSeenUtc:o}.");
            }

            return _cached = loaded;
        }
    }

    public void Save(UninstallAttemptState state)
    {
        lock (_sync)
        {
            _cached = state;

            try
            {
                SecureStore.Write(FilterPlusPaths.UninstallStateFile, state);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "שמירת מצב ההסרה נכשלה.");
            }
        }
    }

    public void ReportTamper(TamperKind kind, string detail)
    {
        _log.LogWarning("אירוע חבלה {Kind}: {Detail}", kind, detail);
        _reportTamper(new TamperEvent { Kind = kind, Detail = detail });
    }

    private static UninstallAttemptState CreateLockedState() => new()
    {
        FailedAttempts = 0,
        LockoutCount = 1,
        LockoutUntilUtc = DateTimeOffset.UtcNow + TamperLockout,
        LastSeenUtc = DateTimeOffset.UtcNow
    };
}
