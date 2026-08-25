using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SafeMe.Core.Models;
using SafeMe.Core.Security;

namespace SafeMe.Service.State;

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

    public UninstallStateStore(ILogger<UninstallStateStore> log, Action<TamperEvent> reportTamper)
    {
        _log = log;
        _reportTamper = reportTamper;
    }

    public UninstallAttemptState Load()
    {
        lock (_sync)
        {
            if (_cached is not null) return _cached;

            var path = SafeMePaths.UninstallStateFile;
            var everInitialized = File.Exists(SafeMePaths.DeviceStateFile);

            if (SecureStore.IsCorrupted(path))
            {
                _log.LogWarning("קובץ מצב ההסרה פגום. המצב מאותחל לנעול.");
                ReportTamper(TamperKind.StateFileTampered, "uninstall.dat אינו ניתן לפענוח.");

                return _cached = CreateLockedState();
            }

            var loaded = SecureStore.Read<UninstallAttemptState>(path);

            if (loaded is null)
            {
                // היעדר קובץ בהתקנה חדשה הוא תקין. היעדרו לאחר שהמכשיר כבר
                // נרשם משמעו שמישהו מחק אותו, וזו חבלה.
                if (everInitialized)
                {
                    _log.LogWarning("קובץ מצב ההסרה נמחק. המצב מאותחל לנעול.");
                    ReportTamper(TamperKind.StateFileMissing, "uninstall.dat נמחק.");

                    return _cached = CreateLockedState();
                }

                return _cached = new UninstallAttemptState { LastSeenUtc = DateTimeOffset.UtcNow };
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
                SecureStore.Write(SafeMePaths.UninstallStateFile, state);
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
