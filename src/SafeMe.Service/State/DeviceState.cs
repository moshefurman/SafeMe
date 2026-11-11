using System.IO;
using System.Runtime.Versioning;
using SafeMe.Core.Models;

namespace SafeMe.Service.State;

/// <summary>זהות המחשב וחומר המפתח שהתקבל מהשרת ברישום.</summary>
public sealed class DeviceState
{
    public Guid InstallId { get; set; } = Guid.NewGuid();

    /// <summary>
    /// מתי המחשב הותקן, לפי השעון שלו.
    ///
    /// נקודת הייחוס לתוקף המוגבל כשעדיין לא היה קשר עם השרת. בלעדיה
    /// היעדר מגע היה נראה כמו ניתוק אינסופי, וכל התקנה חדשה הייתה
    /// נולדת פגה — משוחררת מאכיפה לפני הפעימה הראשונה.
    ///
    /// נשמר עם שאר המצב תחת ProgramData, ולכן שורד עדכוני גרסה.
    /// </summary>
    public DateTimeOffset InstalledUtc { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// האם קובץ מצב ההסרה כבר נוצר.
    ///
    /// מבדיל בין "עוד לא היה" לבין "נמחק". בלי ההבחנה הזו כל ניסיון
    /// הסרה ראשון נחשב לחבלה ונעל את עצמו — וזה מה שקרה בפועל על
    /// כל מחשב רשום.
    /// </summary>
    public bool UninstallStateInitialized { get; set; }
    public Guid? DeviceId { get; set; }
    public string? DeviceToken { get; set; }
    public string? LicenseKey { get; set; }
    public DateTimeOffset? LicenseExpiresUtc { get; set; }
    public bool LicenseValid { get; set; }

    public UninstallKeyMode UninstallKeyMode { get; set; } = UninstallKeyMode.Rsa;

    /// <summary>פרופיל ההתקנה שנקבע ברישום ואינו משתנה.</summary>
    public string? InstallProfile { get; set; }

    /// <summary>מצב האכיפה ההתחלתי מההתקנה.</summary>
    public EnforcementMode EnforcementMode { get; set; } = EnforcementMode.Enforce;

    /// <summary>מפתח ציבורי של השרת, לאימות קודי הסרה ולאימות חתימת מדיניות.</summary>
    public string? ServerPublicKeyPem { get; set; }

    /// <summary>מפתח ציבורי נפרד, לאימות קודי הסרה בלבד.</summary>
    public string? UninstallPublicKeyPem { get; set; }

    /// <summary>מפתח ציבורי נפרד, לאימות היתרי הקלה בלבד.</summary>
    public string? LooseningPublicKeyPem { get; set; }

    /// <summary>
    /// המפתח שמאמת הצעות עדכון.
    ///
    /// נפרד משלושת האחרים, כי עדכון הוא הרצת קוד שרירותי בהרשאות
    /// SYSTEM — הסמכות החזקה במוצר. שרת שנפרץ ויכול לחתום מדיניות
    /// אינו יכול לחתום עדכון.
    /// </summary>
    public string? UpdatePublicKeyPem { get; set; }

    /// <summary>סוד המחשב במצב HMAC, מקודד Base64. ריק במצב RSA.</summary>
    public string? DeviceSecretBase64 { get; set; }

    public string? PolicyEtag { get; set; }

    /// <summary>
    /// גרסת הסוכן שמשכה את המדיניות השמורה.
    ///
    /// סוכן שומר לדיסק רק את השדות שהוא מכיר. שדה שנוסף למדיניות
    /// אחרי שהגרסה ההיא נבנתה נמחק בשמירה, וסוכן חדש שעולה אחריו
    /// קורא גוף שכבר אינו מכיל אותו — וה-ETag לא השתנה, ולכן הוא
    /// גם אינו מושך מחדש. כשהגרסה כאן שונה מזו שרצה, המדיניות נמשכת
    /// במלואה פעם אחת.
    /// </summary>
    public string? PolicyFetchedByVersion { get; set; }
    public long HeartbeatSequence { get; set; }
    public DateTimeOffset? LastServerContactUtc { get; set; }

    /// <summary>עוגן זמן שמתקבל מהשרת, לזיהוי הזזת שעון מקומית.</summary>
    public DateTimeOffset? LastServerUtc { get; set; }

    public byte[]? GetDeviceSecret() =>
        string.IsNullOrEmpty(DeviceSecretBase64) ? null : Convert.FromBase64String(DeviceSecretBase64);
}

/// <summary>גישה מרוכזת ומסונכרנת למצב המחשב.</summary>
[SupportedOSPlatform("windows")]
public sealed class DeviceStateStore
{
    private readonly object _sync = new();
    private DeviceState? _cached;

    public DeviceState Load()
    {
        lock (_sync)
        {
            /*
             * מטמון שאינו שורד היעלמות של הקובץ.
             *
             * ‎_cached ??= בלבד שמר את המצב בזיכרון לנצח. כשספריית
             * המצב נמחקה והשירות שרד — הסרה שהשומר החזיר ממנה, למשל —
             * הערך הישן נשאר בזיכרון ונכתב חזרה לדיסק בעדכון הבא.
             *
             * וזה לא נשאר תיאורטי: UninstallStateInitialized נכתב כך
             * מחדש כ-true בזמן ש-uninstall.dat כבר לא היה קיים, ומאותו
             * רגע כל ניסיון הסרה נקרא כמחיקה זדונית. המשתמש ראה "חסימה
             * זמנית לאחר ניסיונות הסרה שגויים" בלי שהיה ולו ניסיון אחד.
             *
             * רק היעלמות מפילה את המטמון, לא כשל קריאה: קובץ נעול או
             * שגיאת קלט רגעית אינם סיבה לאבד את אסימון המחשב ולהירשם
             * מחדש.
             */
            if (_cached is not null && !File.Exists(SafeMePaths.DeviceStateFile))
                _cached = null;

            _cached ??= SecureStore.Read<DeviceState>(SafeMePaths.DeviceStateFile) ?? new DeviceState();

            return _cached;
        }
    }

    public void Save(DeviceState state)
    {
        lock (_sync)
        {
            _cached = state;
            SecureStore.Write(SafeMePaths.DeviceStateFile, state);
        }
    }

    public void Update(Action<DeviceState> mutate)
    {
        lock (_sync)
        {
            var state = Load();
            mutate(state);
            Save(state);
        }
    }
}
