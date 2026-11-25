using System.Diagnostics;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;

using Microsoft.Extensions.Logging;

namespace FilterPlus.Service.Integrity;

/// <summary>
/// בודק שהרשאות השירותים לא רופפו, ומחזיר אותן.
///
/// ההתקנה מסירה ממנהלים את הזכות לעצור ולמחוק את השירותים, כך
/// ש-sc stop נכשל ב-Access Denied. זו אינה חומה: מנהל יכול להריץ
/// sc sdset ולהחזיר לעצמו את הזכות, ואז לעצור.
///
/// וזו בדיוק הנקודה. בלי מנהל התקן חתום אי אפשר למנוע ממנהל דבר,
/// והמטרה הריאלית היא אחרת: להפוך כל ניסיון לפעולה מכוונת שמשאירה
/// סימן. שינוי ההרשאות הוא הצעד הראשון בכל ניסיון כזה — והמחלקה
/// הזו הופכת אותו לאירוע שההורה רואה.
///
/// היא גם מחזירה את ההקשחה, ולכן מי שמנסה צריך לחזור על הצעד בכל
/// פעם, וכל חזרה נרשמת.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceHardening
{
    /// <summary>
    /// ההרשאות שההתקנה קובעת.
    ///
    /// זהה למחרוזת שב-install.ps1. שני עותקים של אותה מחרוזת הם
    /// סיכון להיפרדות, ולכן הבדיקה כאן היא על החלק שמעניין — מה
    /// שניתן למנהלים — ולא על התאמה מדויקת של המחרוזת כולה.
    /// </summary>
    public const string AdminRights = "CCLCSWRPLOCRRCWD;;;BA";

    private const string Hardened =
        "D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRCWD;;;BA)"
        + "(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

    private readonly ILogger _log;

    public ServiceHardening(ILogger log) => _log = log;

    /// <summary>
    /// האם ההרשאות עדיין מוקשחות.
    ///
    /// מחזיר null כשלא הצלחנו לברר — ואז לא עושים דבר. בדיקה שלא
    /// רצה אינה בדיקה שנכשלה, ואותו כלל שחל על זיהוי הסינון חל גם
    /// כאן.
    /// </summary>
    public bool? IsHardened(string serviceName)
    {
        var output = RunSc($"sdshow {serviceName}");

        if (output is null) return null;

        return output.Replace(" ", "").Contains(AdminRights, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// האם מפתח הרישום של השירות מוגן.
    ///
    /// זו הבדיקה שהייתה חסרה, והיעדרה הוא שהפך תקלה לשקטה: ההתקנה
    /// ניסתה להחיל את ההגנה, נכשלה, הדפיסה אזהרה צהובה שאיש אינו
    /// רואה בעדכון אוטומטי — וההגנה מעולם לא הייתה שם.
    ///
    /// מה שנבדק הוא שני דברים שהיו נכונים אחרי התקנה תקינה: הירושה
    /// מבוטלת, ולמנהלים אין זכות כתיבת ערכים. בלעדיהם אפשר להריץ
    /// reg add על ImagePath ולהחליף את נתיב ההרצה — שירות בשם FilterPlus
    /// שמריץ משהו אחר, והכול נראה תקין.
    ///
    /// מחזיר null כשלא הצלחנו לברר. בדיקה שלא רצה אינה בדיקה שנכשלה.
    /// </summary>
    public bool? RegistryProtected(string serviceName)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}");

            if (key is null) return null;

            var security = key.GetAccessControl();

            if (!security.AreAccessRulesProtected) return false;

            foreach (RegistryAccessRule rule in
                     security.GetAccessRules(true, true, typeof(NTAccount)))
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;

                if (!rule.IdentityReference.Value.EndsWith(
                        "Administrators", StringComparison.OrdinalIgnoreCase))
                    continue;

                if ((rule.RegistryRights & RegistryRights.SetValue) != 0) return false;
            }

            return true;
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException
                                      or IOException)
        {
            _log.LogDebug(ex, "בדיקת הרשאות הרישום של {Service} נכשלה.", serviceName);
            return null;
        }
    }

    /// <summary>מחזיר את ההקשחה. מחזיר true אם הפעולה הצליחה.</summary>
    public bool Restore(string serviceName)
    {
        var output = RunSc($"sdset {serviceName} {Hardened}");

        if (output is null)
        {
            _log.LogError("החזרת ההרשאות של {Service} נכשלה.", serviceName);
            return false;
        }

        _log.LogWarning("הרשאות השירות {Service} הוחזרו למצב מוקשח.", serviceName);

        return true;
    }

    /// <summary>
    /// מריץ sc.exe ומחזיר את הפלט, או null בכשל.
    ///
    /// sc.exe ולא ה-API המנוהל, כי ServiceController אינו חושף את
    /// מתאר האבטחה — וה-P/Invoke הנדרש הוא הרבה קוד לא מנוהל בשביל
    /// פעולה שרצה פעם בכמה דקות.
    /// </summary>
    private string? RunSc(string arguments)
    {
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            using var process = Process.Start(info);

            if (process is null) return null;

            var output = process.StandardOutput.ReadToEnd();

            if (!process.WaitForExit(10_000)) return null;

            return process.ExitCode == 0 ? output : null;
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "הרצת sc.exe נכשלה: {Arguments}", arguments);
            return null;
        }
    }
}
