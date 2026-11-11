using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace SafeMe.Service.DnsFilter;

/// <summary>
/// מפנה את שאלות ה-DNS של המחשב אל שרת השמות המקומי של הסוכן.
///
/// הכלי הוא NRPT — טבלת מדיניות פענוח השמות של Windows. כלל אחד על
/// המרחב "." אומר ללקוח ה-DNS של המערכת לשאול את הכתובת שלנו על כל
/// שם, בכל מתאם רשת.
///
/// ולא שינוי שרתי השמות של המתאמים, שהיא הדרך המוכרת יותר. הגדרת
/// מתאם שייכת לרשת: היא מתחלפת בכל חיבור, DHCP דורס אותה, ומי שמסיר
/// את התוכנה באמצע נשאר עם מתאם שמצביע על שרת שכבר אינו קיים. כלל
/// NRPT הוא מפתח רישום אחד, והסרתו מחזירה את המחשב בדיוק למה שהיה.
///
/// הכלל אינו האכיפה. מי שעוקף אותו ושואל שרת שמות חיצוני ישירות
/// נתקל ב-WFP, שסוגר את פורט 53 החוצה. הכלל רק דואג שמה שאמור
/// לעבוד — יעבוד.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class DnsRedirect
{
    private const string LocalRoot =
        @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

    /// <summary>
    /// כללים שהגיעו ממדיניות קבוצתית. כשיש שם ולו כלל אחד, Windows
    /// מתעלם מכל הכללים המקומיים — ולכן הכלל שלנו נכתב גם לשם.
    /// </summary>
    private const string PolicyRoot =
        @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

    private const string RuleKey = "{5AFE3E00-D5F1-4C0B-9A53-5AFE3E0D0053}";
    private const string Marker = "SafeMe";

    private readonly ILogger<DnsRedirect> _log;

    public DnsRedirect(ILogger<DnsRedirect> log) => _log = log;

    /// <summary>האם הכלל קיים ומצביע על הכתובת הנכונה.</summary>
    public bool IsInstalled(string server)
    {
        try
        {
            if (!RuleMatches(LocalRoot, server)) return false;

            return !HasForeignRules(PolicyRoot) || RuleMatches(PolicyRoot, server);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            // בלי הרשאת קריאה אין מה לתקן, ואין טעם לדווח חבלה בכל סבב.
            return true;
        }
    }

    public void Install(string server)
    {
        WriteRule(LocalRoot, server);

        if (HasForeignRules(PolicyRoot))
        {
            _log.LogWarning(
                "במחשב יש כללי NRPT ממדיניות קבוצתית. הכלל של SafeMe נכתב גם לשם.");

            WriteRule(PolicyRoot, server);
        }

        FlushCache();
    }

    /// <summary>
    /// הדרך השנייה: הפקודה הרשמית של Windows.
    ///
    /// כתיבה ישירה לרישום היא מה שתוכנות אחרות עושות ומה שנמדד כאן,
    /// אבל היא נשענת על כך שלקוח ה-DNS שם לב לשינוי בעצמו. אם הבדיקה
    /// העצמית מראה שלא שם לב, זו הדרך שמודיעה לו במפורש.
    /// </summary>
    public bool InstallViaCmdlet(string server)
    {
        var command =
            $"Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{Marker}' }} | " +
            "Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue; " +
            $"Add-DnsClientNrptRule -Namespace '.' -NameServers '{server}' -Comment '{Marker}'";

        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory,
                    @"WindowsPowerShell\v1.0\powershell.exe"),
                Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command}\"",
                UseShellExecute = false,
                CreateNoWindow = true
            });

            if (process is null) return false;

            if (!process.WaitForExit(20_000))
            {
                process.Kill();
                return false;
            }

            FlushCache();

            return process.ExitCode == 0;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "הגדרת כלל NRPT דרך PowerShell נכשלה.");
            return false;
        }
    }

    /// <summary>
    /// מסיר כל כלל שלנו, מכל מקום שבו הוא יכול להיות.
    ///
    /// לפי הסימן ולא רק לפי המפתח: כלל שנוצר בדרך השנייה מקבל מפתח
    /// אקראי, וכלל שנשאר מאחור אחרי הסרה הוא מחשב בלי DNS.
    /// </summary>
    public void Remove()
    {
        var removed = RemoveFrom(LocalRoot) | RemoveFrom(PolicyRoot);

        if (!removed) return;

        FlushCache();
        _log.LogInformation("הפניית ה-DNS אל SafeMe הוסרה.");
    }

    public void FlushCache()
    {
        try
        {
            DnsFlushResolverCache();
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "ריקון מטמון ה-DNS נכשל.");
        }
    }

    private static bool RuleMatches(string root, string server)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"{root}\{RuleKey}");

        if (key is null) return false;

        var names = key.GetValue("Name") as string[];

        return names is ["."]
            && string.Equals(key.GetValue("GenericDNSServers") as string, server, StringComparison.Ordinal)
            && key.GetValue("ConfigOptions") is int options && options == 8;
    }

    /// <summary>האם יש שם כללים שאינם שלנו.</summary>
    private static bool HasForeignRules(string root)
    {
        using var key = Registry.LocalMachine.OpenSubKey(root);

        return key is not null && key.GetSubKeyNames()
            .Any(name => !string.Equals(name, RuleKey, StringComparison.OrdinalIgnoreCase));
    }

    private static void WriteRule(string root, string server)
    {
        using var key = Registry.LocalMachine.CreateSubKey($@"{root}\{RuleKey}");

        // אותה צורה שכללים קיימים נושאים ברישום: גרסה, מרחב, שרתים,
        // ודגל שאומר "שרת שמות כללי".
        key.SetValue("Version", 1, RegistryValueKind.DWord);
        key.SetValue("Name", new[] { "." }, RegistryValueKind.MultiString);
        key.SetValue("GenericDNSServers", server, RegistryValueKind.String);
        key.SetValue("ConfigOptions", 8, RegistryValueKind.DWord);
        key.SetValue("Comment", Marker, RegistryValueKind.String);
    }

    private bool RemoveFrom(string root)
    {
        var removed = false;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(root, writable: true);

            if (key is null) return false;

            foreach (var name in key.GetSubKeyNames())
            {
                bool ours;

                using (var rule = key.OpenSubKey(name))
                {
                    ours = string.Equals(name, RuleKey, StringComparison.OrdinalIgnoreCase)
                        || string.Equals(rule?.GetValue("Comment") as string, Marker, StringComparison.Ordinal);
                }

                if (!ours) continue;

                key.DeleteSubKeyTree(name, throwOnMissingSubKey: false);
                removed = true;
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "הסרת כלל ה-NRPT של SafeMe נכשלה.");
        }

        return removed;
    }

    [LibraryImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
    private static partial uint DnsFlushResolverCache();
}
