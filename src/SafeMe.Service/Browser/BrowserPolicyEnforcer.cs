using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;
using SafeMe.Core.Models;
using SafeMe.Service.Net;
using SafeMe.Service.State;
using SafeMe.Service.Workers;

namespace SafeMe.Service.Browser;

/// <summary>
/// מתקין ומסיר את תוסף הדפדפן דרך Enterprise Policy ברישום.
///
/// Chrome ו-Edge תומכים בהתקנה כפויה דרך מפתח הרישום
/// ExtensionInstallForcelist. הערך הוא מזהה התוסף וכתובת
/// קובץ העדכון, והדפדפן מתקין אותו בלי שהמשתמש יכול להסיר.
///
/// הסוכן רץ כ-SYSTEM ולכן כותב ל-HKLM. השינוי נכנס לתוקף
/// בעלייה הבאה של הדפדפן, או תוך דקות ספורות בדפדפן שכבר רץ.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BrowserPolicyEnforcer
{
    private const string ChromeForcelistPath =
        @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist";

    private const string EdgeForcelistPath =
        @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist";

    /// <summary>
    /// מזהה התוסף.
    ///
    /// נגזר מהמפתח הציבורי שב-manifest כשהתוסף נארז כ-CRX. ערך
    /// ברירת מחדל לפיתוח; בהפצה הוא נקבע מהמפתח שנוצר בבנייה.
    /// </summary>
    private readonly string _extensionId;
    private readonly string _updateUrl;
    private readonly ILogger<BrowserPolicyEnforcer> _log;
    private readonly EventQueue _events;

    public BrowserPolicyEnforcer(
        ILogger<BrowserPolicyEnforcer> log,
        IOptions<ServerOptions> server,
        EventQueue events)
    {
        _log = log;
        _events = events;

        var baseUrl = server.Value.BaseUrl.TrimEnd('/');
        _updateUrl = $"{baseUrl}/extension/update.xml";
        _extensionId = server.Value.BrowserExtensionId
                       ?? "safeme_youtube_audio_placeholder";
    }

    private string ForcelistEntry => $"{_extensionId};{_updateUrl}";

    /// <summary>
    /// מיישם את המצב הרצוי: מתקין או מסיר את התוסף בשני הדפדפנים.
    /// </summary>
    public void Enforce(bool install)
    {
        EnforceForBrowser(ChromeForcelistPath, "Chrome", install);
        EnforceForBrowser(EdgeForcelistPath, "Edge", install);
    }

    /// <summary>
    /// בודק שהמצב ברישום תואם למצב הרצוי. מחזיר true כשתקין.
    /// </summary>
    public bool Verify(bool shouldBeInstalled)
    {
        return VerifyBrowser(ChromeForcelistPath, shouldBeInstalled)
            && VerifyBrowser(EdgeForcelistPath, shouldBeInstalled);
    }

    /// <summary>
    /// בודק ומתקן. מחזיר true אם נדרש תיקון.
    /// </summary>
    public bool VerifyAndRestore(bool shouldBeInstalled)
    {
        if (Verify(shouldBeInstalled)) return false;

        _log.LogWarning("מדיניות תוסף הדפדפן שונתה מחוץ לסוכן. מוחזרת.");

        _events.Enqueue(new TamperEvent
        {
            Kind = TamperKind.BrowserPolicyTampered,
            Detail = "מפתחות הרישום של תוסף הדפדפן שונו. הוחזרו."
        });

        Enforce(shouldBeInstalled);
        return true;
    }

    private void EnforceForBrowser(string policyPath, string browserName, bool install)
    {
        try
        {
            if (install)
                EnsureEntry(policyPath, browserName);
            else
                RemoveEntry(policyPath, browserName);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            _log.LogError(ex, "אין הרשאה לכתוב מדיניות {Browser}.", browserName);
        }
    }

    private void EnsureEntry(string policyPath, string browserName)
    {
        using var key = Registry.LocalMachine.CreateSubKey(policyPath);

        foreach (var name in key.GetValueNames())
        {
            if (key.GetValue(name) is string val &&
                val.StartsWith(_extensionId, StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(val, ForcelistEntry, StringComparison.Ordinal))
                    return;

                key.SetValue(name, ForcelistEntry, RegistryValueKind.String);

                _log.LogInformation(
                    "כתובת העדכון של תוסף {Browser} עודכנה.", browserName);
                return;
            }
        }

        var next = NextIndex(key);
        key.SetValue(next.ToString(), ForcelistEntry, RegistryValueKind.String);

        _log.LogInformation("תוסף שמע הותקן ב-{Browser} (אינדקס {Index}).",
            browserName, next);
    }

    private void RemoveEntry(string policyPath, string browserName)
    {
        using var key = Registry.LocalMachine.OpenSubKey(policyPath, writable: true);
        if (key is null) return;

        foreach (var name in key.GetValueNames())
        {
            if (key.GetValue(name) is string val &&
                val.StartsWith(_extensionId, StringComparison.OrdinalIgnoreCase))
            {
                key.DeleteValue(name);

                _log.LogInformation("תוסף שמע הוסר מ-{Browser}.", browserName);
            }
        }
    }

    private bool VerifyBrowser(string policyPath, bool shouldExist)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(policyPath);

            if (key is null)
                return !shouldExist;

            var found = key.GetValueNames().Any(name =>
                key.GetValue(name) is string val &&
                val.StartsWith(_extensionId, StringComparison.OrdinalIgnoreCase));

            return found == shouldExist;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return true;
        }
    }

    private static int NextIndex(RegistryKey key)
    {
        var max = 0;

        foreach (var name in key.GetValueNames())
        {
            if (int.TryParse(name, out var idx) && idx > max)
                max = idx;
        }

        return max + 1;
    }
}
