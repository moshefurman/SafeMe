using System.Diagnostics;
using System.Runtime.Versioning;

using Microsoft.Win32;

using FilterPlus.Core.Models;

namespace FilterPlus.TrayApp.Services;

/// <summary>
/// מוודא שהאייקון נראה בשורת המשימות, ולא מאחורי החץ.
///
/// Windows מסתירה אייקון של אפליקציה שהיא רואה בפעם הראשונה. לרוב
/// התוכנות זו התנהגות נכונה, וכאן היא מזיקה: האייקון הוא הדבר היחיד
/// שההורה רואה שאומר שההגנה פועלת, ואם הוא אינו שם המסקנה הסבירה
/// היא שהתוכנה הוסרה.
///
/// זה נצפה מיד אחרי התקנה, כשהכול פעל כשורה.
///
/// ההעלאה נעשית פעם אחת, ורק כשלמשתמש אין החלטה קודמת. הורה שהסתיר
/// את האייקון בחר, וכפייה בכל הפעלה הייתה הופכת את ההגדרה שלו להצעה.
/// </summary>
[SupportedOSPlatform("windows")]
public static class IconVisibility
{
    private const string SettingsKey = @"Control Panel\NotifyIconSettings";

    /// <summary>
    /// הסימן שאנחנו כבר ניסינו.
    ///
    /// תחת המפתח שלנו ולא של Windows: אנחנו זוכרים מה עשינו, ולא
    /// מסתמכים על היעדר ערך כדי להסיק זאת. בלי הזיכרון הזה, הורה
    /// שהסתיר את האייקון היה מקבל אותו בחזרה בכל הפעלה מחדש.
    /// </summary>
    private const string OwnKey = @"Software\FilterPlus\Tray";
    private const string TriedValue = "PromotionAttempted";

    /// <summary>
    /// מנסה פעם אחת. אינו זורק — אייקון מוסתר אינו סיבה להפיל
    /// את אפליקציית המגש, שתפקידה החשוב יותר הוא להציג מצב.
    /// </summary>
    public static void EnsureVisible()
    {
        try
        {
            var exe = Process.GetCurrentProcess().MainModule?.FileName;

            if (string.IsNullOrWhiteSpace(exe)) return;

            var alreadyTried = ReadTried();
            var entry = FindEntry(exe);

            // אין רשומה עדיין. Windows יוצרת אותה רק אחרי שהאייקון
            // הוצג בפועל, ולכן ננסה שוב בהפעלה הבאה.
            if (entry is null) return;

            var action = TrayPromotion.Decide(entry.Value.IsPromoted, alreadyTried);

            if (action != PromotionAction.Promote) return;

            using var key = Registry.CurrentUser.OpenSubKey(
                $@"{SettingsKey}\{entry.Value.Name}", writable: true);

            key?.SetValue("IsPromoted", 1, RegistryValueKind.DWord);

            MarkTried();
        }
        catch (Exception)
        {
            /*
             * הרשומה עשויה להשתנות בין גרסאות Windows, ומפתח שאינו
             * קיים או חסום אינו תקלה שדורשת טיפול. האייקון יישאר
             * מאחורי החץ, וההגנה עצמה אינה מושפעת.
             */
        }
    }

    private static (string Name, bool? IsPromoted)? FindEntry(string exePath)
    {
        using var root = Registry.CurrentUser.OpenSubKey(SettingsKey);

        if (root is null) return null;

        // System.IO במפורש: ב-WPF יש גם System.Windows.Shapes.Path
        var leaf = System.IO.Path.GetFileName(exePath);

        foreach (var name in root.GetSubKeyNames())
        {
            using var sub = root.OpenSubKey(name);

            if (sub?.GetValue("ExecutablePath") is not string stored) continue;

            /*
             * השוואה לפי שם הקובץ בלבד.
             *
             * Windows כותבת את הנתיב עם מזהה תיקייה במקום האות —
             * "{6D809377-...}\FilterPlus\FilterPlus.TrayApp.exe" — ולכן
             * השוואה לנתיב המלא לא הייתה מוצאת דבר. נמדד על מכונה
             * אמיתית, ולא הונח.
             */
            if (!stored.EndsWith(leaf, StringComparison.OrdinalIgnoreCase)) continue;

            var raw = sub.GetValue("IsPromoted");

            return (name, raw is null ? null : Convert.ToInt32(raw) != 0);
        }

        return null;
    }

    private static bool ReadTried()
    {
        using var key = Registry.CurrentUser.OpenSubKey(OwnKey);

        return key?.GetValue(TriedValue) is int v && v != 0;
    }

    private static void MarkTried()
    {
        using var key = Registry.CurrentUser.CreateSubKey(OwnKey);

        key?.SetValue(TriedValue, 1, RegistryValueKind.DWord);
    }
}
